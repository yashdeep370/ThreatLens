"""Lexical URL features. Used both in training and by the backend at predict time,
so the two can never drift apart. No network lookups: everything comes from the
URL string itself."""
import math
import re
from collections import Counter
from urllib.parse import urlparse

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler

SUSPICIOUS_WORDS = (
    "login", "signin", "verify", "account", "update", "secure", "bank", "confirm",
    "password", "paypal", "webscr", "ebayisapi", "free", "lucky", "bonus", "wallet",
)
SHORTENERS = ("bit.ly", "goo.gl", "tinyurl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly")
RISKY_EXTENSIONS = (".exe", ".zip", ".rar", ".apk", ".scr", ".bat", ".js", ".php")

IP_RE = re.compile(r"(\d{1,3}\.){3}\d{1,3}")
HEX_RE = re.compile(r"%[0-9a-fA-F]{2}")

SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "count_dot", "count_hyphen", "count_at", "count_question", "count_ampersand",
    "count_equals", "count_underscore", "count_percent", "count_slash", "count_tilde",
    "count_digits", "count_letters", "digit_ratio", "subdomain_count",
    "has_ip", "has_http_in_path", "has_double_slash_in_path",
    "is_shortener", "suspicious_word_count", "risky_extension", "hex_escape_count",
    "entropy", "host_digit_count", "tld_length",
]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def normalize(url: str) -> str:
    """Strip scheme, 'www.' and trailing '/'. The training data is biased: 97% of
    benign URLs are written without a scheme while most malicious ones have one,
    so without this the model learns 'has https:// = malicious'."""
    url = SCHEME_RE.sub("", str(url).strip())
    if url.lower().startswith("www."):
        url = url[4:]
    return url.rstrip("/")


def _split(url: str) -> tuple[str, str, str]:
    """Return (host, path, query). Falls back to plain string splitting for
    malformed URLs (e.g. a stray '[') that urlparse rejects."""
    # urlparse needs a scheme to find the host.
    full = "http://" + url
    try:
        parsed = urlparse(full)
        return parsed.hostname or "", parsed.path or "", parsed.query or ""
    except ValueError:
        rest = full.split("://", 1)[1]
        rest, _, query = rest.partition("?")
        host, slash, path = rest.partition("/")
        return host.split(":")[0].lower(), slash + path, query


def extract(url: str) -> list[float]:
    url = normalize(url)
    lower = url.lower()
    host, path, query = _split(url)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    digits = sum(ch.isdigit() for ch in url)

    return [
        len(url), len(host), len(path), len(query),
        url.count("."), url.count("-"), url.count("@"), url.count("?"), url.count("&"),
        url.count("="), url.count("_"), url.count("%"), url.count("/"), url.count("~"),
        digits, sum(ch.isalpha() for ch in url), digits / max(len(url), 1),
        max(host.count(".") - 1, 0),
        int(bool(IP_RE.search(host))),
        int("http" in path.lower()), int("//" in path),
        int(any(s in host for s in SHORTENERS)),
        sum(w in lower for w in SUSPICIOUS_WORDS),
        int(path.lower().endswith(RISKY_EXTENSIONS)),
        len(HEX_RE.findall(url)),
        _entropy(url), sum(ch.isdigit() for ch in host), len(tld),
    ]


def extract_many(urls) -> np.ndarray:
    return np.array([extract(u) for u in urls], dtype=np.float32)


class HybridUrlVectorizer(BaseEstimator, TransformerMixin):
    """Character n-grams of the normalized URL + scaled lexical features.
    Takes raw URL strings, so the saved pipeline can be called on user input directly."""

    def __init__(self, max_features=300_000):
        self.max_features = max_features

    def fit(self, urls, y=None):
        self.tfidf_ = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=self.max_features,
                                      sublinear_tf=True, dtype=np.float32)
        self.tfidf_.fit([normalize(u) for u in urls])
        self.scaler_ = MaxAbsScaler().fit(extract_many(urls))
        return self

    def transform(self, urls):
        chars = self.tfidf_.transform([normalize(u) for u in urls])
        lexical = csr_matrix(self.scaler_.transform(extract_many(urls)))
        return hstack([chars, lexical]).tocsr()


def explain(url: str) -> list[str]:
    """Human-readable red flags for a URL, used as evidence in reports."""
    f = dict(zip(FEATURE_NAMES, extract(url)))
    flags = []
    if f["has_ip"]:
        flags.append("Uses a raw IP address instead of a domain name")
    if f["count_at"]:
        flags.append("Contains '@', which can hide the real destination")
    if f["is_shortener"]:
        flags.append("Uses a URL shortener that hides the final destination")
    if f["suspicious_word_count"]:
        flags.append(f"Contains {int(f['suspicious_word_count'])} phishing-style keyword(s) (e.g. login, verify, account)")
    if f["url_length"] > 75:
        flags.append(f"Unusually long URL ({int(f['url_length'])} characters)")
    if f["subdomain_count"] >= 3:
        flags.append(f"Many subdomains ({int(f['subdomain_count'])}), common in look-alike domains")
    if f["risky_extension"]:
        flags.append("Points directly to an executable or script file")
    if f["hex_escape_count"] >= 3:
        flags.append("Heavy percent-encoding, often used to obfuscate URLs")
    if f["has_http_in_path"] or f["has_double_slash_in_path"]:
        flags.append("Contains an embedded URL or redirect in its path")
    if str(url).strip().lower().startswith("http://"):
        flags.append("Does not use HTTPS")
    return flags
