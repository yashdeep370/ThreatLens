"""Website Security Check: URL model verdict + safe, passive live checks.

Live checks make the same single request a browser would (no scanning):
HTTPS use, TLS certificate validity/expiry, security headers, redirect chain.
SSRF guard: refuses to fetch private, loopback or link-local addresses so the
server can't be used to probe internal networks.
"""
import ipaddress
import socket
import ssl
import uuid
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import joblib
import requests
import urllib3

from src.config import ROOT, URL_MODEL_PATH
from src.url_features import _split, explain, normalize

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8
MAX_REDIRECTS = 5
USER_AGENT = "Mozilla/5.0 (SecurityCheck; educational project)"
URL_THREAT = {"phishing": "Phishing", "malware": "Malware", "defacement": "Defacement"}
TRUSTED_DOMAINS_PATH = ROOT / "knowledge" / "trusted_domains.txt"
# Above this ML confidence, a malicious verdict is kept even on a reputable domain.
TRUSTED_OVERRIDE_LIMIT = 0.9

SECURITY_HEADERS = [
    # header, label, why it matters, score penalty if missing
    ("strict-transport-security", "HSTS", "Forces browsers to always use HTTPS", 8),
    ("content-security-policy", "Content-Security-Policy", "Limits which scripts can run (reduces XSS)", 8),
    ("x-frame-options", "X-Frame-Options", "Prevents clickjacking via hidden frames", 5),
    ("x-content-type-options", "X-Content-Type-Options", "Stops MIME-type sniffing attacks", 4),
    ("referrer-policy", "Referrer-Policy", "Limits URL data leaked to other sites", 3),
    ("permissions-policy", "Permissions-Policy", "Restricts camera, mic, location access", 2),
]


class UnsafeTarget(Exception):
    pass


def _check_host(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise UnsafeTarget(f"Domain '{host}' does not resolve (DNS lookup failed)")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise UnsafeTarget("Target resolves to a private/internal address; live check skipped for safety")


def _fetch(url: str) -> tuple[requests.Response, list[str], bool]:
    """Follow redirects manually so every hop passes the SSRF guard."""
    chain, cert_ok = [url], True
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise UnsafeTarget("Only http and https URLs can be checked")
        _check_host(parsed.hostname)
        try:
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=False, stream=True,
                             headers={"User-Agent": USER_AGENT})
        except requests.exceptions.SSLError:
            cert_ok = False
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=False, stream=True, verify=False,
                             headers={"User-Agent": USER_AGENT})
        r.close()
        if r.is_redirect and "location" in r.headers:
            url = urljoin(url, r.headers["location"])
            chain.append(url)
            continue
        return r, chain, cert_ok
    raise UnsafeTarget(f"More than {MAX_REDIRECTS} redirects")


def _certificate(host: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                version = tls.version()
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        return {
            "valid": True,
            "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
            "expires": expires.date().isoformat(),
            "days_left": (expires - datetime.now(timezone.utc)).days,
            "tls_version": version,
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": e.verify_message or str(e)}
    except Exception as e:
        return {"valid": False, "error": f"Could not establish TLS connection: {e.__class__.__name__}"}


def _load_trusted() -> list[str]:
    path = TRUSTED_DOMAINS_PATH
    if not path.exists():
        return []
    return [line.strip().lower() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


class UrlChecker:
    def __init__(self, knowledge):
        bundle = joblib.load(URL_MODEL_PATH)
        self.model, self.classes = bundle["model"], bundle["classes"]
        self.model_name = bundle.get("model_name", "URL model")
        self.trusted = _load_trusted()
        self.kb = knowledge

    def reputation(self, url: str) -> str | None:
        """Matched trusted entry, or None. Exact domain or subdomain only, so
        look-alikes like google.com-verify.info don't match."""
        host = _split(normalize(url))[0].lower().rstrip(".")
        for entry in self.trusted:
            if entry.startswith("."):
                if host.endswith(entry):
                    return entry
            elif host == entry or host.endswith("." + entry):
                return entry
        return None

    def classify(self, url: str) -> dict:
        proba = self.model.predict_proba([url])[0]
        ml_label = self.classes[proba.argmax()]
        confidence = float(proba.max())
        trusted = self.reputation(url)
        label, note = ml_label, None
        if trusted and ml_label != "benign":
            if confidence >= TRUSTED_OVERRIDE_LIMIT:
                note = (f"Domain is on the reputable list ({trusted}), but the ML model is highly confident this "
                        f"specific URL looks {ml_label}. It could be a compromised page or an open redirect.")
            else:
                label = "benign"
                note = (f"Known reputable domain ({trusted}). The ML model leaned {ml_label} "
                        f"({confidence:.0%}), so the reputation layer overrides it.")
        elif trusted:
            note = f"Known reputable domain ({trusted})."
        return {
            "label": label,
            "ml_label": ml_label,
            "confidence": round(confidence if label == ml_label else float(proba[self.classes.index("benign")]), 4),
            "probabilities": {c: round(float(p), 4) for c, p in zip(self.classes, proba)},
            "reputation": {"trusted": bool(trusted), "matched": trusted, "note": note},
            "model_name": self.model_name,
            "red_flags": explain(url),
        }

    def live_check(self, url: str) -> dict:
        target = url if "://" in url else "https://" + url
        try:
            try:
                resp, chain, cert_ok = _fetch(target)
            except requests.exceptions.ConnectionError:
                if "://" in url:
                    raise
                target = "http://" + url  # site may not support HTTPS at all
                resp, chain, cert_ok = _fetch(target)
        except UnsafeTarget as e:
            return {"performed": False, "reason": str(e)}
        except requests.exceptions.RequestException as e:
            return {"performed": False, "reason": f"Site unreachable ({e.__class__.__name__})"}

        final = urlparse(resp.url)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        https = final.scheme == "https"
        header_results = []
        for key, label, why, penalty in SECURITY_HEADERS:
            present = key in headers
            if key == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
                present = True
            if key == "strict-transport-security" and not https:
                present = False
            header_results.append({"header": label, "present": present, "why": why, "penalty": penalty,
                                   "value": headers.get(key, "")[:120]})

        domains = {urlparse(u).hostname for u in chain}
        server = headers.get("server", "")
        # Validity comes from the OS trust store (ssl default context), not requests'
        # bundled CA list: antivirus HTTPS scanning (e.g. Avast) re-signs certificates
        # with a root only the OS trusts, which requests would wrongly call invalid.
        cert = _certificate(final.hostname) if https else None
        return {
            "performed": True,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "https": https,
            "certificate": cert,
            "certificate_verified": bool(cert and cert["valid"]),
            "requests_ca_verified": cert_ok,
            "headers": header_results,
            "redirects": chain[1:],
            "cross_domain_redirect": len(domains) > 1,
            "server_disclosure": server if any(ch.isdigit() for ch in server) else "",
        }

    @staticmethod
    def _score(model: dict, live: dict) -> tuple[int, list[dict]]:
        deductions = []
        if model["label"] != "benign":
            deductions.append({"reason": f"URL pattern classified as {model['label']}",
                               "points": round(50 * model["confidence"])})
        if live.get("performed"):
            if not live["https"]:
                deductions.append({"reason": "Site does not use HTTPS", "points": 25})
            cert = live.get("certificate") or {}
            if live["https"] and (not cert.get("valid") or not live["certificate_verified"]):
                deductions.append({"reason": "Invalid or untrusted TLS certificate", "points": 30})
            elif cert.get("days_left", 999) < 14:
                deductions.append({"reason": f"Certificate expires in {cert['days_left']} days", "points": 10})
            for h in live["headers"]:
                if not h["present"]:
                    deductions.append({"reason": f"Missing {h['header']} header", "points": h["penalty"]})
            if live["cross_domain_redirect"]:
                deductions.append({"reason": "Redirects to a different domain", "points": 5})
            if live["server_disclosure"]:
                deductions.append({"reason": f"Server version disclosed ({live['server_disclosure']})", "points": 3})
        return max(0, 100 - sum(d["points"] for d in deductions)), deductions

    def check(self, url: str, live: bool = True) -> dict:
        url = url.strip()
        model = self.classify(url)
        live_result = self.live_check(url) if live else {"performed": False, "reason": "Live check disabled"}
        score, deductions = self._score(model, live_result)
        threat = URL_THREAT.get(model["label"])
        pb = self.kb.playbook(threat) if threat else None

        if threat and model["reputation"]["trusted"]:
            status = {"level": "warning", "headline": f"Reputable domain, but this URL looks like {threat.lower()}"}
        elif threat and model["confidence"] >= 0.7:
            status = {"level": "danger", "headline": f"Likely {threat.lower()} URL"}
        elif threat:
            status = {"level": "warning", "headline": f"Possibly {threat.lower()} - treat with caution"}
        elif score < 70:
            status = {"level": "warning", "headline": "URL looks benign, but the site has security weaknesses"}
        else:
            status = {"level": "safe", "headline": "No significant risk indicators found"}

        return {
            "id": uuid.uuid4().hex[:10],
            "type": "url",
            "url": url,
            "analyzed_at": datetime.now().isoformat(timespec="seconds"),
            "status": status,
            "model": model,
            "live": live_result,
            "score": {"value": score, "deductions": deductions},
            "threat": threat,
            "playbook": pb,
        }
