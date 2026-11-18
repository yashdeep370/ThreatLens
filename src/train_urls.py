"""Train and compare malicious-URL classifiers (benign / phishing / defacement / malware).

Expects data/raw/urls/*.csv with columns `url` and `type` (Kaggle
"Malicious URLs dataset", malicious_phish.csv).

Compared approaches (both are pipelines that take raw URL strings):
  A. Lexical   - 28 hand-crafted URL features -> XGBoost
  B. Hybrid    - character 3-5-grams + lexical features -> linear model (SGD, log loss)

URLs are normalized (scheme and 'www.' removed) because the dataset is biased:
97% of benign URLs have no scheme while most malicious ones do.

Usage:  python -m src.train_urls
"""
import json
import sys
import time

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, LabelEncoder
from xgboost import XGBClassifier

from src.config import MODELS_DIR, RANDOM_STATE, REPORTS_DIR, URL_MODEL_PATH, URLS_DIR
from src.url_features import HybridUrlVectorizer, extract_many, normalize

# Sanity check on real-world URLs: test-set scores alone hid the scheme bias.
SANITY_URLS = [
    ("https://www.google.com", "benign"), ("https://github.com/anthropics", "benign"),
    ("https://www.kiit.ac.in/", "benign"), ("https://en.wikipedia.org/wiki/Denial-of-service_attack", "benign"),
    ("https://www.amazon.in/gp/cart/view.html", "benign"), ("https://mail.google.com/mail/u/0/#inbox", "benign"),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ", "benign"),
    ("https://stackoverflow.com/questions/12345/how-to-parse", "benign"),
    ("http://paypal-login-verify.account-secure.xyz/signin", "malicious"),
    ("http://103.21.44.5/bank/login.php", "malicious"),
    ("http://secure-update-appleid.com-verify.info/login", "malicious"),
    ("http://free-bonus-wallet.top/claim.php?id=88231", "malicious"),
]


def augment_benign_domains(urls, y, benign_idx):
    """Add the bare domain of every benign training URL as an extra benign example.
    In the raw data a third of bare domains are labelled phishing (mostly ordinary
    small sites), so without this the model treats 'google.com' as suspicious.
    Applied to the training split only, so test metrics stay comparable."""
    seen = {normalize(u) for u in urls}
    hosts = {normalize(u).split("/")[0].split("?")[0] for u, label in zip(urls, y) if label == benign_idx}
    extra = sorted(h for h in hosts if h and h not in seen)
    print(f"Augmentation: +{len(extra):,} benign bare-domain examples (training split only)")
    return np.concatenate([urls, extra]), np.concatenate([y, np.full(len(extra), benign_idx)])


def sanity(model, classes) -> tuple[int, list[str]]:
    proba = model.predict_proba([u for u, _ in SANITY_URLS])
    lines, correct = [], 0
    for (url, expected), p in zip(SANITY_URLS, proba):
        label = classes[p.argmax()]
        ok = (label == "benign") == (expected == "benign")
        correct += ok
        lines.append(f"  {'OK ' if ok else 'BAD'} {url:<58} {label:<11} {p.max():.2f}")
    return correct, lines


def main():
    files = sorted(URLS_DIR.rglob("*.csv"))
    if not files:
        sys.exit(f"No CSV found in {URLS_DIR}")
    df = pd.read_csv(files[0])
    df.columns = df.columns.str.strip().str.lower()
    if not {"url", "type"} <= set(df.columns):
        sys.exit(f"Expected columns 'url' and 'type', got {list(df.columns)}")

    df = df.dropna(subset=["url", "type"]).drop_duplicates(subset="url")
    df["type"] = df["type"].str.strip().str.lower()
    print(f"{len(df):,} unique URLs\n{df['type'].value_counts().to_string()}")

    encoder = LabelEncoder()
    y = encoder.fit_transform(df["type"])
    classes = list(encoder.classes_)
    urls = df["url"].astype(str).to_numpy()
    u_train, u_test, y_train, y_test = train_test_split(
        urls, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    u_train, y_train = augment_benign_domains(u_train, y_train, classes.index("benign"))

    candidates = {
        "Lexical-XGBoost": make_pipeline(
            FunctionTransformer(extract_many),
            XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, tree_method="hist",
                          n_jobs=-1, random_state=RANDOM_STATE, eval_metric="mlogloss"),
        ),
        "Hybrid-CharNgram-SGD": make_pipeline(
            HybridUrlVectorizer(),
            SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=30, tol=1e-4, class_weight="balanced",
                          n_jobs=-1, random_state=RANDOM_STATE),
        ),
    }

    results, fitted = {}, {}
    for name, model in candidates.items():
        t = time.perf_counter()
        model.fit(u_train, y_train)
        pred = model.predict(u_test)
        report = classification_report(y_test, pred, target_names=classes, digits=4)
        correct, lines = sanity(model, classes)
        print(f"\n=== {name} ({time.perf_counter() - t:.0f}s) ===\n{report}"
              f"Real-world sanity check: {correct}/{len(SANITY_URLS)}\n" + "\n".join(lines))
        results[name] = {
            "macro_f1": f1_score(y_test, pred, average="macro"),
            "accuracy": float((pred == y_test).mean()),
            "sanity_correct": correct,
            "per_class": classification_report(y_test, pred, target_names=classes, output_dict=True),
            "report": report,
            "pred": pred,
        }
        fitted[name] = model

    # Select on held-out macro F1. The sanity check is reported, not optimized: popular
    # domains the dataset misjudges are handled by the reputation layer in the backend.
    best = max(results, key=lambda n: results[n]["macro_f1"])
    print(f"\nSelected: {best}")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / "classification_report_URL.txt").write_text(
        "\n\n".join(f"=== {n} ===\n{r['report']}" for n, r in results.items()) + f"\nSelected: {best}\n")

    cm = confusion_matrix(y_test, results[best]["pred"], normalize="true")
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt=".3f", cmap="Oranges", xticklabels=classes, yticklabels=classes)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(f"URL model ({best}) - normalized confusion matrix")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "confusion_matrix_URL.png", dpi=150)
    plt.close()

    joblib.dump({"model": fitted[best], "model_name": best, "classes": classes}, URL_MODEL_PATH)
    (REPORTS_DIR / "url_metrics.json").write_text(json.dumps({
        "n_urls": len(df), "train": len(u_train), "test": len(u_test), "selected_model": best,
        "models": {n: {k: v for k, v in r.items() if k not in ("report", "pred")} for n, r in results.items()},
    }, indent=2))
    print(f"Saved {URL_MODEL_PATH}")


if __name__ == "__main__":
    main()
