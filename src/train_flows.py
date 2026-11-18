"""Train and compare network-flow classifiers, plus a benign-only anomaly detector.

Outputs:
  models/flow_classifier.joblib   best supervised model (+ feature list, classes)
  models/flow_anomaly.joblib      Isolation Forest + alert threshold
  models/benign_baseline.json     per-feature benign statistics (for evidence text)
  reports/                        metrics.json, classification reports, confusion
                                  matrices, feature importance chart

Usage:  python -m src.train_flows
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
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix, f1_score, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from src.config import (
    ANOMALY_MODEL_PATH, BASELINE_PATH, FLOW_MODEL_PATH, FLOWS_PARQUET, MODELS_DIR,
    RANDOM_STATE, REPORTS_DIR,
)

# Share of benign training flows the anomaly detector is allowed to flag.
ANOMALY_BENIGN_FLAG_RATE = 0.01


def save_confusion_matrix(y_true, y_pred, classes, name):
    cm = confusion_matrix(y_true, y_pred, normalize="true")
    plt.figure(figsize=(7, 6))
    sns.heatmap(cm, annot=True, fmt=".3f", cmap="Blues", xticklabels=classes, yticklabels=classes)
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title(f"{name} - normalized confusion matrix")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / f"confusion_matrix_{name}.png", dpi=150)
    plt.close()


def evaluate(name, model, X_test, y_test, classes):
    t = time.perf_counter()
    proba = model.predict_proba(X_test)
    pred = proba.argmax(axis=1)
    infer_ms = (time.perf_counter() - t) / len(X_test) * 1000

    report = classification_report(y_test, pred, target_names=classes, digits=4)
    (REPORTS_DIR / f"classification_report_{name}.txt").write_text(report)
    save_confusion_matrix(y_test, pred, classes, name)
    print(f"\n=== {name} ===\n{report}")

    per_class = classification_report(y_test, pred, target_names=classes, output_dict=True)
    return {
        "accuracy": accuracy_score(y_test, pred),
        "macro_f1": f1_score(y_test, pred, average="macro"),
        "weighted_f1": f1_score(y_test, pred, average="weighted"),
        "roc_auc_ovr": roc_auc_score(y_test, proba, multi_class="ovr"),
        "inference_ms_per_flow": infer_ms,
        "per_class": {c: per_class[c] for c in classes},
    }


def save_feature_importance(model, features, name):
    imp = pd.Series(model.feature_importances_, index=features).sort_values(ascending=False)
    top = imp.head(20)
    plt.figure(figsize=(8, 7))
    sns.barplot(x=top.values, y=top.index, color="#3b6fb6")
    plt.title(f"{name} - top 20 feature importances")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "feature_importance.png", dpi=150)
    plt.close()
    return imp


def main():
    if not FLOWS_PARQUET.exists():
        sys.exit(f"{FLOWS_PARQUET} not found - run `python -m src.prepare_flows` first")
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(FLOWS_PARQUET)
    X = df.drop(columns=["Label"])
    X = X.loc[:, X.nunique() > 1]  # constant columns carry no information
    features = list(X.columns)

    encoder = LabelEncoder()
    y = encoder.fit_transform(df["Label"])
    classes = list(encoder.classes_)
    print(f"{len(df):,} flows, {len(features)} features, classes: {classes}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    candidates = {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, n_jobs=-1, class_weight="balanced_subsample",
            random_state=RANDOM_STATE,
        ),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1, tree_method="hist",
            n_jobs=-1, random_state=RANDOM_STATE, eval_metric="mlogloss",
        ),
    }

    results, fitted = {}, {}
    for name, model in candidates.items():
        t = time.perf_counter()
        model.fit(X_train, y_train)
        train_s = time.perf_counter() - t
        results[name] = evaluate(name, model, X_test, y_test, classes)
        results[name]["train_seconds"] = train_s
        fitted[name] = model

    best_name = max(results, key=lambda n: results[n]["macro_f1"])
    best = fitted[best_name]
    print(f"\nBest model by macro F1: {best_name} ({results[best_name]['macro_f1']:.4f})")

    importance = save_feature_importance(best, features, best_name)
    joblib.dump(
        {
            "model": best,
            "model_name": best_name,
            "features": features,
            "classes": classes,
            "feature_importance": importance.to_dict(),
        },
        FLOW_MODEL_PATH,
    )

    # Anomaly detector: learns what normal traffic looks like, flags outliers.
    benign_idx = classes.index("Benign")
    X_benign_train = X_train[y_train == benign_idx]
    iso = IsolationForest(n_estimators=200, n_jobs=-1, random_state=RANDOM_STATE)
    iso.fit(X_benign_train)
    threshold = float(np.quantile(iso.decision_function(X_benign_train), ANOMALY_BENIGN_FLAG_RATE))
    joblib.dump({"model": iso, "features": features, "threshold": threshold}, ANOMALY_MODEL_PATH)

    flagged = iso.decision_function(X_test) < threshold
    anomaly_eval = {
        "threshold": threshold,
        "benign_false_alarm_rate": float(flagged[y_test == benign_idx].mean()),
        "attack_flag_rate_by_class": {
            c: float(flagged[y_test == i].mean()) for i, c in enumerate(classes) if i != benign_idx
        },
    }
    print(f"\nAnomaly detector: {json.dumps(anomaly_eval, indent=2)}")

    # Benign baseline lets the backend say things like "4.2x normal packet rate".
    baseline = {
        f: {
            "median": float(X_benign_train[f].median()),
            "p95": float(X_benign_train[f].quantile(0.95)),
        }
        for f in features
    }
    BASELINE_PATH.write_text(json.dumps(baseline, indent=2))

    metrics = {
        "dataset": {
            "total_flows": len(df),
            "train_flows": len(X_train),
            "test_flows": len(X_test),
            "class_counts": df["Label"].value_counts().to_dict(),
            "n_features": len(features),
        },
        "models": results,
        "selected_model": best_name,
        "anomaly_detector": anomaly_eval,
        "top_features": importance.head(10).to_dict(),
    }
    (REPORTS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"\nSaved models to {MODELS_DIR} and reports to {REPORTS_DIR}")


if __name__ == "__main__":
    main()
