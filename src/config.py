"""Shared paths and settings for the whole project."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DATA_RAW = ROOT / "data" / "raw"
CICIDS_DIR = DATA_RAW / "cicids2017"
URLS_DIR = DATA_RAW / "urls"
DATA_PROCESSED = ROOT / "data" / "processed"
MODELS_DIR = ROOT / "models"
REPORTS_DIR = ROOT / "reports"

FLOWS_PARQUET = DATA_PROCESSED / "flows.parquet"
URLS_PARQUET = DATA_PROCESSED / "urls.parquet"

FLOW_MODEL_PATH = MODELS_DIR / "flow_classifier.joblib"
ANOMALY_MODEL_PATH = MODELS_DIR / "flow_anomaly.joblib"
BASELINE_PATH = MODELS_DIR / "benign_baseline.json"
URL_MODEL_PATH = MODELS_DIR / "url_classifier.joblib"

RANDOM_STATE = 42

# CIC-IDS2017 raw label -> our threat category. Labels not listed are dropped
# (Bot, Infiltration, Heartbleed, Web Attack rows are too few to learn from;
# web threats are handled by the separate URL model instead).
LABEL_MAP = {
    "BENIGN": "Benign",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
}

# Max rows kept per class after de-duplication, so training fits in minutes
# on a laptop while keeping Benign as the majority class (like real traffic).
CLASS_CAP = {
    "Benign": 200_000,
    "DoS": 50_000,
    "DDoS": 50_000,
    "PortScan": 50_000,
    "BruteForce": 50_000,
}

SEVERITY = {
    "DDoS": "Critical",
    "DoS": "Critical",
    "BruteForce": "High",
    "PortScan": "High",
    "WebAttack": "High",
    "Anomaly": "Medium",
    "Benign": "None",
}
