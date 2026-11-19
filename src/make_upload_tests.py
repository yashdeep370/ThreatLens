"""Create CSV files for testing the website's Upload feature (data/test_uploads/).

Every row is one the classifier never trained on:
  - Benign / DoS / DDoS / BruteForce / PortScan rows come from the held-out TEST split
    (same split parameters as train_flows.py)
  - Bot, Web Attack and Infiltration rows come from the raw CIC-IDS2017 CSVs; these
    classes were excluded from training entirely, so they test unknown-attack handling

Usage:  python -m src.make_upload_tests
"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.config import CICIDS_DIR, FLOWS_PARQUET, RANDOM_STATE, ROOT

OUT_DIR = ROOT / "data" / "test_uploads"
UNSEEN_PREFIXES = ("Bot", "Web Attack", "Infiltration")


def test_split() -> pd.DataFrame:
    df = pd.read_parquet(FLOWS_PARQUET)
    _, test_idx = train_test_split(np.arange(len(df)), test_size=0.2, stratify=df["Label"],
                                   random_state=RANDOM_STATE)
    return df.iloc[test_idx]


def mix(test: pd.DataFrame, counts: dict, seed: int) -> pd.DataFrame:
    parts = [test[test["Label"] == label].sample(n, random_state=seed) for label, n in counts.items()]
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)


def unseen_attacks(columns) -> pd.DataFrame:
    """Bot / Web Attack / Infiltration rows from the raw CSVs, cleaned the same way."""
    frames = []
    for path in sorted(CICIDS_DIR.rglob("*.csv")):
        raw = pd.read_csv(path, encoding="latin-1", low_memory=False)
        raw.columns = raw.columns.str.strip()
        # The original files contain a broken dash in "Web Attack - XSS" etc.; normalize it.
        raw["Label"] = (raw["Label"].astype(str).str.strip()
                        .str.replace(r"\s*(ï¿½|�|\x96)\s*", " - ", regex=True))
        keep = raw[raw["Label"].str.startswith(UNSEEN_PREFIXES)]
        if not keep.empty:
            frames.append(keep)
    df = pd.concat(frames, ignore_index=True)
    feats = [c for c in columns if c != "Label"]
    df[feats] = df[feats].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=feats).drop_duplicates(subset=feats)
    return df[columns]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    test = test_split()
    columns = list(test.columns)

    files = {}
    # No Label column: the realistic case where the system doesn't know the answer.
    files["01_unlabelled_normal_office_day.csv"] = mix(test, {"Benign": 4000}, 1).drop(columns="Label")
    files["02_unlabelled_hidden_attacks.csv"] = mix(
        test, {"Benign": 5000, "PortScan": 250, "BruteForce": 150, "DoS": 200}, 2).drop(columns="Label")
    # Labelled: the website also reports accuracy against the true labels.
    files["03_labelled_full_day_15k.csv"] = mix(
        test, {"Benign": 11000, "DoS": 1200, "DDoS": 1200, "PortScan": 1000, "BruteForce": 600}, 3)

    unseen = unseen_attacks(columns)
    per_type = unseen.groupby("Label").apply(lambda g: g.sample(min(len(g), 300), random_state=4),
                                             include_groups=False).reset_index(level=0)
    benign = test[test["Label"] == "Benign"].sample(3000, random_state=4)
    files["04_unseen_attack_types.csv"] = pd.concat([benign, per_type[columns]]).sample(
        frac=1, random_state=4).reset_index(drop=True)

    # Wrong format on purpose: shows the upload validation message.
    files["05_invalid_format_example.csv"] = pd.DataFrame({
        "timestamp": ["2026-11-19 10:00:01", "2026-11-19 10:00:02"],
        "src_ip": ["192.168.1.10", "192.168.1.11"], "dst_ip": ["10.0.0.5", "10.0.0.5"], "bytes": [512, 2048],
    })

    for name, df in files.items():
        df.to_csv(OUT_DIR / name, index=False)
        size = (OUT_DIR / name).stat().st_size / 2**20
        labels = df["Label"].value_counts().to_dict() if "Label" in df.columns else "no labels"
        print(f"{name:<40} {len(df):>6,} rows  {size:5.1f} MB  {labels}")


if __name__ == "__main__":
    main()
