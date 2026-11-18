"""Clean CIC-IDS2017 CSVs into one balanced parquet file.

Steps per file: strip column names, map labels to our categories, drop
unwanted classes, replace inf with NaN, drop NaN rows, downcast to float32.
Then de-duplicate across files and cap each class (see config.CLASS_CAP).

Usage:  python -m src.prepare_flows
"""
import sys

import numpy as np
import pandas as pd

from src.config import (
    CICIDS_DIR, CLASS_CAP, DATA_PROCESSED, FLOWS_PARQUET, LABEL_MAP, RANDOM_STATE,
)


def load_file(path) -> pd.DataFrame:
    # latin-1 because the Thursday file contains a non-UTF-8 dash in labels.
    df = pd.read_csv(path, encoding="latin-1", low_memory=False)
    df.columns = df.columns.str.strip()
    # Duplicate header in the original data ("Fwd Header Length" appears twice).
    df = df.drop(columns=[c for c in df.columns if c.endswith(".1")])

    df["Label"] = df["Label"].astype(str).str.strip().map(LABEL_MAP)
    df = df.dropna(subset=["Label"])

    features = df.columns.drop("Label")
    df[features] = df[features].apply(pd.to_numeric, errors="coerce")
    df[features] = df[features].replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    df[features] = df[features].astype(np.float32)
    return df


def main():
    # rglob: the zip extracts into a MachineLearningCVE/ subfolder.
    files = sorted(CICIDS_DIR.rglob("*.csv"))
    if not files:
        sys.exit(f"No CSV files found in {CICIDS_DIR}")

    parts = []
    for f in files:
        part = load_file(f)
        print(f"{f.name:<70} {len(part):>9,} rows kept  {part['Label'].value_counts().to_dict()}")
        parts.append(part)

    df = pd.concat(parts, ignore_index=True)
    before = len(df)
    df = df.drop_duplicates()
    print(f"\nRemoved {before - len(df):,} duplicate rows ({(before - len(df)) / before:.1%})")

    df = pd.concat(
        [g.sample(n=min(len(g), CLASS_CAP[label]), random_state=RANDOM_STATE)
         for label, g in df.groupby("Label")],
        ignore_index=True,
    )

    DATA_PROCESSED.mkdir(parents=True, exist_ok=True)
    df.to_parquet(FLOWS_PARQUET, index=False)
    print(f"\nFinal class counts:\n{df['Label'].value_counts().to_string()}")
    print(f"\nSaved {len(df):,} rows x {df.shape[1] - 1} features -> {FLOWS_PARQUET}")


if __name__ == "__main__":
    main()
