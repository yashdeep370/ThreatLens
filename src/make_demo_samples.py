"""Create demo CSVs for the website from the TEST split only (rows the model
never saw during training). Same split parameters as train_flows.py.

Usage:  python -m src.make_demo_samples
"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from src.config import FLOWS_PARQUET, RANDOM_STATE, ROOT

SAMPLES_DIR = ROOT / "data" / "samples"

SAMPLES = {
    "01_normal_traffic.csv": {"Benign": 3000},
    "02_bruteforce_attack.csv": {"Benign": 2500, "BruteForce": 400},
    "03_dos_attack.csv": {"Benign": 2500, "DoS": 800},
    "04_ddos_attack.csv": {"Benign": 2000, "DDoS": 1500},
    "05_portscan_attack.csv": {"Benign": 2500, "PortScan": 600},
    "06_mixed_attacks.csv": {"Benign": 4000, "DoS": 300, "DDoS": 300, "BruteForce": 300, "PortScan": 300},
}


def main():
    df = pd.read_parquet(FLOWS_PARQUET)
    _, test_idx = train_test_split(
        np.arange(len(df)), test_size=0.2, stratify=df["Label"], random_state=RANDOM_STATE
    )
    test = df.iloc[test_idx]
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(RANDOM_STATE)

    for name, mix in SAMPLES.items():
        parts = [test[test["Label"] == label].sample(n, random_state=int(rng.integers(1e9)))
                 for label, n in mix.items()]
        out = pd.concat(parts).sample(frac=1, random_state=RANDOM_STATE)
        out.to_csv(SAMPLES_DIR / name, index=False)
        print(f"{name:<28} {len(out):>6,} flows  {mix}")


if __name__ == "__main__":
    main()
