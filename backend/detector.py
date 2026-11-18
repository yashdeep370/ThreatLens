"""Network-flow analysis: classify flows, group them into incidents, build
evidence, and compute the observed-risk security score."""
import uuid
from datetime import datetime

import joblib
import json
import numpy as np
import pandas as pd

from src.config import ANOMALY_MODEL_PATH, BASELINE_PATH, FLOW_MODEL_PATH, LABEL_MAP, SEVERITY

# Anomalies are only an incident when clearly above the calibrated noise level.
ANOMALY_REPORT_MULTIPLIER = 2.0
ANOMALY_MIN_FLOWS = 10
# Fewer flows than this are listed as isolated detections (likely misclassifications),
# not incidents - alert aggregation avoids alert fatigue from single stray flows.
MIN_INCIDENT_FLOWS = 5

SEVERITY_WEIGHT = {"Critical": 40, "High": 25, "Medium": 10}
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2}

FEATURE_TEXT = {
    "Flow Packets/s": "packet rate",
    "Flow Bytes/s": "data rate",
    "Flow Duration": "connection duration",
    "Total Fwd Packets": "packets sent per connection",
    "Total Backward Packets": "response packets per connection",
    "Total Length of Fwd Packets": "bytes sent per connection",
    "Total Length Bwd Packets": "bytes received per connection",
    "Average Packet Size": "average packet size",
    "Max Packet Length": "largest packet size",
    "Fwd Packet Length Mean": "average request packet size",
    "Bwd Packet Length Std": "variation in response packet sizes",
    "Flow IAT Mean": "average time between packets",
    "Idle Max": "maximum idle time",
    "Idle Mean": "average idle time",
    "Init_Win_bytes_forward": "initial TCP window size",
    "act_data_pkt_fwd": "data-carrying packets sent",
}

PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
    3389: "RDP", 8080: "HTTP-alt",
}


def score_band(score: float) -> tuple[str, str]:
    if score >= 90:
        return "low", "Low observed risk"
    if score >= 70:
        return "moderate", "Moderate risk"
    if score >= 40:
        return "high", "High risk"
    return "critical", "Critical risk"


def volume_factor(flows: int) -> float:
    return 0.5 if flows < 10 else 0.75 if flows < 100 else 1.0


class FlowDetector:
    def __init__(self, knowledge):
        bundle = joblib.load(FLOW_MODEL_PATH)
        self.model = bundle["model"]
        self.model_name = bundle["model_name"]
        self.features = bundle["features"]
        self.classes = bundle["classes"]
        importance = bundle["feature_importance"]
        anomaly = joblib.load(ANOMALY_MODEL_PATH)
        self.iso, self.iso_threshold = anomaly["model"], anomaly["threshold"]
        self.baseline = json.loads(BASELINE_PATH.read_text())
        self.kb = knowledge
        # Evidence candidates: readable features, most important first.
        self.evidence_features = sorted(
            (f for f in FEATURE_TEXT if f in self.features), key=lambda f: -importance.get(f, 0)
        )

    # ---------- input ----------
    def load_csv(self, file) -> tuple[pd.DataFrame, int]:
        df = pd.read_csv(file, encoding="latin-1", low_memory=False)
        df.columns = df.columns.str.strip()
        missing = [f for f in self.features if f not in df.columns]
        if missing:
            raise ValueError(
                f"CSV is missing {len(missing)} required flow features (CICFlowMeter format expected), "
                f"e.g. {missing[:5]}"
            )
        before = len(df)
        df[self.features] = df[self.features].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
        df = df.dropna(subset=self.features).reset_index(drop=True)
        if df.empty:
            raise ValueError("No valid flow rows found in the file")
        return df, before - len(df)

    # ---------- evidence ----------
    def _deviations(self, X: pd.DataFrame, limit=4) -> list[str]:
        out = []
        for f in self.evidence_features:
            base = self.baseline[f]["median"]
            value = float(X[f].median())
            if base <= 0 or value <= 0:
                continue
            ratio = value / base
            text = FEATURE_TEXT[f][0].upper() + FEATURE_TEXT[f][1:]
            if ratio >= 2:
                out.append(f"{text} is {ratio:,.1f}x higher than normal traffic")
            elif ratio <= 0.5:
                out.append(f"{text} is {1 / ratio:,.1f}x lower than normal traffic")
            if len(out) == limit:
                break
        return out

    def _ports(self, df: pd.DataFrame) -> tuple[list[dict], int]:
        if "Destination Port" not in df.columns:
            return [], 0
        counts = df["Destination Port"].astype(int).value_counts()
        top = [{"port": int(p), "service": PORT_NAMES.get(int(p), "other"), "flows": int(n)}
               for p, n in counts.head(3).items()]
        return top, int(counts.size)

    def _incident(self, threat, df_part, X_part, confidence, total, extra_evidence=()):
        pb = self.kb.playbook(threat) or {}
        ports, distinct_ports = self._ports(df_part)
        n = len(df_part)
        evidence = [f"{n:,} flows ({n / total:.1%} of analyzed traffic) classified as {pb.get('title', threat)}"]
        evidence += list(extra_evidence)
        if ports and ports[0]["flows"] / n >= 0.2:
            p = ports[0]
            evidence.append(f"{p['flows'] / n:.0%} of these flows target port {p['port']} ({p['service']})")
        if threat == "PortScan" and distinct_ports > 1:
            evidence.append(f"{distinct_ports:,} distinct destination ports probed")
        if "Source IP" in df_part.columns:
            sources = df_part["Source IP"].astype(str).value_counts()
            evidence.append(f"{sources.size:,} source IP(s); top: {sources.index[0]} ({sources.iloc[0]:,} flows)")
        evidence += self._deviations(X_part)

        severity = SEVERITY.get(threat, "Medium")
        penalty = SEVERITY_WEIGHT[severity] * confidence * volume_factor(n)
        return {
            "id": uuid.uuid4().hex[:8],
            "threat": threat,
            "title": pb.get("title", threat),
            "severity": severity,
            "confidence": round(confidence, 4),
            "flows": n,
            "share": round(n / total, 4),
            "top_ports": ports,
            "evidence": evidence,
            "summary": pb.get("summary", ""),
            "impact": pb.get("impact", ""),
            "mitre": pb.get("mitre", []),
            "recommendations": pb.get("recommendations", []),
            "penalty": round(penalty, 1),
        }

    # ---------- main entry ----------
    def analyze(self, file, filename: str) -> dict:
        df, skipped = self.load_csv(file)
        return self.analyze_df(df, filename, skipped)

    def classify(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Per-flow (predicted class, confidence). Used by the live monitor."""
        proba = self.model.predict_proba(df[self.features].astype(np.float32))
        return np.array(self.classes)[proba.argmax(axis=1)], proba.max(axis=1)

    def analyze_df(self, df: pd.DataFrame, filename: str, skipped: int = 0) -> dict:
        df = df.reset_index(drop=True)
        X = df[self.features].astype(np.float32)
        proba = self.model.predict_proba(X)
        pred_idx = proba.argmax(axis=1)
        conf = proba.max(axis=1)
        pred = np.array(self.classes)[pred_idx]
        total = len(df)

        incidents, isolated = [], []
        for threat in self.classes:
            if threat == "Benign":
                continue
            mask = pred == threat
            if mask.sum() >= MIN_INCIDENT_FLOWS:
                incidents.append(self._incident(threat, df[mask], X[mask], float(conf[mask].mean()), total))
            elif mask.any():
                isolated.append({"threat": threat, "flows": int(mask.sum()),
                                 "confidence": round(float(conf[mask].mean()), 4)})

        # Anomaly detector on traffic the classifier considers benign.
        benign_mask = pred == "Benign"
        anomaly = {"checked": int(benign_mask.sum()), "flagged": 0, "rate": 0.0, "expected_rate": 0.01, "reported": False}
        final_pred = pred.copy()
        if benign_mask.any():
            flagged = self.iso.decision_function(X[benign_mask]) < self.iso_threshold
            rate = float(flagged.mean())
            anomaly.update(flagged=int(flagged.sum()), rate=round(rate, 4))
            if rate > ANOMALY_REPORT_MULTIPLIER * anomaly["expected_rate"] and flagged.sum() >= ANOMALY_MIN_FLOWS:
                anomaly["reported"] = True
                idx = np.flatnonzero(benign_mask)[flagged]
                final_pred[idx] = "Anomaly"
                excess = 1 - anomaly["expected_rate"] / rate  # share of flags above expected noise
                incidents.append(self._incident(
                    "Anomaly", df.iloc[idx], X.iloc[idx], excess, total,
                    [f"Anomaly rate {rate:.1%} vs expected noise level of ~1% for normal traffic"],
                ))

        incidents.sort(key=lambda i: (SEVERITY_RANK[i["severity"]], -i["flows"]))
        score = max(0.0, 100 - sum(i["penalty"] for i in incidents))
        band, band_label = score_band(score)
        malicious = int((final_pred != "Benign").sum())

        if not incidents:
            status = {"level": "safe", "headline": "No significant malicious activity detected"}
        elif any(i["severity"] in ("Critical", "High") for i in incidents):
            top = incidents[0]
            status = {"level": "danger", "headline": f"Threat detected: {top['title']}"}
        else:
            status = {"level": "warning", "headline": "Unusual activity detected - review recommended"}

        return {
            "id": uuid.uuid4().hex[:10],
            "type": "flows",
            "filename": filename,
            "analyzed_at": datetime.now().isoformat(timespec="seconds"),
            "model": self.model_name,
            "total_flows": total,
            "skipped_rows": skipped,
            "malicious_flows": malicious,
            "threats_detected": len(incidents),
            "mean_confidence": round(float(conf.mean()), 4),
            "status": status,
            "score": {"value": round(score), "band": band, "label": band_label,
                      "breakdown": [{"threat": i["title"], "penalty": i["penalty"]} for i in incidents]},
            "class_distribution": {c: int(n) for c, n in pd.Series(final_pred).value_counts().items()},
            "anomaly": anomaly,
            "incidents": incidents,
            "isolated_detections": isolated,
            "evaluation": self._evaluate(df, pred),
        }

    def _evaluate(self, df, pred):
        """If the file carries ground-truth labels (like the CIC-IDS2017 CSVs), compare."""
        if "Label" not in df.columns:
            return None
        truth = df["Label"].astype(str).str.strip()
        truth = truth.map(lambda v: LABEL_MAP.get(v, v if v in self.classes else None))
        known = truth.notna().to_numpy()
        if not known.any():
            return None
        t, p = truth[known].to_numpy(), pred[known]
        attack = t != "Benign"
        return {
            "labelled_flows": int(known.sum()),
            "accuracy": round(float((t == p).mean()), 4),
            "attack_detection_rate": round(float((p[attack] != "Benign").mean()), 4) if attack.any() else None,
            "false_alarm_rate": round(float((p[~attack] != "Benign").mean()), 4) if (~attack).any() else None,
        }
