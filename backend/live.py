"""Simulated live monitoring: replays held-out test flows (data/samples) as a
real-time stream following a scripted attack timeline, classifying each
one-second batch as it arrives. Clearly a simulation - real deployment would
feed flows from CICFlowMeter running on a network interface instead.
"""
import json
import time
from datetime import datetime

import numpy as np
import pandas as pd

from src.config import ROOT, SEVERITY

SAMPLES_DIR = ROOT / "data" / "samples"
ALERT_MIN_FLOWS = 5          # same idea as MIN_INCIDENT_FLOWS: ignore stray flows
WINDOW_TICKS = 30            # live score looks at the last 30 seconds
SEVERITY_WEIGHT = {"Critical": 40, "High": 25, "Medium": 10}
LIVE_SCORE_SCALE = 2.5

# (duration in ticks, attack class or None, attack flows per tick)
SCENARIOS = {
    "timeline": {
        "title": "Attack timeline (scan → brute force → DDoS)",
        "phases": [(12, None, 0), (14, "PortScan", 30), (8, None, 0), (14, "BruteForce", 20),
                   (8, None, 0), (16, "DDoS", 60), (8, None, 0)],
    },
    "normal": {"title": "Normal traffic only", "phases": [(40, None, 0)]},
    "dos": {"title": "DoS attack", "phases": [(10, None, 0), (20, "DoS", 45), (10, None, 0)]},
    "ddos": {"title": "DDoS attack", "phases": [(10, None, 0), (20, "DDoS", 70), (10, None, 0)]},
}
BENIGN_PER_TICK = (35, 60)


def _load_pool() -> dict[str, pd.DataFrame]:
    frames = [pd.read_csv(p) for p in sorted(SAMPLES_DIR.glob("*.csv"))]
    if not frames:
        raise RuntimeError("No demo samples found - run `python -m src.make_demo_samples`")
    df = pd.concat(frames, ignore_index=True)
    return {label: g.reset_index(drop=True) for label, g in df.groupby("Label")}


class LiveMonitor:
    def __init__(self, detector, knowledge):
        self.detector = detector
        self.kb = knowledge
        self.pool = _load_pool()

    def _sse(self, event: str, data: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(data)}\n\n"

    def stream(self, scenario: str, speed: float, on_finish):
        spec = SCENARIOS.get(scenario, SCENARIOS["timeline"])
        rng = np.random.default_rng()
        interval = 1.0 / max(0.5, min(speed, 5.0))
        timeline = [(cls, n) for dur, cls, n in spec["phases"] for _ in range(dur)]
        seen, window, totals = [], [], {}
        active_alerts = {}  # threat -> alert id, so one wave = one alert that updates

        yield self._sse("start", {"scenario": spec["title"], "ticks": len(timeline)})
        for tick, (attack, n_attack) in enumerate(timeline):
            started = time.perf_counter()
            parts = [self.pool["Benign"].sample(int(rng.integers(*BENIGN_PER_TICK)), random_state=int(rng.integers(1e9)))]
            if attack and attack in self.pool:
                jitter = max(1, int(n_attack * rng.uniform(0.7, 1.3)))
                parts.append(self.pool[attack].sample(jitter, replace=True, random_state=int(rng.integers(1e9))))
            batch = pd.concat(parts, ignore_index=True)
            pred, conf = self.detector.classify(batch)
            seen.append(batch)

            counts = pd.Series(pred).value_counts().to_dict()
            for c, n in counts.items():
                totals[c] = totals.get(c, 0) + int(n)

            alerts, tick_penalty = [], 0.0
            for threat, n in counts.items():
                if threat == "Benign" or n < ALERT_MIN_FLOWS:
                    continue
                mask = pred == threat
                severity = SEVERITY.get(threat, "Medium")
                confidence = float(conf[mask].mean())
                tick_penalty += SEVERITY_WEIGHT[severity] * confidence
                if threat not in active_alerts:  # new attack wave -> new alert
                    pb = self.kb.playbook(threat) or {}
                    active_alerts[threat] = f"{threat}-{tick}"
                    evidence = self.detector._deviations(batch[mask].astype({f: np.float32 for f in self.detector.features}), limit=2)
                    alerts.append({
                        "id": active_alerts[threat], "threat": threat, "title": pb.get("title", threat),
                        "severity": severity, "confidence": round(confidence, 4), "flows": int(n),
                        "time": datetime.now().strftime("%H:%M:%S"), "evidence": evidence,
                        "action": (pb.get("recommendations") or [{}])[0].get("action", ""),
                    })
            # waves that stopped this tick are no longer active
            for threat in [t for t in active_alerts if counts.get(t, 0) < ALERT_MIN_FLOWS]:
                active_alerts.pop(threat)

            window.append(tick_penalty)
            window = window[-WINDOW_TICKS:]
            # Live score: 100 - 2.5 x average threat penalty per second over the last 30 s.
            # One Critical wave lasting 15 s (40 x 15 / 30 x 2.5) drops it to ~50.
            score = round(max(0.0, 100 - LIVE_SCORE_SCALE * sum(window) / WINDOW_TICKS))

            yield self._sse("tick", {
                "tick": tick + 1, "of": len(timeline), "time": datetime.now().strftime("%H:%M:%S"),
                "flows": len(batch), "counts": {k: int(v) for k, v in counts.items()},
                "totals": totals, "alerts": alerts, "active": sorted(active_alerts), "score": score,
                "mean_confidence": round(float(conf.mean()), 4),
            })
            time.sleep(max(0.0, interval - (time.perf_counter() - started)))

        analysis = on_finish(pd.concat(seen, ignore_index=True), f"Live session - {spec['title']}")
        yield self._sse("done", {"analysis_id": analysis["id"], "score": analysis["score"]["value"],
                                 "headline": analysis["status"]["headline"]})
