"""Build the chatbot's knowledge base (knowledge/kb.json).

Combines:
  - MITRE ATT&CK technique descriptions and official mitigations for the
    techniques our threats map to (from data/raw/mitre/enterprise-attack.json)
  - our curated playbooks (knowledge/playbooks.json)
  - short project documents (how the models / score work, limitations)

Each entry is one retrievable chunk: {id, title, threat, source, text}.

Usage:  python -m src.build_knowledge
"""
import json
import re

from src.config import DATA_RAW, ROOT

KNOWLEDGE_DIR = ROOT / "knowledge"
MITRE_PATH = DATA_RAW / "mitre" / "enterprise-attack.json"
CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MD_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
MAX_CHARS = 1500

PROJECT_DOCS = [
    ("How threats are detected",
     "Network traffic is analyzed as flows (one flow = one connection) with about 69 statistical "
     "features such as packet sizes, packet rates, durations and idle times, in the CICFlowMeter format. "
     "An XGBoost classifier trained on the CIC-IDS2017 dataset labels each flow as Benign, DoS, DDoS, "
     "BruteForce or PortScan. It was compared against a Random Forest and selected for its higher macro F1 "
     "score (0.9994 on a held-out test set of 71,830 flows). Flows predicted as Benign are also checked by "
     "an Isolation Forest anomaly detector trained only on normal traffic."),
    ("What the confidence value means",
     "Confidence is the probability the classifier assigns to its predicted class, averaged over the flows "
     "in an incident. It reflects how strongly the traffic matches patterns learned from the training data. "
     "It is not a guarantee: traffic from a different network than the training data can be misclassified."),
    ("How the security score works",
     "The security posture score starts at 100 and subtracts a penalty per incident. Penalty = severity weight "
     "(Critical 40, High 25, Medium 10) x mean confidence x volume factor (0.5 below 10 flows, 0.75 below 100 "
     "flows, 1.0 otherwise). Bands: 90-100 low observed risk, 70-89 moderate, 40-69 high, 0-39 critical. "
     "It is an observed-risk score for the analyzed traffic, not a guarantee that a system is secure."),
    ("Limitations of the system",
     "The system detects known attack patterns it was trained on and unusual traffic, but cannot prove that "
     "a system is secure. Models trained on lab data (CIC-IDS2017) may perform worse on real networks. Flow "
     "data does not show packet contents or whether logins succeeded. URL analysis is based on the URL text "
     "and public page checks only. The system recommends actions but never blocks anything automatically; a "
     "human decides (human-in-the-loop)."),
    ("Website security headers",
     "Strict-Transport-Security (HSTS) forces browsers to use HTTPS. Content-Security-Policy (CSP) restricts "
     "which scripts can run and reduces cross-site scripting (XSS) risk. X-Frame-Options or CSP frame-ancestors "
     "prevents clickjacking. X-Content-Type-Options: nosniff stops MIME type sniffing. Referrer-Policy limits "
     "what URL information is leaked to other sites. Permissions-Policy restricts browser features like camera "
     "or location. Missing headers are weaknesses in defense-in-depth, not proof of compromise."),
]


def clean(text: str) -> str:
    text = CITATION_RE.sub("", text)
    text = MD_LINK_RE.sub(r"\1", text)
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:MAX_CHARS] + ("..." if len(text) > MAX_CHARS else "")


def mitre_entries(playbooks: dict) -> list[dict]:
    if not MITRE_PATH.exists():
        print(f"{MITRE_PATH} not found - skipping MITRE entries")
        return []
    technique_threats = {}
    for threat, pb in playbooks.items():
        for tid in pb["mitre"]:
            technique_threats.setdefault(tid, []).append(threat)

    objects = json.loads(MITRE_PATH.read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objects}
    techniques = {}
    for o in objects:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r["external_id"] for r in o.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if ext in technique_threats:
            techniques[o["id"]] = (ext, o)

    mitigations = {stix_id: [] for stix_id in techniques}
    for rel in objects:
        if rel["type"] == "relationship" and rel.get("relationship_type") == "mitigates" \
                and rel["target_ref"] in mitigations and not rel.get("revoked"):
            coa = by_id.get(rel["source_ref"], {})
            if coa.get("x_mitre_deprecated"):
                continue
            mitigations[rel["target_ref"]].append(f"{coa.get('name', 'Mitigation')}: {clean(rel.get('description', ''))}")

    entries = []
    for stix_id, (ext, o) in techniques.items():
        for threat in technique_threats[ext]:
            entries.append({
                "id": f"mitre-{ext}-{threat}", "title": f"MITRE ATT&CK {ext}: {o['name']}",
                "threat": threat, "source": f"MITRE ATT&CK {ext}", "text": clean(o["description"]),
            })
            if mitigations[stix_id]:
                entries.append({
                    "id": f"mitre-{ext}-{threat}-mitigations", "title": f"MITRE ATT&CK {ext} mitigations",
                    "threat": threat, "source": f"MITRE ATT&CK {ext}",
                    "text": clean(" | ".join(mitigations[stix_id])),
                })
    return entries


def playbook_entries(playbooks: dict) -> list[dict]:
    entries = []
    for threat, pb in playbooks.items():
        src = "Project playbook"
        entries.append({"id": f"pb-{threat}-overview", "title": pb["title"], "threat": threat, "source": src,
                        "text": f"{pb['summary']} Impact: {pb['impact']} Indicators: {pb['indicators']}"})
        recs = " ".join(f"{i}. {r['action']} - {r['why']}" for i, r in enumerate(pb["recommendations"], 1))
        entries.append({"id": f"pb-{threat}-actions", "title": f"{pb['title']}: recommended actions",
                        "threat": threat, "source": src, "text": recs})
    return entries


def main():
    playbooks = json.loads((KNOWLEDGE_DIR / "playbooks.json").read_text(encoding="utf-8"))
    entries = playbook_entries(playbooks) + mitre_entries(playbooks)
    entries += [{"id": f"doc-{i}", "title": t, "threat": "General", "source": "Project documentation", "text": x}
                for i, (t, x) in enumerate(PROJECT_DOCS)]
    (KNOWLEDGE_DIR / "kb.json").write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    mitre = sum(e["source"].startswith("MITRE") for e in entries)
    print(f"Saved {len(entries)} knowledge chunks ({mitre} from MITRE ATT&CK) -> {KNOWLEDGE_DIR / 'kb.json'}")


if __name__ == "__main__":
    main()
