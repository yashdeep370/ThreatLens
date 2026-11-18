"""Retrieval over the knowledge base (the 'R' in RAG).

TF-IDF similarity between the question and each knowledge chunk, boosted for
chunks about the threats in the current analysis. Small, fast, fully offline,
and every answer can cite which chunks it used.
"""
import json

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from src.config import ROOT

KNOWLEDGE_DIR = ROOT / "knowledge"
THREAT_BOOST = 0.25


class KnowledgeBase:
    def __init__(self):
        self.playbooks = json.loads((KNOWLEDGE_DIR / "playbooks.json").read_text(encoding="utf-8"))
        kb_path = KNOWLEDGE_DIR / "kb.json"
        if kb_path.exists():
            self.chunks = json.loads(kb_path.read_text(encoding="utf-8"))
        else:  # run `python -m src.build_knowledge` for MITRE content
            self.chunks = [{"id": t, "title": p["title"], "threat": t, "source": "Project playbook",
                            "text": f"{p['summary']} {p['impact']}"} for t, p in self.playbooks.items()]
        self.vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
        self.matrix = self.vectorizer.fit_transform(f"{c['title']} {c['threat']} {c['text']}" for c in self.chunks)

    def search(self, query: str, threats: list[str] = (), k: int = 5) -> list[dict]:
        scores = cosine_similarity(self.vectorizer.transform([query]), self.matrix)[0]
        for i, c in enumerate(self.chunks):
            if c["threat"] in threats:
                scores[i] += THREAT_BOOST
        top = scores.argsort()[::-1][:k]
        return [self.chunks[i] | {"score": round(float(scores[i]), 3)} for i in top if scores[i] > 0.02]

    def playbook(self, threat: str) -> dict | None:
        return self.playbooks.get(threat)

    def mitre_names(self) -> dict:
        """'T1110' -> 'Brute Force', parsed from chunk titles like 'MITRE ATT&CK T1110: Brute Force'."""
        names = {}
        for c in self.chunks:
            if c["title"].startswith("MITRE ATT&CK ") and ": " in c["title"]:
                tid, name = c["title"][len("MITRE ATT&CK "):].split(": ", 1)
                names[tid] = name
        return names
