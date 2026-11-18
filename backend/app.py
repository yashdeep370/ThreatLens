"""FastAPI backend + static website.

Run:  python -m uvicorn backend.app:app --reload
Open: http://127.0.0.1:8000
"""
import json
from collections import OrderedDict
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.config import ROOT

load_dotenv(ROOT / ".env")

from backend import llm  # noqa: E402  (needs env loaded first)
from backend.detector import FlowDetector  # noqa: E402
from backend.knowledge import KnowledgeBase  # noqa: E402
from backend.url_checker import UrlChecker  # noqa: E402

FRONTEND_DIR = ROOT / "frontend"
SAMPLES_DIR = ROOT / "data" / "samples"
HISTORY_PATH = ROOT / "data" / "history.json"
MAX_HISTORY = 50

kb = KnowledgeBase()
detector = FlowDetector(kb)
url_checker = UrlChecker(kb)

app = FastAPI(title="AI Threat Detection & Security Assessment")


# ---------- history (persisted so a restart doesn't wipe the dashboard) ----------
def _load_history() -> OrderedDict:
    try:
        return OrderedDict((a["id"], a) for a in json.loads(HISTORY_PATH.read_text(encoding="utf-8")))
    except Exception:
        return OrderedDict()


history = _load_history()


def _remember(analysis: dict) -> dict:
    history[analysis["id"]] = analysis
    while len(history) > MAX_HISTORY:
        history.popitem(last=False)
    HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_PATH.write_text(json.dumps(list(history.values())), encoding="utf-8")
    return analysis


# ---------- API ----------
@app.get("/api/status")
def status():
    return {
        "flow_model": detector.model_name,
        "flow_classes": detector.classes,
        "knowledge_chunks": len(kb.chunks),
        "llm": llm.status(),
        "analyses": len(history),
    }


@app.post("/api/analyze/flows")
def analyze_flows(file: UploadFile = File(...)):
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "Please upload a .csv file of network flows")
    try:
        return _remember(detector.analyze(file.file, file.filename))
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/api/samples")
def list_samples():
    return sorted(p.name for p in SAMPLES_DIR.glob("*.csv")) if SAMPLES_DIR.exists() else []


@app.post("/api/analyze/sample/{name}")
def analyze_sample(name: str):
    path = SAMPLES_DIR / Path(name).name  # Path().name blocks ../ traversal
    if not path.is_file():
        raise HTTPException(404, "Sample not found")
    with path.open("rb") as f:
        return _remember(detector.analyze(f, path.name))


class UrlRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    live: bool = True


@app.post("/api/analyze/url")
def analyze_url(req: UrlRequest):
    return _remember(url_checker.check(req.url, live=req.live))


@app.get("/api/history")
def list_history():
    out = []
    for a in reversed(history.values()):
        out.append({
            "id": a["id"], "type": a["type"], "analyzed_at": a["analyzed_at"],
            "name": a.get("filename") or a.get("url"), "status": a["status"],
            "score": a["score"]["value"], "threats": a.get("threats_detected", int(bool(a.get("threat")))),
        })
    return out


@app.get("/api/analysis/{analysis_id}")
def get_analysis(analysis_id: str):
    if analysis_id not in history:
        raise HTTPException(404, "Analysis not found")
    return history[analysis_id]


# ---------- chatbot ----------
SYSTEM_PROMPT = """You are the security assistant inside an AI threat detection system.
You explain detection results and recommend defensive actions to the user.

Rules:
- Base answers on the ANALYSIS CONTEXT and KNOWLEDGE provided. If they don't contain the answer, say so.
- Explain predictions using the listed evidence. Do not invent numbers, IPs or findings.
- Never claim a system is 100% secure or that an IP is definitely malicious; detections are model-based
  assessments with stated confidence.
- The system never blocks anything automatically; recommend actions for a human to decide.
- Give defensive guidance only. Refuse to help carry out attacks.
- Be concise: short paragraphs or bullet points. Mention MITRE ATT&CK IDs when relevant.
"""


class ChatTurn(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    analysis_id: str | None = None
    history: list[ChatTurn] = []


def _analysis_context(a: dict | None) -> tuple[str, list[str]]:
    if not a:
        return "No analysis selected.", []
    if a["type"] == "flows":
        ctx = {
            "file": a["filename"], "status": a["status"]["headline"], "security_score": a["score"],
            "total_flows": a["total_flows"], "malicious_flows": a["malicious_flows"],
            "detection_model": a["model"], "anomaly_detector": a["anomaly"], "evaluation_vs_labels": a["evaluation"],
            "incidents": [{k: i[k] for k in ("title", "severity", "confidence", "flows", "share", "evidence",
                                             "mitre", "top_ports")}
                          | {"recommended_actions": [r["action"] for r in i["recommendations"]]}
                          for i in a["incidents"]],
        }
        return json.dumps(ctx, indent=1), [i["threat"] for i in a["incidents"]]
    ctx = {"url": a["url"], "status": a["status"]["headline"], "model_verdict": a["model"],
           "website_score": a["score"], "live_checks": a["live"]}
    return json.dumps(ctx, indent=1), [a["threat"]] if a["threat"] else []


def _offline_answer(message: str, analysis: dict | None, chunks: list[dict]) -> str:
    """Used when no LLM is reachable: answer from the analysis and knowledge base directly."""
    q = message.lower()
    incidents = (analysis or {}).get("incidents") or []
    if analysis and analysis["type"] == "url":
        pb = analysis.get("playbook")
        incidents = [{"title": pb["title"], "evidence": analysis["model"]["red_flags"],
                      "recommendations": pb["recommendations"]}] if pb else []
    if incidents and any(w in q for w in ("why", "evidence", "reason", "how did", "explain")):
        i = incidents[0]
        return f"**{i['title']}** was flagged based on this evidence:\n" + "\n".join(f"- {e}" for e in i["evidence"])
    if incidents and any(w in q for w in ("do", "recommend", "fix", "mitigat", "should", "prevent", "action")):
        i = incidents[0]
        return f"Recommended actions for **{i['title']}**:\n" + "\n".join(
            f"{n}. {r['action']} - {r['why']}" for n, r in enumerate(i["recommendations"], 1))
    if chunks:
        return f"**{chunks[0]['title']}** ({chunks[0]['source']}):\n{chunks[0]['text']}"
    return "I couldn't find information about that in the current analysis or knowledge base."


@app.post("/api/chat")
def chat(req: ChatRequest):
    analysis = history.get(req.analysis_id) if req.analysis_id else None
    context, threats = _analysis_context(analysis)
    chunks = kb.search(f"{req.message} {' '.join(threats)}", threats=threats, k=5)
    knowledge = "\n\n".join(f"[{c['source']}] {c['title']}: {c['text']}" for c in chunks)

    prompt = f"ANALYSIS CONTEXT:\n{context}\n\nKNOWLEDGE:\n{knowledge}\n\nQUESTION: {req.message}"
    messages = [t.model_dump() for t in req.history[-6:] if t.role in ("user", "assistant")]
    messages.append({"role": "user", "content": prompt})
    try:
        answer, provider = llm.chat(SYSTEM_PROMPT, messages)
    except llm.LLMUnavailable as e:
        answer, provider = _offline_answer(req.message, analysis, chunks), "offline knowledge base"
        print(f"LLM unavailable, used offline answer: {e}")
    return {
        "answer": answer,
        "provider": provider,
        "sources": [{"title": c["title"], "source": c["source"]} for c in chunks],
    }


# ---------- website ----------
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")
