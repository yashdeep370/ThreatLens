"""FastAPI backend + static website.

Run:  python -m uvicorn backend.app:app --reload
Open: http://127.0.0.1:8000

Set THREATLENS_MULTI_USER=1 when deployed publicly (per-visitor sessions + rate limits).
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.config import ROOT

load_dotenv(ROOT / ".env")

from backend import llm  # noqa: E402  (needs env loaded first)
from backend.detector import FlowDetector  # noqa: E402
from backend.knowledge import KnowledgeBase  # noqa: E402
from backend.live import SCENARIOS, LiveMonitor  # noqa: E402
from backend.sessions import (  # noqa: E402
    COOKIE, HEADER, LOCAL_SID, MULTI_USER, RateLimiter, SessionStore, new_sid, valid_sid,
)
from backend.url_checker import UrlChecker  # noqa: E402

FRONTEND_DIR = ROOT / "frontend"
SAMPLES_DIR = ROOT / "data" / "samples"
TEST_UPLOADS_DIR = ROOT / "data" / "test_uploads"
TEST_UPLOAD_NOTES = {
    "01": "Normal office day · no labels",
    "02": "Hidden attacks · no labels",
    "03": "Full day, 15k flows · labelled (shows accuracy)",
    "04": "Attack types never seen in training",
    "05": "Wrong format · shows validation error",
}
MAX_UPLOAD_MB = int(os.getenv("THREATLENS_MAX_UPLOAD_MB", "25"))
SSE_HEADERS = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}

kb = KnowledgeBase()
detector = FlowDetector(kb)
url_checker = UrlChecker(kb)
live_monitor = LiveMonitor(detector, kb)
sessions = SessionStore()

# Limits apply only when deployed (MULTI_USER). Keyed by client IP so clearing
# cookies doesn't reset them; generous enough for a class sharing one network.
limits = {
    "chat": RateLimiter(30, 600),
    "chat_global": RateLimiter(300, 3600),  # protects the free LLM quota as a whole
    "url": RateLimiter(60, 60),
    "flows": RateLimiter(20, 60),
    "live": RateLimiter(10, 600),
}

app = FastAPI(title="ThreatLens - AI Threat Detection & Security Assessment")


# ---------- sessions & limits ----------
@app.middleware("http")
async def session_middleware(request: Request, call_next):
    sid = request.headers.get(HEADER) or request.cookies.get(COOKIE)
    created = None
    if not MULTI_USER:
        sid = LOCAL_SID
    elif not valid_sid(sid):
        sid = created = new_sid()
    request.state.sid = sid
    response = await call_next(request)
    if created and not request.headers.get(HEADER):
        https = request.headers.get("x-forwarded-proto", request.url.scheme) == "https"
        # SameSite=None lets the cookie work inside the Hugging Face page iframe too.
        response.set_cookie(COOKIE, created, max_age=30 * 86400, httponly=True,
                            samesite="none" if https else "lax", secure=https)
    return response


def session(request: Request):
    return sessions.get(request.state.sid)


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")


def rate_limit(request: Request, *names: str):
    ip = client_ip(request)
    for name in names:
        key = "all" if name.endswith("_global") else ip
        if not limits[name].allow(key):
            raise HTTPException(429, "Too many requests - please wait a few minutes and try again.")


def find_analysis(request: Request, analysis_id: str) -> dict:
    a = session(request).history.get(analysis_id)
    if not a:
        raise HTTPException(404, "Analysis not found")
    return a


# ---------- API ----------
@app.get("/api/status")
def status(request: Request):
    return {
        "flow_model": detector.model_name,
        "flow_classes": detector.classes,
        "knowledge_chunks": len(kb.chunks),
        "llm": llm.status(),
        "analyses": len(session(request).history),
        "multi_user": MULTI_USER,
        # the visitor's own id, shown as the extension pairing code when deployed
        "session": request.state.sid if MULTI_USER else None,
    }


@app.post("/api/analyze/flows")
def analyze_flows(request: Request, file: UploadFile = File(...)):
    rate_limit(request, "flows")
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(400, "Please upload a .csv file of network flows")
    file.file.seek(0, 2)
    if file.file.tell() > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(413, f"File too large - the limit is {MAX_UPLOAD_MB} MB")
    file.file.seek(0)
    try:
        return session(request).remember(detector.analyze(file.file, file.filename))
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/api/samples")
def list_samples():
    return sorted(p.name for p in SAMPLES_DIR.glob("*.csv")) if SAMPLES_DIR.exists() else []


@app.get("/api/test-uploads")
def list_test_uploads():
    if not TEST_UPLOADS_DIR.exists():
        return []
    return [{"name": p.name, "note": TEST_UPLOAD_NOTES.get(p.name[:2], ""),
             "size_mb": round(p.stat().st_size / 2**20, 1), "url": f"/downloads/{p.name}"}
            for p in sorted(TEST_UPLOADS_DIR.glob("*.csv"))]


@app.post("/api/analyze/sample/{name}")
def analyze_sample(request: Request, name: str):
    rate_limit(request, "flows")
    path = SAMPLES_DIR / Path(name).name  # Path().name blocks ../ traversal
    if not path.is_file():
        raise HTTPException(404, "Sample not found")
    with path.open("rb") as f:
        return session(request).remember(detector.analyze(f, path.name))


@app.get("/api/live/scenarios")
def live_scenarios():
    return [{"id": k, "title": v["title"], "seconds": sum(p[0] for p in v["phases"])} for k, v in SCENARIOS.items()]


@app.get("/api/live/stream")
def live_stream(request: Request, scenario: str = "timeline", speed: float = 1.0):
    """Server-Sent Events: one 'tick' event per simulated second, then 'done' with
    the id of a full analysis of everything streamed (so reports and chat work on it)."""
    rate_limit(request, "live")
    s = session(request)
    on_finish = lambda df, name: s.remember(detector.analyze_df(df, name))  # noqa: E731
    return StreamingResponse(live_monitor.stream(scenario, speed, on_finish),
                             media_type="text/event-stream", headers=SSE_HEADERS)


class UrlRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)
    live: bool = True
    save: bool = True  # the browser extension's automatic checks pass False to keep history clean
    source: str | None = None  # "extension" = a page navigation, shown on the live browsing dashboard
    block: bool = False  # whether the extension will show its warning page for dangerous results


@app.post("/api/analyze/url")
def analyze_url(request: Request, req: UrlRequest):
    if req.live:  # quick model-only checks from the extension are not limited
        rate_limit(request, "url")
    s = session(request)
    result = url_checker.check(req.url, live=req.live)
    if req.source == "extension":
        s.browsing.add(result, blocked=req.block)
    return s.remember(result) if req.save else result


@app.get("/api/browsing/stream")
def browsing_stream(request: Request):
    """Server-Sent Events: 'init' with recent events, then one 'event' per site visited."""
    return StreamingResponse(session(request).browsing.stream(), media_type="text/event-stream", headers=SSE_HEADERS)


@app.delete("/api/browsing")
def browsing_clear(request: Request):
    session(request).browsing.clear()
    return {"cleared": True}


@app.get("/api/history")
def list_history(request: Request):
    out = []
    for a in reversed(session(request).history.values()):
        out.append({
            "id": a["id"], "type": a["type"], "analyzed_at": a["analyzed_at"],
            "name": a.get("filename") or a.get("url"), "status": a["status"],
            "score": a["score"]["value"], "threats": a.get("threats_detected", int(bool(a.get("threat")))),
        })
    return out


@app.get("/api/analysis/{analysis_id}")
def get_analysis(request: Request, analysis_id: str):
    return find_analysis(request, analysis_id)


@app.get("/api/analysis/{analysis_id}/report.pdf")
def analysis_pdf(request: Request, analysis_id: str):
    from backend.report_pdf import build_pdf  # lazy: matplotlib costs ~25 MB RAM, load it only when needed
    pdf = build_pdf(find_analysis(request, analysis_id), kb.mitre_names())
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="threatlens-report-{analysis_id}.pdf"'})


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
    content: str = Field(max_length=4000)


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
def chat(request: Request, req: ChatRequest):
    rate_limit(request, "chat", "chat_global")
    analysis = session(request).history.get(req.analysis_id) if req.analysis_id else None
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
if TEST_UPLOADS_DIR.exists():
    app.mount("/downloads", StaticFiles(directory=TEST_UPLOADS_DIR), name="downloads")


@app.get("/")
def landing():
    return FileResponse(FRONTEND_DIR / "landing.html")


APP_PAGES = {"dashboard", "live", "browsing", "traffic", "website", "history", "how-it-works", "about"}


@app.get("/app")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/app/{page}")
def app_page(page: str):
    """Each feature has its own URL; the single-page app picks the view from the path."""
    if page not in APP_PAGES:
        raise HTTPException(404, "Page not found")
    return FileResponse(FRONTEND_DIR / "index.html")
