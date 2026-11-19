"""Per-visitor isolation and rate limiting for public deployment.

Local use (default): one shared session, history saved to data/history.json.
Deployed (THREATLENS_MULTI_USER=1): every visitor gets a random session id
(cookie), with their own in-memory history and browsing feed. The browser
extension joins a session by sending the same id as a pairing code
(X-ThreatLens-Session header).
"""
import json
import os
import re
import secrets
import threading
import time
from collections import OrderedDict, deque

from backend.browsing import BrowsingLog
from src.config import ROOT

MULTI_USER = os.getenv("THREATLENS_MULTI_USER") == "1"
COOKIE = "tl_sid"
HEADER = "x-threatlens-session"
LOCAL_SID = "local"
SID_RE = re.compile(r"^[A-Za-z0-9_-]{8,32}$")
MAX_SESSIONS = 300
MAX_HISTORY = 50
HISTORY_PATH = ROOT / "data" / "history.json"


def new_sid() -> str:
    return secrets.token_urlsafe(9)  # 12 chars, ~72 bits


def valid_sid(sid: str | None) -> bool:
    return bool(sid and SID_RE.fullmatch(sid))


class Session:
    def __init__(self, persist: bool):
        self.persist = persist
        self.history: OrderedDict = OrderedDict()
        self.browsing = BrowsingLog()
        if persist:
            try:
                self.history = OrderedDict((a["id"], a) for a in json.loads(HISTORY_PATH.read_text(encoding="utf-8")))
            except Exception:
                pass

    def remember(self, analysis: dict) -> dict:
        self.history[analysis["id"]] = analysis
        while len(self.history) > MAX_HISTORY:
            self.history.popitem(last=False)
        if self.persist:
            HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
            HISTORY_PATH.write_text(json.dumps(list(self.history.values())), encoding="utf-8")
        return analysis


class SessionStore:
    def __init__(self):
        self._sessions: OrderedDict[str, Session] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, sid: str) -> Session:
        with self._lock:
            if sid not in self._sessions:
                self._sessions[sid] = Session(persist=not MULTI_USER)
                while len(self._sessions) > MAX_SESSIONS:  # forget least recently used visitors
                    self._sessions.popitem(last=False)
            self._sessions.move_to_end(sid)
            return self._sessions[sid]


class RateLimiter:
    """Sliding-window limit per key. Only enforced when deployed."""

    def __init__(self, limit: int, window_seconds: int):
        self.limit, self.window = limit, window_seconds
        self.hits: dict[str, deque] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        if not MULTI_USER:
            return True
        now = time.monotonic()
        with self._lock:
            q = self.hits.setdefault(key, deque())
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.limit:
                return False
            q.append(now)
            if len(self.hits) > MAX_SESSIONS * 4:
                self.hits = {k: v for k, v in self.hits.items() if v and now - v[-1] < self.window}
            return True
