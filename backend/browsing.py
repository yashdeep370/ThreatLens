"""Live browsing activity: sites checked by the browser extension, pushed to the
website over Server-Sent Events. Kept in memory only (never written to disk) -
browsing history is sensitive, so it disappears when the server restarts."""
import json
import threading
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

MAX_EVENTS = 500
DEDUPE_SECONDS = 3
KEEPALIVE_SECONDS = 15


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


class BrowsingLog:
    def __init__(self):
        self.events = deque(maxlen=MAX_EVENTS)
        self.cond = threading.Condition()
        self.seq = 0
        self.epoch = 0  # bumps on clear so connected dashboards reset
        self._last_seen = {}  # url -> timestamp, for de-duplication

    def add(self, result: dict, blocked: bool):
        now = datetime.now()
        url = result["url"]
        last = self._last_seen.get(url)
        if last and (now - last).total_seconds() < DEDUPE_SECONDS:
            return
        self._last_seen[url] = now
        if len(self._last_seen) > MAX_EVENTS * 2:
            self._last_seen.clear()
        m = result["model"]
        host = urlparse(url if "://" in url else "http://" + url).hostname or url
        with self.cond:
            self.seq += 1
            self.events.append({
                # timezone-aware, so browsers show local time even if the server runs on UTC
                "seq": self.seq, "time": now.astimezone().isoformat(timespec="seconds"), "url": url[:300], "host": host,
                "level": result["status"]["level"], "headline": result["status"]["headline"],
                "label": m["label"], "confidence": m["confidence"], "trusted": m["reputation"]["matched"],
                "blocked": bool(blocked and result["status"]["level"] == "danger"),
                "flag": (m["red_flags"] or [""])[0],
            })
            self.cond.notify_all()

    def clear(self):
        with self.cond:
            self.events.clear()
            self._last_seen.clear()
            self.epoch += 1
            self.cond.notify_all()

    def stream(self):
        with self.cond:
            last, epoch = self.seq, self.epoch
            snapshot = list(self.events)
        yield _sse("init", {"events": snapshot})
        while True:
            with self.cond:
                self.cond.wait_for(lambda: self.seq != last or self.epoch != epoch, timeout=KEEPALIVE_SECONDS)
                cleared = self.epoch != epoch
                new = [] if cleared else [e for e in self.events if e["seq"] > last]
                last, epoch = self.seq, self.epoch
            if cleared:
                yield _sse("clear", {})
            for e in new:
                yield _sse("event", e)
            if not new and not cleared:
                yield ": keepalive\n\n"
