"""Live browsing activity: sites checked by the browser extension, pushed to the
website over Server-Sent Events. Kept in memory only (never written to disk) -
browsing history is sensitive, so it disappears when the server restarts."""
import asyncio
import json
import threading
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

MAX_EVENTS = 500
DEDUPE_SECONDS = 3
KEEPALIVE_SECONDS = 15
POLL_SECONDS = 0.5


def _sse(event: str, data) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


class BrowsingLog:
    def __init__(self):
        self.events = deque(maxlen=MAX_EVENTS)
        self._lock = threading.Lock()
        self.seq = 0
        self.epoch = 0  # bumps on clear so connected dashboards reset
        self._last_seen = {}  # url -> timestamp, for de-duplication

    def add(self, result: dict, blocked: bool):
        now = datetime.now().astimezone()  # timezone-aware: browsers show local time even on a UTC server
        url = result["url"]
        m = result["model"]
        host = urlparse(url if "://" in url else "http://" + url).hostname or url
        with self._lock:
            last = self._last_seen.get(url)
            if last and (now - last).total_seconds() < DEDUPE_SECONDS:
                return
            self._last_seen[url] = now
            if len(self._last_seen) > MAX_EVENTS * 2:
                self._last_seen.clear()
            self.seq += 1
            self.events.append({
                "seq": self.seq, "time": now.isoformat(timespec="seconds"), "url": url[:300], "host": host,
                "level": result["status"]["level"], "headline": result["status"]["headline"],
                "label": m["label"], "confidence": m["confidence"], "trusted": m["reputation"]["matched"],
                "blocked": bool(blocked and result["status"]["level"] == "danger"),
                "flag": (m["red_flags"] or [""])[0],
            })

    def clear(self):
        with self._lock:
            self.events.clear()
            self._last_seen.clear()
            self.epoch += 1

    async def stream(self):
        """Async generator, so open dashboards don't each hold a server thread."""
        last, epoch = self.seq, self.epoch
        yield _sse("init", {"events": list(self.events)})
        idle = 0.0
        while True:
            await asyncio.sleep(POLL_SECONDS)
            if self.epoch != epoch:
                last, epoch, idle = self.seq, self.epoch, 0.0
                yield _sse("clear", {})
            elif self.seq != last:
                new = [e for e in list(self.events) if e["seq"] > last]
                last, idle = self.seq, 0.0
                for e in new:
                    yield _sse("event", e)
            else:
                idle += POLL_SECONDS
                if idle >= KEEPALIVE_SECONDS:
                    idle = 0.0
                    yield ": keepalive\n\n"
