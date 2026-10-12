"""
Bounded, disk-backed event buffer.

If the server is unavailable, collected events are held here and retried later.
The queue is bounded (`max_events`) so disk usage cannot grow without limit —
when full, the oldest events are dropped (a dropped-count is tracked so the loss
is observable). Backed by an append-friendly JSONL file that is rewritten on
flush; thread-safe for the agent's collector/flush threads.
"""
from __future__ import annotations

import json
import os
import threading
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional


class EventBuffer:
    def __init__(self, path: str, max_events: int = 10_000):
        self.path = Path(path)
        self.max_events = max_events
        self._q: Deque[Dict[str, Any]] = deque(maxlen=max_events)
        self._lock = threading.RLock()
        self.dropped_total = 0
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        self._q.append(json.loads(line))
        except (json.JSONDecodeError, OSError):
            # Corrupt buffer file — start clean rather than crash-loop.
            self._q.clear()

    def persist(self) -> None:
        """Rewrite the buffer file to reflect the current queue contents."""
        with self._lock:
            items = list(self._q)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                for item in items:
                    fh.write(json.dumps(item, default=str) + "\n")
            os.replace(tmp, self.path)
        except OSError:
            pass

    # ── Queue operations ──────────────────────────────────────────────────────

    def enqueue(self, event: Dict[str, Any]) -> None:
        with self._lock:
            if len(self._q) >= self.max_events:
                self.dropped_total += 1  # deque(maxlen) will evict the oldest
            self._q.append(event)

    def enqueue_many(self, events: List[Dict[str, Any]]) -> None:
        for e in events:
            self.enqueue(e)

    def peek_batch(self, n: int) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._q)[:n]

    def commit(self, n: int) -> None:
        """Remove the first n events (call after they were sent successfully)."""
        with self._lock:
            for _ in range(min(n, len(self._q))):
                self._q.popleft()

    def __len__(self) -> int:
        with self._lock:
            return len(self._q)

    @property
    def size(self) -> int:
        return len(self)
