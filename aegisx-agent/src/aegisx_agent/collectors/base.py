"""
Collector base class.

A collector is polled periodically and returns a list of loosely-shaped event
dicts. It must be:
  - lightweight (event-driven or cheap snapshot diffing, never full disk/packet scans);
  - fail-safe (a collector error must not crash the agent);
  - stateless across restarts beyond what it explicitly tracks.
"""
from __future__ import annotations

from typing import Any, Dict, List


class Collector:
    name: str = "base"
    #: True only on platforms the collector supports; unsupported ones no-op.
    supported: bool = True

    def __init__(self, logger=None):
        self.log = logger

    def collect(self) -> List[Dict[str, Any]]:
        """Return new events since the last poll. Override in subclasses."""
        return []

    def safe_collect(self) -> List[Dict[str, Any]]:
        """Collect without ever propagating an exception to the agent loop."""
        if not self.supported:
            return []
        try:
            return self.collect()
        except Exception as exc:  # pragma: no cover - defensive
            if self.log:
                self.log.warning("collector %s failed: %s", self.name, exc)
            return []
