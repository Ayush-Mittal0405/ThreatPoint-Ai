"""
Process collector — emits `process_creation` events for newly-seen processes.

Uses psutil snapshot diffing (event-driven ETW is a future enhancement). Captures
name, executable path, PID, parent PID/name, and — when permitted by config —
the command line. Never captures process memory or arguments containing obvious
secrets beyond the raw command line the OS already exposes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Set

from .base import Collector

try:
    import psutil  # type: ignore
    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False


class ProcessCollector(Collector):
    name = "process"
    supported = _HAVE_PSUTIL

    def __init__(self, logger=None, include_command_line: bool = True):
        super().__init__(logger)
        self.include_command_line = include_command_line
        self._seen: Set[int] = set()
        self._primed = False

    def collect(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        current: Set[int] = set()

        for proc in psutil.process_iter(["pid", "name", "ppid", "exe", "cmdline", "username", "create_time"]):
            try:
                info = proc.info
                pid = info["pid"]
                current.add(pid)
                if pid in self._seen:
                    continue
                # First pass primes the baseline without flooding the server.
                if not self._primed:
                    continue

                parent_name = None
                try:
                    parent_name = psutil.Process(info["ppid"]).name() if info.get("ppid") else None
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    parent_name = None

                cmdline = None
                if self.include_command_line and info.get("cmdline"):
                    cmdline = " ".join(info["cmdline"])

                events.append({
                    "event_type": "process_creation",
                    "timestamp": datetime.fromtimestamp(
                        info.get("create_time") or 0, tz=timezone.utc
                    ).isoformat(),
                    "process": info.get("name"),
                    "parent_process": parent_name,
                    "file_path": info.get("exe"),
                    "command_line": cmdline,
                    "user": info.get("username"),
                    "raw": {"pid": pid, "ppid": info.get("ppid")},
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._seen = current
        self._primed = True
        return events
