"""
Persistence collector (Windows) — emits `persistence` events when a new autorun
entry appears. Monitors registry Run/RunOnce keys and scheduled tasks by
snapshot diffing, so only *newly added* persistence is reported (the
security-relevant signal), not the existing baseline. Read-only. Windows-only.
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from .base import Collector

_IS_WINDOWS = os.name == "nt"

if _IS_WINDOWS:
    import winreg  # type: ignore

# (hive, subkey, human label)
_RUN_KEYS = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
]


class PersistenceCollector(Collector):
    name = "persistence"
    supported = _IS_WINDOWS

    def __init__(self, logger=None, include_scheduled_tasks: bool = True):
        super().__init__(logger)
        self.include_scheduled_tasks = include_scheduled_tasks
        self._seen: Set[Tuple[str, str]] = set()
        self._primed = False

    def collect(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        current: Set[Tuple[str, str]] = set()

        for entry, event in self._registry_autoruns():
            current.add(entry)
            if entry not in self._seen and self._primed:
                events.append(event)

        if self.include_scheduled_tasks:
            for entry, event in self._scheduled_tasks():
                current.add(entry)
                if entry not in self._seen and self._primed:
                    events.append(event)

        self._seen = current
        self._primed = True
        return events

    # ── Registry autoruns ─────────────────────────────────────────────────────

    def _registry_autoruns(self):
        for hive_name, subkey, label in _RUN_KEYS:
            hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
            try:
                key = winreg.OpenKey(hive, subkey)
            except OSError:
                continue
            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    entry = (f"reg:{label}:{name}", str(value))
                    yield entry, {
                        "event_type": "persistence",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "severity": "warning",
                        "process": name,
                        "file_path": str(value),
                        "raw": {"mechanism": "registry_run_key", "location": label, "value_name": name},
                    }
            finally:
                winreg.CloseKey(key)

    # ── Scheduled tasks ───────────────────────────────────────────────────────

    def _scheduled_tasks(self):
        try:
            out = subprocess.run(
                ["schtasks", "/query", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return
        if out.returncode != 0:
            return
        for line in out.stdout.splitlines():
            parts = [p.strip('"') for p in line.split('","')]
            if not parts:
                continue
            task_name = parts[0].strip('"').strip()
            if not task_name or task_name.lower() == "taskname":
                continue
            entry = (f"task:{task_name}", task_name)
            yield entry, {
                "event_type": "persistence",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "warning",
                "file_path": task_name,
                "raw": {"mechanism": "scheduled_task", "task_name": task_name},
            }
