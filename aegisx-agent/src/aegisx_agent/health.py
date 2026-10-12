"""
Agent self-health metrics for heartbeats.

Reports the agent process's own CPU/memory footprint so the SOC can verify the
agent stays lightweight, plus the current offline-buffer depth.
"""
from __future__ import annotations

import os
from typing import Optional

try:
    import psutil  # type: ignore
    _PROC = psutil.Process(os.getpid())
    _HAVE_PSUTIL = True
    _PROC.cpu_percent(None)  # prime the CPU meter
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False
    _PROC = None


def self_cpu_percent() -> Optional[float]:
    if not _HAVE_PSUTIL:
        return None
    try:
        return round(_PROC.cpu_percent(None), 1)
    except Exception:  # pragma: no cover
        return None


def self_memory_percent() -> Optional[float]:
    if not _HAVE_PSUTIL:
        return None
    try:
        return round(_PROC.memory_percent(), 1)
    except Exception:  # pragma: no cover
        return None
