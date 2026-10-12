"""
Client-side event normalization.

Collectors emit loosely-shaped dicts; this module coerces them into the exact
schema the server's /api/v1/endpoints/events API accepts (AgentEventIn), so the
server can normalize once more into its internal NormalizedEvent model.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

CANONICAL_EVENT_TYPES = {
    "process_creation",
    "process_termination",
    "network_connection",
    "dns_query",
    "authentication",
    "user_account_change",
    "file_event",
    "persistence",
    "eventlog",
}

_ALLOWED_FIELDS = {
    "event_type", "timestamp", "severity", "host", "user", "process",
    "parent_process", "command_line", "file_path", "hash_md5", "hash_sha256",
    "src_ip", "dst_ip", "dst_port", "domain", "raw",
}


def _iso(ts: Any) -> str:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.isoformat()
    if isinstance(ts, str) and ts:
        return ts
    return datetime.now(timezone.utc).isoformat()


def normalize_event(raw: Dict[str, Any], *, default_host: Optional[str] = None) -> Dict[str, Any]:
    """Return a server-ready event dict. Unknown keys are moved into `raw`."""
    out: Dict[str, Any] = {}
    extra: Dict[str, Any] = dict(raw.get("raw") or {})

    for k, v in raw.items():
        if k == "raw":
            continue
        if k in _ALLOWED_FIELDS:
            out[k] = v
        else:
            extra[k] = v

    out["event_type"] = str(out.get("event_type", "eventlog")).lower().strip()
    out["timestamp"] = _iso(out.get("timestamp"))
    out.setdefault("severity", "info")
    if not out.get("host") and default_host:
        out["host"] = default_host
    if extra:
        out["raw"] = extra

    # dst_port must be an int if present
    if out.get("dst_port") is not None:
        try:
            out["dst_port"] = int(out["dst_port"])
        except (TypeError, ValueError):
            out["dst_port"] = None
    return out
