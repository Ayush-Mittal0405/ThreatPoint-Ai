"""
Endpoint-agent service helpers.

Pure, dependency-light functions for agent identity, credential hashing,
online/offline status computation, and mapping agent telemetry onto the
existing NormalizedEvent pipeline. Kept free of DB/session state so they can
be unit-tested in isolation (matching the project's testing conventions).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional


# ─── Identity & credentials ───────────────────────────────────────────────────

def generate_agent_id() -> str:
    """Opaque, collision-resistant public identity, e.g. 'AGT-8F32A91C'.

    Deliberately independent of hostname so machines with similar names stay
    distinguishable.
    """
    return f"AGT-{secrets.token_hex(4).upper()}"


def generate_secret_token(nbytes: int = 32) -> str:
    """Generate a high-entropy URL-safe secret (enrollment or agent credential)."""
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """SHA-256 hex digest. Only the hash is ever persisted or compared."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_token(token: str, token_hash: str) -> bool:
    """Constant-time comparison of a presented token against a stored hash."""
    if not token or not token_hash:
        return False
    return secrets.compare_digest(hash_token(token), token_hash)


# ─── Status computation ───────────────────────────────────────────────────────

def compute_status(
    last_seen: datetime,
    *,
    now: Optional[datetime] = None,
    warning_after_s: int,
    offline_after_s: int,
    health: str = "healthy",
    revoked: bool = False,
) -> str:
    """Derive an endpoint's presence status from its last heartbeat.

    Returns one of: online | warning | offline | unhealthy | revoked.
    A configurable timeout is used rather than any hard-coded assumption.
    """
    if revoked:
        return "revoked"
    now = now or datetime.now(timezone.utc)
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    age = (now - last_seen).total_seconds()

    if age >= offline_after_s:
        return "offline"
    if health == "unhealthy":
        return "unhealthy"
    if age >= warning_after_s or health == "warning":
        return "warning"
    return "online"


def is_enrollment_token_valid(
    *,
    revoked: bool,
    used_count: int,
    max_uses: int,
    expires_at: datetime,
    now: Optional[datetime] = None,
) -> bool:
    """Validate an enrollment token's usability (not revoked, unexpired, uses left)."""
    now = now or datetime.now(timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if revoked:
        return False
    if now >= expires_at:
        return False
    if used_count >= max_uses:
        return False
    return True


# ─── Telemetry mapping ────────────────────────────────────────────────────────

# Canonical event types understood by the detection engine. Agents SHOULD emit
# these; anything else is still stored but is unlikely to trigger a rule.
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

AGENT_SOURCE = "aegisx-agent"


def agent_event_to_raw_dict(event, agent_id: str) -> dict:
    """Map an AgentEventIn (or dict) to the RawEventIn shape used by the
    normalization pipeline, tagging it with the originating agent_id.
    """
    get = (event.get if isinstance(event, dict) else lambda k, d=None: getattr(event, k, d))
    return {
        "source": AGENT_SOURCE,
        "event_type": (get("event_type") or "").lower().strip(),
        "timestamp": get("timestamp"),
        "agent_id": agent_id,
        "host": get("host"),
        "user": get("user"),
        "process": get("process"),
        "parent_process": get("parent_process"),
        "command_line": get("command_line"),
        "file_path": get("file_path"),
        "hash_md5": get("hash_md5"),
        "hash_sha256": get("hash_sha256"),
        "src_ip": get("src_ip"),
        "dst_ip": get("dst_ip"),
        "dst_port": get("dst_port"),
        "domain": get("domain"),
        "raw": get("raw"),
    }
