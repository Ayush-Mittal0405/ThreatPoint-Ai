"""
Agent enrollment.

Exchanges a one-time enrollment token for a permanent agent identity + per-agent
credential, then persists them to the secure state store. Idempotent: if the
agent is already enrolled, enrollment is skipped.
"""
from __future__ import annotations

import platform
import socket
from datetime import datetime, timezone
from typing import Optional

from . import __version__
from .config import Config
from .state import AgentState, StateStore
from .transport import Transport, AgentCredentials


def _host_metadata(config: Config) -> dict:
    system = platform.system().lower()  # 'windows' | 'linux' | 'darwin'
    os_name = {"darwin": "macos"}.get(system, system)
    meta = {
        "hostname": socket.gethostname(),
        "operating_system": os_name,
        "os_version": platform.version(),
        "agent_version": __version__,
    }
    if config.agent.report_username:
        try:
            import getpass
            meta["username"] = getpass.getuser()
        except Exception:
            pass
    return meta


def ensure_enrolled(config: Config, store: StateStore, transport: Transport, logger) -> AgentCredentials:
    """Return valid credentials, enrolling first if necessary."""
    state = store.load()
    if state.enrolled:
        logger.info("Already enrolled as %s", state.agent_id)
        return AgentCredentials(agent_id=state.agent_id, agent_token=state.agent_token)

    if not config.enrollment_token:
        raise RuntimeError(
            "Agent is not enrolled and no enrollment token was provided. "
            "Set enrollment.token in the config or AEGISX_AGENT_ENROLLMENT_TOKEN."
        )

    body = {"enrollment_token": config.enrollment_token, **_host_metadata(config)}
    logger.info("Enrolling with server %s as host %s", config.server.url, body["hostname"])
    resp = transport.enroll(body)

    agent_id = resp["agent_id"]
    agent_token = resp["agent_token"]
    store.save(AgentState(
        agent_id=agent_id,
        agent_token=agent_token,
        enrolled_at=datetime.now(timezone.utc).isoformat(),
        server_url=config.server.url,
    ))
    # Enrollment token is single-use server-side; drop our in-memory copy.
    config.enrollment_token = None
    logger.info("Enrollment successful — assigned agent id %s", agent_id)
    return AgentCredentials(agent_id=agent_id, agent_token=agent_token)
