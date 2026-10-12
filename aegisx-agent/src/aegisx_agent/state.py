"""
Secure agent state store.

Persists the agent identity and per-agent credential returned at enrollment.
The credential is a secret: it is stored with owner-only permissions where the
platform supports it, and is never emitted to logs.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class AgentState:
    agent_id: Optional[str] = None
    agent_token: Optional[str] = None      # secret credential — do not log
    enrolled_at: Optional[str] = None
    server_url: Optional[str] = None

    @property
    def enrolled(self) -> bool:
        return bool(self.agent_id and self.agent_token)


class StateStore:
    """Read/write the agent state file (JSON) under the state directory."""

    FILENAME = "agent_state.json"

    def __init__(self, state_dir: str):
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / self.FILENAME

    def load(self) -> AgentState:
        if not self.path.is_file():
            return AgentState()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return AgentState()
        return AgentState(
            agent_id=data.get("agent_id"),
            agent_token=data.get("agent_token"),
            enrolled_at=data.get("enrolled_at"),
            server_url=data.get("server_url"),
        )

    def save(self, state: AgentState) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "agent_id": state.agent_id,
            "agent_token": state.agent_token,
            "enrolled_at": state.enrolled_at,
            "server_url": state.server_url,
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)
        self._restrict_permissions()

    def _restrict_permissions(self) -> None:
        """Owner-only read/write. On POSIX chmod 600; on Windows rely on the
        ProgramData ACL and document tightening in the install guide."""
        try:
            if os.name != "nt":
                os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:  # pragma: no cover
            pass

    def clear(self) -> None:
        try:
            self.path.unlink(missing_ok=True)  # type: ignore[call-arg]
        except OSError:  # pragma: no cover
            pass
