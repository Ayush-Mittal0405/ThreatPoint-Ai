"""
Agent configuration loading.

Precedence (highest first):
  1. Environment variables (AEGISX_AGENT_*)
  2. YAML config file
  3. Built-in defaults

Secrets (enrollment token) may be supplied via env or the config file but are
never written back to the config file. The per-agent credential lives in the
separate state store (see state.py), not here.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False


def _default_state_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return str(Path(base) / "AegisX" / "agent")
    return str(Path.home() / ".aegisx-agent")


@dataclass
class ServerConfig:
    url: str = "https://localhost:8008"
    verify_tls: bool = True
    ca_cert: Optional[str] = None          # path to CA bundle for self-signed servers
    timeout_seconds: float = 15.0


@dataclass
class AgentTuning:
    heartbeat_interval_seconds: int = 2
    collect_interval_seconds: int = 1
    flush_interval_seconds: int = 1
    batch_size: int = 100
    buffer_max_events: int = 10_000       # bounded queue — disk cannot grow without limit
    report_username: bool = False          # privacy: only send username if explicitly enabled
    max_backoff_seconds: float = 300.0


@dataclass
class CollectorToggles:
    process: bool = True
    network: bool = True
    authentication: bool = True            # Windows Security logon events
    persistence: bool = True
    eventlog: bool = True


@dataclass
class Config:
    server: ServerConfig = field(default_factory=ServerConfig)
    agent: AgentTuning = field(default_factory=AgentTuning)
    collectors: CollectorToggles = field(default_factory=CollectorToggles)
    state_dir: str = field(default_factory=_default_state_dir)
    enrollment_token: Optional[str] = None

    # ── Construction ──────────────────────────────────────────────────────────

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Config":
        data = data or {}
        server = ServerConfig(**{**asdict(ServerConfig()), **(data.get("server") or {})})
        agent = AgentTuning(**{**asdict(AgentTuning()), **(data.get("agent") or {})})
        collectors = CollectorToggles(**{**asdict(CollectorToggles()), **(data.get("collectors") or {})})
        return cls(
            server=server,
            agent=agent,
            collectors=collectors,
            state_dir=data.get("state_dir") or _default_state_dir(),
            enrollment_token=(data.get("enrollment") or {}).get("token") or data.get("enrollment_token"),
        )

    @classmethod
    def load(cls, path: Optional[str] = None) -> "Config":
        """Load from YAML file (if present) then overlay environment variables."""
        data: Dict[str, Any] = {}
        if path and Path(path).is_file():
            raw = Path(path).read_text(encoding="utf-8")
            if _HAVE_YAML:
                data = yaml.safe_load(raw) or {}
            else:  # pragma: no cover - yaml is a declared dependency
                raise RuntimeError("PyYAML is required to read the agent config file")
        cfg = cls.from_dict(data)
        cfg._apply_env()
        return cfg

    def _apply_env(self) -> None:
        """Environment overrides — useful for containers / CI / secret injection."""
        env = os.environ
        if v := env.get("AEGISX_AGENT_SERVER_URL"):
            self.server.url = v
        if v := env.get("AEGISX_AGENT_CA_CERT"):
            self.server.ca_cert = v
        if (v := env.get("AEGISX_AGENT_VERIFY_TLS")) is not None:
            self.server.verify_tls = v.strip().lower() not in ("0", "false", "no")
        if v := env.get("AEGISX_AGENT_ENROLLMENT_TOKEN"):
            self.enrollment_token = v
        if v := env.get("AEGISX_AGENT_STATE_DIR"):
            self.state_dir = v
        if v := env.get("AEGISX_AGENT_HEARTBEAT_INTERVAL"):
            try:
                self.agent.heartbeat_interval_seconds = int(v)
            except ValueError:
                pass

    # ── Validation ────────────────────────────────────────────────────────────

    def validate(self) -> None:
        if not self.server.url or not self.server.url.startswith(("http://", "https://")):
            raise ValueError("server.url must be an http(s) URL")
        if self.server.url.startswith("http://") and "localhost" not in self.server.url \
                and "127.0.0.1" not in self.server.url:
            # Not fatal, but the agent must not ship telemetry in cleartext in prod.
            raise ValueError("Refusing to use plain HTTP to a non-local server; use HTTPS")
        if self.agent.batch_size < 1:
            raise ValueError("agent.batch_size must be >= 1")
        if self.agent.buffer_max_events < self.agent.batch_size:
            raise ValueError("agent.buffer_max_events must be >= batch_size")
