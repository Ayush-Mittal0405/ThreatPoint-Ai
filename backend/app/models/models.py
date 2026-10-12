"""
SQLAlchemy ORM models for AegisX telemetry, alerts, and incidents.
All tables are co-located here for Phase 0/1; split by domain in later phases.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    BigInteger, Boolean, DateTime, Float, ForeignKey,
    Integer, String, Text, JSON, Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─── Telemetry ────────────────────────────────────────────────────────────────

class NormalizedEvent(Base):
    """Normalized security event (endpoint, network, identity, etc.)."""
    __tablename__ = "normalized_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)  # sysmon, zeek, etc.
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # Endpoint agent that produced this event (nullable — legacy/server-side
    # collectors do not set it). Distinct from hostname so machines with similar
    # names remain distinguishable.
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    host: Mapped[Optional[str]] = mapped_column(String(256))
    user: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    process: Mapped[Optional[str]] = mapped_column(String(256))
    parent_process: Mapped[Optional[str]] = mapped_column(String(256))
    command_line: Mapped[Optional[str]] = mapped_column(Text)
    file_path: Mapped[Optional[str]] = mapped_column(Text)
    hash_md5: Mapped[Optional[str]] = mapped_column(String(32))
    hash_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    src_ip: Mapped[Optional[str]] = mapped_column(String(45))
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45))
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)
    domain: Mapped[Optional[str]] = mapped_column(String(512))
    raw: Mapped[Optional[dict]] = mapped_column(JSON)  # original event

    # Relationships
    alerts: Mapped[list["Alert"]] = relationship("Alert", secondary="alert_events", back_populates="events")


# ─── Detection ────────────────────────────────────────────────────────────────

class DetectionRule(Base):
    """Detection rule metadata."""
    __tablename__ = "detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(256), nullable=False, unique=True)
    rule_type: Mapped[str] = mapped_column(String(32), nullable=False)  # sigma, yara, behavioral, ioc
    severity: Mapped[str] = mapped_column(String(16), nullable=False)   # informational|low|medium|high|critical
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON)      # ["T1059.001", ...]
    description: Mapped[Optional[str]] = mapped_column(Text)
    rule_content: Mapped[Optional[str]] = mapped_column(Text)           # raw Sigma/YARA/etc.
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── Alerts ───────────────────────────────────────────────────────────────────

class Alert(Base):
    """Security alert produced by the detection engine."""
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open")      # open|in_incident|closed|false_positive

    rule_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("detection_rules.id"))
    rule: Mapped[Optional["DetectionRule"]] = relationship("DetectionRule")

    host: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    user: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)  # originating endpoint agent
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON)
    threat_intel: Mapped[Optional[dict]] = mapped_column(JSON)

    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"))
    incident: Mapped[Optional["Incident"]] = relationship("Incident", back_populates="alerts")
    events: Mapped[list["NormalizedEvent"]] = relationship("NormalizedEvent", secondary="alert_events", back_populates="alerts")


class AlertEvent(Base):
    """Association: Alert ↔ NormalizedEvent."""
    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("alerts.id"), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("normalized_events.id"), primary_key=True)


# ─── Incidents ────────────────────────────────────────────────────────────────

class Incident(Base):
    """Correlated security incident."""
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open")  # open|investigating|responded|closed|false_positive
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    risk_score: Mapped[Optional[float]] = mapped_column(Float)
    confidence: Mapped[Optional[float]] = mapped_column(Float)

    entities: Mapped[Optional[dict]] = mapped_column(JSON)       # {users, hosts, ips, domains, hashes}
    mitre_techniques: Mapped[Optional[list]] = mapped_column(JSON)
    attack_graph: Mapped[Optional[dict]] = mapped_column(JSON)
    attack_story: Mapped[Optional[dict]] = mapped_column(JSON)
    investigation_trace: Mapped[Optional[list]] = mapped_column(JSON)
    recommendations: Mapped[Optional[list]] = mapped_column(JSON)
    actions: Mapped[Optional[list]] = mapped_column(JSON)
    verification: Mapped[Optional[dict]] = mapped_column(JSON)
    analyst_feedback: Mapped[Optional[dict]] = mapped_column(JSON)

    alerts: Mapped[list["Alert"]] = relationship("Alert", back_populates="incident")


# ─── Agent Audit ─────────────────────────────────────────────────────────────

class AgentTrace(Base):
    """Audit trail for every agent action."""
    __tablename__ = "agent_traces"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    agent_name: Mapped[str] = mapped_column(String(64), nullable=False)
    step: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(128), nullable=False)  # tool_call | reasoning | decision
    tool_name: Mapped[Optional[str]] = mapped_column(String(128))
    tool_args: Mapped[Optional[dict]] = mapped_column(JSON)
    tool_result: Mapped[Optional[dict]] = mapped_column(JSON)
    reasoning: Mapped[Optional[str]] = mapped_column(Text)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[Optional[str]] = mapped_column(Text)


# ─── Analyst Continuous Learning Feedback ─────────────────────────────────────

class AnalystFeedback(Base):
    """Analyst feedback for model evaluation and continuous learning."""
    __tablename__ = "analyst_feedback"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("incidents.id"), index=True)
    rating: Mapped[int] = mapped_column(Integer, nullable=False)  # 1-5 stars
    is_false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    category: Mapped[Optional[str]] = mapped_column(String(64))  # accurate | missed_evidence | wrong_triage | wrong_remediation
    analyst_note: Mapped[Optional[str]] = mapped_column(Text)
    corrected_severity: Mapped[Optional[str]] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── Enterprise Fleet Management (100+ Endpoints) ─────────────────────────────

class EndpointDevice(Base):
    """Real enterprise endpoint asset and telemetry tracking."""
    __tablename__ = "endpoint_devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    mac_address: Mapped[Optional[str]] = mapped_column(String(32))
    os: Mapped[str] = mapped_column(String(64), nullable=False)
    device_type: Mapped[str] = mapped_column(String(32), default="workstation")
    department: Mapped[str] = mapped_column(String(64), default="Corporate")
    assigned_user: Mapped[Optional[str]] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(32), default="online")
    containment_status: Mapped[str] = mapped_column(String(32), default="normal")
    agent_version: Mapped[str] = mapped_column(String(32), default="v2.5.0-aegis")
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    cpu_usage_pct: Mapped[float] = mapped_column(Float, default=12.5)
    memory_usage_pct: Mapped[float] = mapped_column(Float, default=45.0)
    open_alerts_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class DeviceActionLog(Base):
    """Audit log of active containment and response actions executed on fleet devices."""
    __tablename__ = "device_action_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    hostname: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[Optional[str]] = mapped_column(String(256))
    analyst: Mapped[str] = mapped_column(String(128), default="SecOps Analyst (L2)")
    status: Mapped[str] = mapped_column(String(32), default="success")
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


# ─── Endpoint Agent Integration (real registered agents) ──────────────────────
# NOTE: These are the *real* endpoint agents that enroll, authenticate, heartbeat
# and stream telemetry — distinct from the synthetic `EndpointDevice` fleet above.

class EndpointAgent(Base):
    """A real endpoint agent that has enrolled with the AegisX server."""
    __tablename__ = "endpoint_agents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Public opaque identity, e.g. "AGT-8F32A91C". Never the hostname alone.
    agent_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    # SHA-256 hash of the per-agent credential. The plaintext token is returned
    # once at enrollment and NEVER stored or logged.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    hostname: Mapped[str] = mapped_column(String(256), index=True, nullable=False)
    operating_system: Mapped[Optional[str]] = mapped_column(String(64))   # windows | linux | macos
    os_version: Mapped[Optional[str]] = mapped_column(String(128))
    agent_version: Mapped[Optional[str]] = mapped_column(String(32))
    username: Mapped[Optional[str]] = mapped_column(String(128))          # only if operator opts in
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    mac_address: Mapped[Optional[str]] = mapped_column(String(32))

    status: Mapped[str] = mapped_column(String(32), default="online")      # online|warning|offline|unhealthy|revoked
    health: Mapped[str] = mapped_column(String(32), default="healthy")     # healthy|warning|unhealthy
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    labels: Mapped[Optional[dict]] = mapped_column(JSON)                    # freeform metadata


class EnrollmentToken(Base):
    """One-time (or bounded-use) enrollment token used to bootstrap an agent."""
    __tablename__ = "enrollment_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # SHA-256 hash of the enrollment secret — plaintext is shown once to the admin.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    label: Mapped[Optional[str]] = mapped_column(String(128))
    max_uses: Mapped[int] = mapped_column(Integer, default=1)
    used_count: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class AgentHeartbeat(Base):
    """Historical heartbeat log for an endpoint agent."""
    __tablename__ = "agent_heartbeats"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    agent_version: Mapped[Optional[str]] = mapped_column(String(32))
    status: Mapped[Optional[str]] = mapped_column(String(32))
    cpu_usage_pct: Mapped[Optional[float]] = mapped_column(Float)
    memory_usage_pct: Mapped[Optional[float]] = mapped_column(Float)
    queued_events: Mapped[Optional[int]] = mapped_column(Integer)


class AgentSecurityLog(Base):
    """Security-relevant audit log for endpoint-agent server actions."""
    __tablename__ = "agent_security_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    event: Mapped[str] = mapped_column(String(64), nullable=False)  # enroll|enroll_denied|auth_failure|revoke|...
    source_ip: Mapped[Optional[str]] = mapped_column(String(45))
    detail: Mapped[Optional[str]] = mapped_column(Text)
    success: Mapped[bool] = mapped_column(Boolean, default=True)


