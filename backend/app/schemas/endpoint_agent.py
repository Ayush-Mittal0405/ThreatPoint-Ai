"""
Pydantic schemas for the endpoint-agent integration API (/api/v1/endpoints).

Covers enrollment, heartbeat, telemetry ingestion, and dashboard read models.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ─── Enrollment token administration (admin-authenticated) ────────────────────

class EnrollmentTokenCreate(BaseModel):
    label: Optional[str] = Field(None, max_length=128)
    max_uses: int = Field(1, ge=1, le=1000)
    ttl_seconds: Optional[int] = Field(None, ge=60, le=31_536_000)


class EnrollmentTokenCreated(BaseModel):
    # Plaintext token is returned exactly once, at creation time.
    enrollment_token: str
    label: Optional[str]
    max_uses: int
    expires_at: datetime


# ─── Agent enrollment ─────────────────────────────────────────────────────────

class EnrollRequest(BaseModel):
    enrollment_token: str = Field(..., min_length=8)
    hostname: str = Field(..., max_length=256)
    operating_system: Optional[str] = Field(None, max_length=64)
    os_version: Optional[str] = Field(None, max_length=128)
    agent_version: Optional[str] = Field(None, max_length=32)
    username: Optional[str] = Field(None, max_length=128)
    ip_address: Optional[str] = Field(None, max_length=45)
    mac_address: Optional[str] = Field(None, max_length=32)
    labels: Optional[Dict[str, Any]] = None


class EnrollResponse(BaseModel):
    agent_id: str
    # Per-agent credential — returned once; the agent must persist it securely.
    agent_token: str
    heartbeat_interval_seconds: int
    server_time: datetime


# ─── Heartbeat ────────────────────────────────────────────────────────────────

class HeartbeatRequest(BaseModel):
    timestamp: Optional[datetime] = None
    agent_version: Optional[str] = Field(None, max_length=32)
    status: Optional[str] = Field(None, max_length=32)      # healthy|warning|unhealthy
    cpu_usage_pct: Optional[float] = Field(None, ge=0, le=100)
    memory_usage_pct: Optional[float] = Field(None, ge=0, le=100)
    queued_events: Optional[int] = Field(None, ge=0)
    ip_address: Optional[str] = Field(None, max_length=45)


class HeartbeatResponse(BaseModel):
    agent_id: str
    status: str
    server_time: datetime
    heartbeat_interval_seconds: int


# ─── Telemetry events ─────────────────────────────────────────────────────────

class AgentEventIn(BaseModel):
    """A single endpoint security event emitted by an agent collector."""
    event_type: str = Field(..., max_length=64)   # process_creation | network_connection | ...
    timestamp: datetime
    severity: Optional[str] = Field("info", max_length=16)
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    hash_md5: Optional[str] = Field(None, max_length=32)
    hash_sha256: Optional[str] = Field(None, max_length=64)
    src_ip: Optional[str] = Field(None, max_length=45)
    dst_ip: Optional[str] = Field(None, max_length=45)
    dst_port: Optional[int] = Field(None, ge=0, le=65535)
    domain: Optional[str] = Field(None, max_length=512)
    raw: Optional[Dict[str, Any]] = None


class AgentEventBatch(BaseModel):
    events: List[AgentEventIn] = Field(..., max_length=1000)


class EventIngestResponse(BaseModel):
    accepted: int
    agent_id: str


# ─── Dashboard read models ────────────────────────────────────────────────────

class EndpointAgentOut(BaseModel):
    agent_id: str
    hostname: str
    operating_system: Optional[str]
    os_version: Optional[str]
    agent_version: Optional[str]
    username: Optional[str]
    ip_address: Optional[str]
    status: str
    health: str
    risk_score: int
    open_alerts: int
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class EndpointFleetStats(BaseModel):
    total: int
    online: int
    offline: int
    warning: int
    unhealthy: int
    suspicious: int


class TimelineEntry(BaseModel):
    timestamp: datetime
    kind: str          # event | detection | incident
    title: str
    severity: Optional[str] = None
    detail: Optional[str] = None


class EndpointDetailOut(BaseModel):
    agent: EndpointAgentOut
    recent_events: List[Dict[str, Any]]
    detections: List[Dict[str, Any]]
    incidents: List[Dict[str, Any]]
    timeline: List[TimelineEntry]
