"""
Pydantic schemas for the telemetry ingestion API (Phase 1).
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ─── Ingest ───────────────────────────────────────────────────────────────────

class RawEventIn(BaseModel):
    """A raw security event sent by a collector."""
    source: str = Field(..., description="Telemetry source: sysmon | zeek | suricata | winlog | linux | aegisx-agent")
    event_type: str = Field(..., description="Canonical event type: process_creation | network_connection | ...")
    timestamp: datetime
    agent_id: Optional[str] = Field(None, description="Originating endpoint agent id (e.g. AGT-8F32A91C)")
    host: Optional[str] = None
    user: Optional[str] = None
    process: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None  # full original event


class RawEventBatch(BaseModel):
    """Batch ingest endpoint accepts up to 1 000 events."""
    events: List[RawEventIn] = Field(..., max_length=1000)


class EventOut(BaseModel):
    """Normalized event returned from storage."""
    id: uuid.UUID
    event_id: str
    timestamp: datetime
    ingested_at: datetime
    source: str
    event_type: str
    host: Optional[str]
    user: Optional[str]
    process: Optional[str]
    parent_process: Optional[str]
    command_line: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    domain: Optional[str]

    model_config = {"from_attributes": True}


# ─── Alerts ───────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: uuid.UUID
    alert_id: str
    created_at: datetime
    title: str
    description: Optional[str]
    severity: str
    status: str
    host: Optional[str]
    user: Optional[str]
    mitre_techniques: Optional[List[str]]

    model_config = {"from_attributes": True}


# ─── Incidents ────────────────────────────────────────────────────────────────

class IncidentOut(BaseModel):
    id: uuid.UUID
    incident_id: str
    created_at: datetime
    updated_at: datetime
    title: str
    description: Optional[str]
    status: str
    severity: str
    risk_score: Optional[float]
    confidence: Optional[float]
    entities: Optional[Dict[str, Any]]
    mitre_techniques: Optional[List[str]]
    attack_story: Optional[Dict[str, Any]]
    recommendations: Optional[List[Dict[str, Any]]]
    verification: Optional[Dict[str, Any]]

    model_config = {"from_attributes": True}


class IncidentListOut(BaseModel):
    total: int
    incidents: List[IncidentOut]


# ─── Ingestion Response ───────────────────────────────────────────────────────

class IngestResponse(BaseModel):
    accepted: int
    event_ids: List[str]
