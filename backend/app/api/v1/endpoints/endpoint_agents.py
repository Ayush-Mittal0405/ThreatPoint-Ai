"""
Endpoint-agent integration API (/api/v1/endpoints).

Real endpoint agents (distinct from the AI `/agents` router and the synthetic
`/fleet` mock) enroll, authenticate, heartbeat, and stream security telemetry
through here. Ingested telemetry is fed into the existing
Normalize -> Detect -> Correlate pipeline so endpoint activity produces the same
Alerts / Incidents the rest of the SOC already understands.

Auth model
----------
- Admin actions (mint/revoke enrollment tokens, revoke agents) require the
  `X-Admin-API-Key` header matching settings.AEGISX_ADMIN_API_KEY.
- Agent actions (heartbeat, events) require BOTH headers:
    X-Agent-Id: AGT-....
    Authorization: Bearer <agent_token>
  The token is verified against the stored SHA-256 hash (constant time).
Only credential *hashes* are stored; plaintext tokens are returned once and
never logged.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, BackgroundTasks
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db, AsyncSessionLocal
from app.models.models import (
    EndpointAgent, EnrollmentToken, AgentHeartbeat, AgentSecurityLog,
    NormalizedEvent, Alert, Incident,
)
from app.schemas.endpoint_agent import (
    EnrollmentTokenCreate, EnrollmentTokenCreated,
    EnrollRequest, EnrollResponse,
    HeartbeatRequest, HeartbeatResponse,
    AgentEventBatch, EventIngestResponse,
    EndpointAgentOut, EndpointFleetStats,
    EndpointDetailOut, TimelineEntry,
)
from app.schemas.telemetry import RawEventIn
from app.services import endpoint_agents as svc
from app.services.normalization import NormalizationService
from app.detection.engine import DetectionEngine
from app.correlation.engine import CorrelationEngine

log = structlog.get_logger()
router = APIRouter()

# Heartbeat cadence advertised to agents (kept in step with the offline timeout).
_HEARTBEAT_INTERVAL = max(15, settings.ENDPOINT_WARNING_TIMEOUT_SECONDS // 3)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _client_ip(request: Request) -> Optional[str]:
    if request.client:
        return request.client.host
    return None


async def _audit(
    db: AsyncSession, event: str, *, agent_id: Optional[str] = None,
    source_ip: Optional[str] = None, detail: Optional[str] = None, success: bool = True,
) -> None:
    """Write a security audit row (best-effort; never raises into the request)."""
    try:
        db.add(AgentSecurityLog(
            event=event, agent_id=agent_id, source_ip=source_ip,
            detail=detail, success=success,
        ))
        await db.flush()
    except Exception:  # pragma: no cover - audit must not break the request
        log.warning("audit_write_failed", event=event, agent_id=agent_id)


def _require_admin(x_admin_api_key: Optional[str] = Header(None)) -> None:
    """Dependency enforcing the admin API key."""
    import secrets as _secrets
    expected = settings.AEGISX_ADMIN_API_KEY
    if not x_admin_api_key or not _secrets.compare_digest(x_admin_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing admin API key")


async def _authenticate_agent(
    db: AsyncSession,
    agent_id: Optional[str],
    authorization: Optional[str],
    source_ip: Optional[str],
) -> EndpointAgent:
    """Resolve and authenticate an agent from its id + bearer token."""
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    if not agent_id or not token:
        raise HTTPException(status_code=401, detail="Missing agent credentials")

    result = await db.execute(select(EndpointAgent).where(EndpointAgent.agent_id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None or agent.revoked or not svc.verify_token(token, agent.token_hash):
        await _audit(db, "auth_failure", agent_id=agent_id, source_ip=source_ip,
                     detail="invalid agent id or token", success=False)
        # Commit the audit row before raising, so the get_db dependency's
        # exception-path rollback does not discard the security log entry.
        try:
            await db.commit()
        except Exception:  # pragma: no cover - audit must not break the response
            await db.rollback()
        raise HTTPException(status_code=401, detail="Agent authentication failed")
    return agent


def _serialize_agent(agent: EndpointAgent, open_alerts: int = 0) -> EndpointAgentOut:
    status = svc.compute_status(
        agent.last_seen,
        warning_after_s=settings.ENDPOINT_WARNING_TIMEOUT_SECONDS,
        offline_after_s=settings.ENDPOINT_OFFLINE_TIMEOUT_SECONDS,
        health=agent.health,
        revoked=agent.revoked,
    )
    return EndpointAgentOut(
        agent_id=agent.agent_id,
        hostname=agent.hostname,
        operating_system=agent.operating_system,
        os_version=agent.os_version,
        agent_version=agent.agent_version,
        username=agent.username,
        ip_address=agent.ip_address,
        status=status,
        health=agent.health,
        risk_score=agent.risk_score,
        open_alerts=open_alerts,
        first_seen=agent.first_seen,
        last_seen=agent.last_seen,
    )


async def _run_agent_pipeline(events_in: List[RawEventIn], agent_id: str) -> None:
    """Normalize -> Detect -> Correlate, on a fresh dedicated session so it is
    safe to run after the HTTP response has been returned."""
    async with AsyncSessionLocal() as db:
        try:
            norm_svc = NormalizationService(db)
            event_ids = await norm_svc.ingest_batch(events_in)

            result = await db.execute(
                select(NormalizedEvent).where(NormalizedEvent.event_id.in_(event_ids))
            )
            stored = list(result.scalars().all())

            det_engine = DetectionEngine(db)
            for event in stored:
                await det_engine.evaluate_event(event)

            corr_engine = CorrelationEngine(db)
            await corr_engine.correlate_pending_alerts()
            await db.commit()
            log.info("agent_pipeline_done", agent_id=agent_id, events=len(stored))
        except Exception as exc:  # pragma: no cover - defensive
            await db.rollback()
            log.error("agent_pipeline_failed", agent_id=agent_id, error=str(exc))


# ─── Admin: enrollment token lifecycle ────────────────────────────────────────

@router.post("/enroll-tokens", response_model=EnrollmentTokenCreated,
             dependencies=[Depends(_require_admin)], status_code=201)
async def create_enrollment_token(
    body: EnrollmentTokenCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Mint a new enrollment token. The plaintext is returned exactly once."""
    token = svc.generate_secret_token()
    ttl = body.ttl_seconds or settings.ENROLLMENT_TOKEN_TTL_SECONDS
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)

    row = EnrollmentToken(
        token_hash=svc.hash_token(token),
        label=body.label,
        max_uses=body.max_uses,
        expires_at=expires_at,
        created_by="admin",
    )
    db.add(row)
    await _audit(db, "enroll_token_created", source_ip=_client_ip(request),
                 detail=f"label={body.label} max_uses={body.max_uses}")
    await db.commit()

    return EnrollmentTokenCreated(
        enrollment_token=token,
        label=body.label,
        max_uses=body.max_uses,
        expires_at=expires_at,
    )


# ─── Agent enrollment ─────────────────────────────────────────────────────────

@router.post("/enroll", response_model=EnrollResponse, status_code=201)
async def enroll_agent(
    body: EnrollRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Enroll a new agent using a valid enrollment token.

    Returns a unique agent_id and a per-agent credential (once). The credential
    is stored only as a SHA-256 hash server-side.
    """
    src = _client_ip(request)
    token_hash = svc.hash_token(body.enrollment_token)
    result = await db.execute(
        select(EnrollmentToken).where(EnrollmentToken.token_hash == token_hash)
    )
    token_row = result.scalar_one_or_none()

    if token_row is None or not svc.is_enrollment_token_valid(
        revoked=token_row.revoked,
        used_count=token_row.used_count,
        max_uses=token_row.max_uses,
        expires_at=token_row.expires_at,
    ):
        await _audit(db, "enroll_denied", source_ip=src,
                     detail=f"hostname={body.hostname}", success=False)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")

    agent_id = svc.generate_agent_id()
    agent_token = svc.generate_secret_token()
    agent = EndpointAgent(
        agent_id=agent_id,
        token_hash=svc.hash_token(agent_token),
        hostname=body.hostname,
        operating_system=(body.operating_system or "").lower() or None,
        os_version=body.os_version,
        agent_version=body.agent_version,
        username=body.username,
        ip_address=body.ip_address or src,
        mac_address=body.mac_address,
        labels=body.labels,
        status="online",
        health="healthy",
    )
    db.add(agent)
    token_row.used_count += 1
    await _audit(db, "enroll", agent_id=agent_id, source_ip=src,
                 detail=f"hostname={body.hostname} os={body.operating_system}")
    await db.commit()

    log.info("agent_enrolled", agent_id=agent_id, hostname=body.hostname)
    return EnrollResponse(
        agent_id=agent_id,
        agent_token=agent_token,
        heartbeat_interval_seconds=_HEARTBEAT_INTERVAL,
        server_time=datetime.now(timezone.utc),
    )


# ─── Heartbeat ────────────────────────────────────────────────────────────────

@router.post("/heartbeat", response_model=HeartbeatResponse)
async def agent_heartbeat(
    body: HeartbeatRequest,
    request: Request,
    x_agent_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Record an agent heartbeat and refresh presence/health."""
    src = _client_ip(request)
    agent = await _authenticate_agent(db, x_agent_id, authorization, src)

    now = datetime.now(timezone.utc)
    agent.last_seen = now
    if body.agent_version:
        agent.agent_version = body.agent_version
    if body.ip_address:
        agent.ip_address = body.ip_address
    if body.status in {"healthy", "warning", "unhealthy"}:
        agent.health = body.status
    agent.status = svc.compute_status(
        now,
        warning_after_s=settings.ENDPOINT_WARNING_TIMEOUT_SECONDS,
        offline_after_s=settings.ENDPOINT_OFFLINE_TIMEOUT_SECONDS,
        health=agent.health,
        revoked=agent.revoked,
    )

    db.add(AgentHeartbeat(
        agent_id=agent.agent_id,
        agent_version=body.agent_version,
        status=body.status,
        cpu_usage_pct=body.cpu_usage_pct,
        memory_usage_pct=body.memory_usage_pct,
        queued_events=body.queued_events,
    ))
    await db.commit()

    return HeartbeatResponse(
        agent_id=agent.agent_id,
        status=agent.status,
        server_time=now,
        heartbeat_interval_seconds=_HEARTBEAT_INTERVAL,
    )


# ─── Telemetry ingestion ──────────────────────────────────────────────────────

@router.post("/events", response_model=EventIngestResponse, status_code=202)
async def ingest_agent_events(
    body: AgentEventBatch,
    request: Request,
    background_tasks: BackgroundTasks,
    x_agent_id: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Accept a batch of endpoint security events from an authenticated agent."""
    src = _client_ip(request)
    agent = await _authenticate_agent(db, x_agent_id, authorization, src)

    if len(body.events) > settings.ENDPOINT_EVENT_BATCH_MAX:
        raise HTTPException(
            status_code=413,
            detail=f"Batch too large (max {settings.ENDPOINT_EVENT_BATCH_MAX})",
        )

    # Map + validate onto the internal RawEventIn schema, tagging with agent_id.
    raw_events: List[RawEventIn] = []
    for ev in body.events:
        raw_dict = svc.agent_event_to_raw_dict(ev, agent.agent_id)
        # host defaults to the agent's own hostname when the collector omits it
        if not raw_dict.get("host"):
            raw_dict["host"] = agent.hostname
        raw_events.append(RawEventIn(**raw_dict))

    agent.last_seen = datetime.now(timezone.utc)
    await db.commit()

    background_tasks.add_task(_run_agent_pipeline, raw_events, agent.agent_id)
    return EventIngestResponse(accepted=len(raw_events), agent_id=agent.agent_id)


# ─── Admin: agent revocation ──────────────────────────────────────────────────

@router.post("/{agent_id}/revoke", dependencies=[Depends(_require_admin)])
async def revoke_agent(agent_id: str, request: Request, db: AsyncSession = Depends(get_db)):
    """Revoke an agent's credential; it can no longer authenticate."""
    result = await db.execute(select(EndpointAgent).where(EndpointAgent.agent_id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.revoked = True
    agent.status = "revoked"
    await _audit(db, "revoke", agent_id=agent_id, source_ip=_client_ip(request))
    await db.commit()
    return {"status": "revoked", "agent_id": agent_id}


# ─── Dashboard reads ──────────────────────────────────────────────────────────

async def _open_alerts_by_agent(db: AsyncSession) -> Dict[str, int]:
    """Count open (open|in_incident) alerts grouped by agent_id."""
    result = await db.execute(
        select(Alert.agent_id, func.count(Alert.id))
        .where(Alert.agent_id.isnot(None), Alert.status.in_(["open", "in_incident"]))
        .group_by(Alert.agent_id)
    )
    return {row[0]: row[1] for row in result.all()}


@router.get("", response_model=List[EndpointAgentOut])
async def list_endpoints(
    status: Optional[str] = None,
    os: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List registered endpoint agents for the dashboard."""
    try:
        q = select(EndpointAgent).order_by(EndpointAgent.last_seen.desc())
        if os:
            q = q.where(EndpointAgent.operating_system == os.lower())
        if search:
            like = f"%{search}%"
            q = q.where(
                EndpointAgent.hostname.ilike(like) | EndpointAgent.agent_id.ilike(like)
            )
        result = await db.execute(q.limit(limit).offset(offset))
        agents = list(result.scalars().all())
        alerts_by_agent = await _open_alerts_by_agent(db)
    except Exception as exc:
        log.warning("list_endpoints_db_unavailable", error=str(exc))
        return []

    out = [_serialize_agent(a, alerts_by_agent.get(a.agent_id, 0)) for a in agents]
    if status:
        out = [a for a in out if a.status == status.lower()]
    return out


@router.get("/stats", response_model=EndpointFleetStats)
async def endpoint_stats(db: AsyncSession = Depends(get_db)):
    """Endpoint fleet overview counts for the dashboard header cards."""
    try:
        result = await db.execute(select(EndpointAgent))
        agents = list(result.scalars().all())
    except Exception as exc:
        log.warning("endpoint_stats_db_unavailable", error=str(exc))
        return EndpointFleetStats(total=0, online=0, offline=0, warning=0, unhealthy=0, suspicious=0)

    statuses = [
        svc.compute_status(
            a.last_seen,
            warning_after_s=settings.ENDPOINT_WARNING_TIMEOUT_SECONDS,
            offline_after_s=settings.ENDPOINT_OFFLINE_TIMEOUT_SECONDS,
            health=a.health, revoked=a.revoked,
        )
        for a in agents
    ]
    return EndpointFleetStats(
        total=len(agents),
        online=statuses.count("online"),
        offline=statuses.count("offline"),
        warning=statuses.count("warning"),
        unhealthy=statuses.count("unhealthy"),
        suspicious=sum(1 for a in agents if a.risk_score >= 60),
    )


@router.get("/{agent_id}", response_model=EndpointDetailOut)
async def endpoint_detail(agent_id: str, db: AsyncSession = Depends(get_db)):
    """Full endpoint detail: agent info, recent activity, detections, incidents, timeline."""
    result = await db.execute(select(EndpointAgent).where(EndpointAgent.agent_id == agent_id))
    agent = result.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Endpoint agent not found")

    # Recent normalized events for this agent
    ev_res = await db.execute(
        select(NormalizedEvent)
        .where(NormalizedEvent.agent_id == agent_id)
        .order_by(NormalizedEvent.timestamp.desc())
        .limit(100)
    )
    events = list(ev_res.scalars().all())

    # Detections (alerts) attributed to this agent
    al_res = await db.execute(
        select(Alert).where(Alert.agent_id == agent_id).order_by(Alert.created_at.desc()).limit(100)
    )
    alerts = list(al_res.scalars().all())

    # Incidents linked to those alerts
    incident_ids = {a.incident_id for a in alerts if a.incident_id}
    incidents: List[Incident] = []
    if incident_ids:
        inc_res = await db.execute(select(Incident).where(Incident.id.in_(incident_ids)))
        incidents = list(inc_res.scalars().all())

    open_alerts = sum(1 for a in alerts if a.status in ("open", "in_incident"))

    def _event_dict(e: NormalizedEvent) -> Dict[str, Any]:
        return {
            "event_id": e.event_id, "timestamp": e.timestamp, "event_type": e.event_type,
            "host": e.host, "user": e.user, "process": e.process,
            "parent_process": e.parent_process, "command_line": e.command_line,
            "src_ip": e.src_ip, "dst_ip": e.dst_ip, "dst_port": e.dst_port, "domain": e.domain,
        }

    def _alert_dict(a: Alert) -> Dict[str, Any]:
        return {
            "alert_id": a.alert_id, "title": a.title, "severity": a.severity,
            "status": a.status, "created_at": a.created_at,
            "mitre_techniques": a.mitre_techniques, "incident_id": str(a.incident_id) if a.incident_id else None,
        }

    def _incident_dict(i: Incident) -> Dict[str, Any]:
        return {
            "incident_id": i.incident_id, "id": str(i.id), "title": i.title,
            "status": i.status, "severity": i.severity, "risk_score": i.risk_score,
            "created_at": i.created_at,
        }

    # Merge into a single chronological security timeline
    timeline: List[TimelineEntry] = []
    for e in events[:40]:
        timeline.append(TimelineEntry(
            timestamp=e.timestamp, kind="event", title=f"{e.event_type}: {e.process or e.host or ''}".strip(),
            detail=e.command_line,
        ))
    for a in alerts:
        timeline.append(TimelineEntry(
            timestamp=a.created_at, kind="detection", title=a.title, severity=a.severity,
        ))
    for i in incidents:
        timeline.append(TimelineEntry(
            timestamp=i.created_at, kind="incident", title=i.title, severity=i.severity,
        ))
    timeline.sort(key=lambda t: t.timestamp, reverse=True)

    return EndpointDetailOut(
        agent=_serialize_agent(agent, open_alerts),
        recent_events=[_event_dict(e) for e in events],
        detections=[_alert_dict(a) for a in alerts],
        incidents=[_incident_dict(i) for i in incidents],
        timeline=timeline[:80],
    )
