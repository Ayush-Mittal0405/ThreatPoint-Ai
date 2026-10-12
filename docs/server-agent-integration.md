# Server ↔ Endpoint-Agent Integration

This document describes the **real** endpoint-agent integration added to AegisX:
how agents enroll, authenticate, heartbeat, and stream telemetry, and how that
telemetry flows into the existing detection/correlation/triage pipeline.

> This is separate from the synthetic **Fleet** feature (`/api/v1/fleet`,
> `/fleet` page), which is a hard-coded in-memory simulation of 110 hosts. The
> integration here concerns agents that actually enroll and report.

## Component map

| Concern | File |
|---|---|
| API routes | `backend/app/api/v1/endpoints/endpoint_agents.py` (mounted at `/api/v1/endpoints`) |
| Request/response schemas | `backend/app/schemas/endpoint_agent.py` |
| Pure service logic (identity, credential hashing, status, mapping) | `backend/app/services/endpoint_agents.py` |
| DB models | `backend/app/models/models.py` → `EndpointAgent`, `EnrollmentToken`, `AgentHeartbeat`, `AgentSecurityLog` |
| Migration | `backend/alembic/versions/002_endpoint_agents.py` |
| Reused pipeline | `services/normalization.py` → `detection/engine.py` → `correlation/engine.py` |
| Dashboard | `frontend/src/pages/Endpoints.tsx`, API client in `frontend/src/services/api.ts` |

## API surface (`/api/v1/endpoints`)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /enroll-tokens` | Admin (`X-Admin-API-Key`) | Mint a one-time enrollment token |
| `POST /enroll` | Enrollment token | Register an agent, receive `agent_id` + credential |
| `POST /heartbeat` | Agent (`X-Agent-Id` + Bearer) | Refresh presence/health |
| `POST /events` | Agent (`X-Agent-Id` + Bearer) | Submit a batch of security events |
| `POST /{agent_id}/revoke` | Admin | Revoke an agent credential |
| `GET  /` | none (read) | List enrolled agents (dashboard) |
| `GET  /stats` | none (read) | Overview counts (dashboard) |
| `GET  /{agent_id}` | none (read) | Detail: events, detections, incidents, timeline |

## Authentication model

- **Admin actions** require `X-Admin-API-Key` equal to `AEGISX_ADMIN_API_KEY`
  (constant-time compared). Set this in `.env`; never commit it.
- **Agent actions** require two headers:
  - `X-Agent-Id: AGT-XXXXXXXX`
  - `Authorization: Bearer <agent_token>`
  The token is verified against the stored **SHA-256 hash** (constant-time).
  Plaintext credentials are returned **once** at enrollment and never stored or
  logged. The abstraction (hashed credential + revocation flag) is designed to
  extend to certificate/mTLS and token rotation later.

## Identity

`agent_id` is an opaque value like `AGT-8F32A91C` generated from a CSPRNG
(`secrets.token_hex`) — deliberately **independent of hostname**, so
`EMP-LAPTOP-01` and a near-identical `EMP-LAPTOP-02` are always distinguishable.

## Enrollment flow

```
Admin: POST /enroll-tokens (X-Admin-API-Key)   ──►  { enrollment_token }  (shown once)
                                                        │
Agent: POST /enroll { enrollment_token, hostname, os … } │
                                                        ▼
Server validates token (unrevoked, unexpired, uses left)
        creates EndpointAgent, stores SHA-256(agent_token)
        returns { agent_id, agent_token, heartbeat_interval }  (token shown once)
        increments token used_count
                                                        │
Agent persists agent_id + agent_token to secure state store
```

## Telemetry flow (reuses the existing pipeline)

```
POST /events (agent-authenticated)
   │  validate against AgentEventIn, tag with agent_id, default host=hostname
   ▼
RawEventIn[]  ──► NormalizationService (dedup, NormalizedEvent rows, agent_id column)
   ▼
DetectionEngine.evaluate_event  ──► Alert rows (agent_id copied through)
   ▼
CorrelationEngine.correlate_pending_alerts ──► Incident rows
   ▼
(existing) AgentOrchestrator / TriageAgent — investigate incidents on demand
```

Because endpoint telemetry lands in the **same** `NormalizedEvent` / `Alert` /
`Incident` tables, every existing capability applies automatically: the 5
behavioral rules (Office→shell, encoded PowerShell, C2 ports, admin-group
change, suspicious path), 30-minute host/user correlation, the deterministic
risk engine, and the multi-agent investigation loop. The endpoint detail page
surfaces these per agent.

### Event schema (`AgentEventIn`)

```json
{
  "event_type": "process_creation",
  "timestamp": "2026-09-03T12:30:00Z",
  "severity": "info",
  "host": "EMP-LAPTOP-01",
  "user": "jdoe",
  "process": "powershell.exe",
  "parent_process": "winword.exe",
  "command_line": "powershell -enc ...",
  "file_path": "C:\\...\\powershell.exe",
  "hash_sha256": "…",
  "src_ip": "10.0.0.5", "dst_ip": "185.220.101.5", "dst_port": 4444,
  "domain": "example.com",
  "raw": { "pid": 1234, "ppid": 980 }
}
```

Canonical `event_type` values the detection engine understands:
`process_creation`, `process_termination`, `network_connection`, `dns_query`,
`authentication`, `user_account_change`, `file_event`, `persistence`, `eventlog`.

## Presence / health status

Computed from `last_seen` using configurable timeouts (no hard-coded
assumptions):

- `online` — heartbeat within `ENDPOINT_WARNING_TIMEOUT_SECONDS` (default 90s)
- `warning` — older than warning timeout, or agent self-reports `warning`
- `offline` — older than `ENDPOINT_OFFLINE_TIMEOUT_SECONDS` (default 180s)
- `unhealthy` — agent self-reports `unhealthy`
- `revoked` — credential revoked

## Security controls

- HTTPS/TLS for all agent traffic (enforced by the agent; server should sit
  behind TLS in production — see architecture doc).
- Unique per-agent identity + credential; credentials stored only as hashes.
- Admin authorization on token minting and revocation.
- Every enroll / auth-failure / revoke is written to `agent_security_logs`.
- Incoming telemetry is validated (Pydantic) and size-capped
  (`ENDPOINT_EVENT_BATCH_MAX`, default 500).
- `slowapi` rate limiting (200/min default) already applies globally.
- The agent collects security-relevant metadata only — no packet payloads, file
  contents, passwords, keys, or cookies.

## Configuration (server `.env`)

```
AEGISX_ADMIN_API_KEY=<strong-random>
ENDPOINT_WARNING_TIMEOUT_SECONDS=90
ENDPOINT_OFFLINE_TIMEOUT_SECONDS=180
ENROLLMENT_TOKEN_TTL_SECONDS=86400
ENDPOINT_EVENT_BATCH_MAX=500
```
