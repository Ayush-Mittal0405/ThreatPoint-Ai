# AegisX Endpoint-to-SOC Architecture

How a client PC's activity becomes a triaged incident in the AegisX dashboard.

```
   Client PC (Windows)                         AegisX Server
 ┌──────────────────────┐                 ┌───────────────────────────────────┐
 │  AegisX agent        │                 │  /api/v1/endpoints (ingestion API) │
 │  ┌────────────────┐  │  outbound TLS   │            │                      │
 │  │ collectors     │  │  ─────────────► │      normalization                │
 │  │ process/net/   │  │   (HTTPS only,  │            │                      │
 │  │ auth/persist   │  │    agent → svr) │      detection engine (rules)     │
 │  └──────┬─────────┘  │                 │            │                      │
 │   normalize          │                 │      correlation (30-min window)  │
 │   bounded buffer     │                 │            │                      │
 │   retry/backoff      │                 │      incidents                    │
 │   heartbeat          │                 │            │                      │
 └──────────────────────┘                 │      TriageAgent / LLM (existing) │
                                          │            │                      │
                                          │      Endpoints dashboard page     │
                                          └───────────────────────────────────┘
```

The agent only ever makes **outbound** connections, so clients outside the
corporate LAN can report without the server reaching into each PC — and the
dashboard never connects directly to employee machines.

## Alert flow (end to end)

```
Client PC → AegisX agent → (TLS) → Ingestion API → Normalizer → Detection
   → benign  → stored only
   → suspicious → Correlation → Incident → TriageAgent → Risk/Severity → Dashboard
```

This is the exact reuse of the pre-existing pipeline; endpoint telemetry shares
the `NormalizedEvent` / `Alert` / `Incident` tables with every other source.

## Data model additions (migration `002_endpoint_agents`)

- `endpoint_agents` — enrolled agents (identity, hashed credential, presence).
- `enrollment_tokens` — hashed bootstrap tokens (bounded uses + expiry).
- `agent_heartbeats` — heartbeat history (agent CPU/mem, queue depth).
- `agent_security_logs` — enroll/auth-failure/revoke audit trail.
- `normalized_events.agent_id`, `alerts.agent_id` — attribute telemetry and
  detections to a specific enrolled agent (indexed; nullable for legacy rows).

## Trust boundaries & controls

- **Transport:** HTTPS/TLS agent↔server (the agent refuses cleartext to remote
  servers). Terminate TLS at the server or a reverse proxy.
- **Identity:** opaque `AGT-XXXXXXXX`, independent of hostname.
- **Authentication:** per-agent bearer credential, stored only as SHA-256.
- **Authorization:** admin API key gates token minting and agent revocation.
- **Validation:** all telemetry is Pydantic-validated and batch-size-capped.
- **Least privilege / minimization:** metadata-only collection; no payloads,
  secrets, or personal content; username opt-in.
- **No unauthenticated remote command execution** — the ingestion API only
  accepts telemetry; response/containment stays behind the existing
  human-approval gates in the Response Center.

## Running the full stack (development)

Prerequisite: PostgreSQL reachable with the credentials in `.env` (copy
`.env.example` → `.env` and set `POSTGRES_*` + `AEGISX_ADMIN_API_KEY`). Apply
migrations:

```bash
cd aegisx/backend
alembic upgrade head           # creates endpoint_agents tables + agent_id columns
```

Start the server and dashboard:

```powershell
# Backend (FastAPI, port 8008)
cd aegisx\backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8008 --reload

# Frontend (React, port 3000)
cd aegisx\frontend
npm run dev
```

Mint a token, then enroll and run an agent (see
[windows-agent-installation.md](./windows-agent-installation.md)):

```bash
curl -X POST http://127.0.0.1:8008/api/v1/endpoints/enroll-tokens \
  -H "X-Admin-API-Key: $AEGISX_ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"label":"my-pc","max_uses":1}'
```

```powershell
cd aegisx\aegisx-agent
.\scripts\enroll.ps1 -Token "<token>" -Server "http://127.0.0.1:8008"
.\scripts\run-agent.ps1
```

Open the dashboard → **Endpoints** to watch the host come online and stream
telemetry, detections, incidents, and its security timeline.

## Testing

```bash
# Server (144 tests incl. endpoint-agent service unit tests)
cd aegisx && python -m pytest tests/ -q

# Agent (28 tests incl. a real agent↔HTTP-server end-to-end)
cd aegisx/aegisx-agent && python -m pytest -q
```

## What is real vs. mock

- **Real:** enrollment/auth/heartbeat/ingestion API, credential hashing,
  status computation, the normalize→detect→correlate reuse, the Windows agent
  and its process/network collectors (verified capturing live telemetry), the
  offline buffer + retry, and the Endpoints dashboard.
- **Windows-only collectors** (`eventlog`, `persistence`) run on Windows and
  no-op on other platforms.
- **Mock (unchanged, separate):** the `/fleet` page and `/api/v1/fleet` API are
  a synthetic 110-host simulation and are not part of this integration.
- **Future:** see [../REMAINING_WORK.md](../REMAINING_WORK.md) (mTLS/cert auth,
  token rotation, packaged MSI, ETW event-driven process collection, full-stack
  automated e2e in CI).
