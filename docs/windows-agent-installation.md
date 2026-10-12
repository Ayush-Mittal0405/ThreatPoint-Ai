# AegisX Windows Endpoint Agent — Installation Guide

This guide covers installing the AegisX endpoint agent on a Windows client PC so
it enrolls with the AegisX server and streams security telemetry.

Everything below matches the actual implementation in
[`aegisx-agent/`](../aegisx-agent). No fictional commands or paths.

---

## Step 1 — Requirements

- **OS:** Windows 10 / 11, or Windows Server 2019/2022. (Process & network
  collectors are cross-platform; the Security event-log and persistence
  collectors are Windows-only and no-op elsewhere.)
- **Python:** 3.9+ on the client (the dev installer builds a local venv). A
  packaged binary is a future enhancement.
- **Privileges:** Administrator is required to (a) install the auto-start task
  as SYSTEM and (b) read the Windows **Security** event log and full network
  connection table. The process collector works unprivileged but sees fewer
  processes.
- **Network:** outbound HTTPS from the client to the AegisX server. Only the
  agent→server direction is needed (works from outside the LAN).
- **Server URL:** e.g. `https://aegisx.example.com:8008` (your deployment).
- **Ports:** the server's HTTPS port (8008 by default in dev; 443 behind a
  reverse proxy in production).
- **Certificates:** if the server uses a private/self-signed CA, have the CA
  bundle path ready for `server.ca_cert`.

## Step 2 — Obtain the agent

The agent source lives in the repository at:

```
aegisx/aegisx-agent/
```

Copy that folder to the client PC (or clone the repo). A packaged MSI/EXE is
listed under Remaining Work.

## Step 3 — Configure the server address

```powershell
cd aegisx-agent
Copy-Item config\agent.example.yaml config\agent.yaml
notepad config\agent.yaml
```

Set at minimum:

```yaml
server:
  url: "https://aegisx.example.com:8008"
  verify_tls: true          # keep true in production
  ca_cert: ""               # path to CA bundle if the server is self-signed
```

Never put a secret (enrollment token or credential) into source-controlled
files. Supply the enrollment token at enroll time (Step 4) instead.

## Step 4 — Enrollment

**On the server side**, an admin mints a one-time enrollment token:

```bash
curl -X POST https://aegisx.example.com:8008/api/v1/endpoints/enroll-tokens \
  -H "X-Admin-API-Key: $AEGISX_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"label":"laptop-jdoe","max_uses":1,"ttl_seconds":86400}'
# → { "enrollment_token": "….", "expires_at": "…" }   (shown once)
```

**On the client**, run the enrollment script with that token:

```powershell
.\scripts\enroll.ps1 -Token "PASTE-ENROLLMENT-TOKEN" -Server "https://aegisx.example.com:8008"
```

What happens (actual implemented flow):

```
Admin mints enrollment token  ──►  token handed to installer
        ▼
Agent POSTs /api/v1/endpoints/enroll with the token + host metadata
        ▼
Server validates the token, assigns agent_id (AGT-XXXXXXXX)
        ▼
Server returns a per-agent credential (once)
        ▼
Agent stores agent_id + credential in the state directory
        (%PROGRAMDATA%\AegisX\agent\agent_state.json)
```

## Step 5 — Install (auto-start background task)

From an **elevated** PowerShell:

```powershell
.\scripts\install-service.ps1
```

This registers a Scheduled Task named **`AegisXAgent`** that runs
`python -m aegisx_agent --config <your config>` at system startup as SYSTEM with
highest privileges, and starts it immediately. To run it in the foreground
instead (for testing):

```powershell
.\scripts\run-agent.ps1
```

## Step 6 — Start / verify the agent is running

```powershell
schtasks /Query /TN AegisXAgent
# Status should be Running (or Ready between restarts)
```

Local operational logs:

```
%PROGRAMDATA%\AegisX\agent\logs\aegisx-agent.log
```

You should see lines for: startup, enrollment (or "Already enrolled"), collectors
enabled, heartbeat ok, and "Uploaded N events".

## Step 7 — Verify registration

```powershell
.\scripts\status.ps1
# enrolled:   True
# agent_id:   AGT-XXXXXXXX
# server_url: https://aegisx.example.com:8008
```

In the dashboard, open **Endpoints** — the host appears with its Agent ID, OS,
`online` status, agent version, and last-seen time. (Server-side listing:
`GET /api/v1/endpoints`.)

## Step 8 — Verify telemetry (safe test activity)

Generate **benign** activity that the built-in rules recognise:

```powershell
# Encoded PowerShell (matches "Encoded PowerShell Command Execution")
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGgAaQA=
```

Within ~20–30s (one collect + flush cycle) the event appears under the
endpoint's **Recent Events**, a **Detection** is raised, and if it correlates
with other activity an **Incident** is created — visible on the endpoint detail
page and the main Incidents view. Only use safe, synthetic test activity; never
real malware.

## Step 9 — Troubleshooting

See [troubleshooting.md](./troubleshooting.md).
