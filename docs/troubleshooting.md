# AegisX Endpoint Agent — Troubleshooting

Practical diagnostics for the Windows agent and server integration. Agent logs
are at `%PROGRAMDATA%\AegisX\agent\logs\aegisx-agent.log`.

## Agent not starting
- Confirm Python is installed: `python --version`.
- Run in the foreground to see errors: `.\scripts\run-agent.ps1`.
- "Configuration error: server.url must be an http(s) URL" → fix `server.url`
  in `config\agent.yaml`.
- Scheduled task present but not running: `schtasks /Query /TN AegisXAgent /V /FO LIST`.

## Registration / enrollment failure
- `401 Invalid or expired enrollment token`:
  - the token was already used (tokens are single-use unless `max_uses` > 1);
  - the token expired (`ttl_seconds`);
  - mint a fresh one on the server (`POST /api/v1/endpoints/enroll-tokens`).
- "not enrolled and no enrollment token was provided" → pass `-Token` to
  `enroll.ps1` or set `AEGISX_AGENT_ENROLLMENT_TOKEN`.
- Verify local state: `.\scripts\status.ps1`.

## TLS / certificate error
- Self-signed / internal CA: set `server.ca_cert` to your CA bundle path.
- For a throwaway local demo only, set `server.verify_tls: false` (never in
  production).
- Note: the agent refuses plain `http://` to a non-local server by design.

## Server unreachable
- From the client: `Invoke-WebRequest https://<server>:8008/healthz`.
- Check the server port and any reverse proxy / firewall between client and
  server. Only outbound client→server HTTPS is required.
- While unreachable, the agent buffers events (bounded) and retries with
  exponential backoff — no data loss until the buffer cap is hit.

## Authentication failure (heartbeat/events return 401)
- The agent credential may have been **revoked** on the server
  (`POST /api/v1/endpoints/{agent_id}/revoke`). Re-enroll with a new token.
- Corrupted state file: delete `agent_state.json` in the state dir and re-enroll.
- Check `agent_security_logs` on the server for the `auth_failure` reason.

## No telemetry appearing in the dashboard
- Confirm heartbeats first (Endpoints page shows the host as `online`).
- The Security event-log and network collectors need **Administrator**; without
  it they degrade quietly. Reinstall via `install-service.ps1` (runs as SYSTEM).
- Collectors prime a baseline on first poll — generate new activity (e.g. launch
  a process) and wait one collect+flush cycle (~20–30s).
- Check the agent log for "Collected N events" and "Uploaded N events".
- Server side: `GET /api/v1/endpoints/{agent_id}` returns recent_events.

## Firewall / network problem
- Allow outbound TCP to the server's HTTPS port for `python.exe` /
  `aegisx-agent.exe`.
- Corporate proxy: `requests` honours `HTTPS_PROXY`; set it in the task's
  environment if needed.

## High CPU / memory
- Increase `agent.collect_interval_seconds` / `flush_interval_seconds`.
- Disable noisy collectors you don't need (`collectors.persistence: false`, etc.).
- Heartbeats report the agent's own CPU%/mem% — inspect them on the server
  (`agent_heartbeats`) to confirm the footprint.

## Server-side checks
- `GET /healthz` — DB connectivity.
- `GET /api/v1/endpoints/stats` — enrolled/online/offline counts.
- Backend logs include `agent_enrolled`, `auth_failure`, `agent_pipeline_done`.
- Enrollment/auth/revoke events are in the `agent_security_logs` table.
