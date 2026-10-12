# AegisX Endpoint Agent

A secure, lightweight, Windows-first endpoint agent that enrolls with the AegisX
SOC server and streams security telemetry (process, network, authentication, and
persistence events) over an outbound HTTPS connection.

The agent makes only **outbound** connections to the server, so client PCs can
report from outside the corporate LAN without the server needing to reach in.

```
 collectors ──► normalize ──► bounded buffer ──► HTTPS transport ──► AegisX server
   (psutil / wevtutil / winreg)      (retry + offline queue)     /api/v1/endpoints/*
```

## Layout

```
aegisx-agent/
├── src/aegisx_agent/
│   ├── collectors/            process / network / eventlog / persistence
│   ├── config.py              YAML + env configuration
│   ├── state.py               secure identity + credential store
│   ├── buffer.py              bounded, disk-backed offline queue
│   ├── transport.py           HTTPS client with retry/backoff
│   ├── enrollment.py          one-time token → agent identity
│   ├── health.py              self CPU/memory metrics
│   ├── normalize.py           collector event → server schema
│   ├── agent.py               main runtime loop
│   └── main.py                CLI entry point (python -m aegisx_agent)
├── config/agent.example.yaml
├── scripts/
│   ├── enroll.ps1  run-agent.ps1  install-service.ps1  status.ps1   (Windows)
│   ├── enroll.sh   run-agent.sh                                     (Linux/macOS)
│   ├── install-systemd.sh                                           (Linux startup)
│   └── install-launchd.sh                                           (macOS startup)
├── tests/
└── requirements.txt
```

## Quick start

Get a one-time enrollment token from the dashboard (**Endpoints → + Add Endpoint**)
or `POST /api/v1/endpoints/enroll-tokens`.

**Windows**
```powershell
cd aegisx-agent
Copy-Item config\agent.example.yaml config\agent.yaml   # then set server.url

.\scripts\enroll.ps1 -Token "PASTE-TOKEN" -Server "https://your-aegisx:8008" -Insecure
.\scripts\run-agent.ps1
.\scripts\install-service.ps1        # auto-start at boot (elevated)
```

**Linux / macOS**
```bash
cd aegisx-agent
cp config/agent.example.yaml config/agent.yaml          # then set server.url
chmod +x scripts/*.sh

./scripts/enroll.sh --token "PASTE-TOKEN" --server "https://your-aegisx:8008" --insecure
./scripts/run-agent.sh
sudo ./scripts/install-systemd.sh    # Linux auto-start
sudo ./scripts/install-launchd.sh    # macOS auto-start
```

`-Insecure` / `--insecure` accepts a self-signed server certificate (lab/demo
only). Full walkthrough: [`SETUP.md`](../../SETUP.md).

## What it collects

| Collector    | Source                              | Events |
|--------------|-------------------------------------|--------|
| process      | `psutil` snapshot diff              | `process_creation` (name, path, PID, parent, command line) |
| network      | `psutil.net_connections`            | `network_connection` (dst IP/port, process) — metadata only, never packets |
| eventlog     | `wevtutil` Security channel (Win)   | `authentication` / `user_account_change` (4624/4625/4634/4672/4720/4726/4740) |
| persistence  | `winreg` Run keys + `schtasks` (Win)| `persistence` (newly added autoruns / scheduled tasks) |

Privacy: the agent collects only security-relevant metadata. It does **not**
capture packet payloads, file contents, passwords, keystrokes, or browser data.
The logged-in username is sent only if `agent.report_username: true`.

## Security notes

- All server traffic is HTTPS; plain HTTP to a non-local server is refused.
- The per-agent credential is stored (as returned by the server) under the state
  directory and is never written to logs. On Windows, tighten the ACL of
  `%PROGRAMDATA%\AegisX\agent` to SYSTEM/Administrators only.
- The enrollment token is single-use server-side and is cleared from memory after
  a successful enrollment.
- The offline buffer is bounded (`agent.buffer_max_events`) so disk cannot grow
  without limit.

## Tests

```powershell
python -m pytest        # from the aegisx-agent directory
```
