# Endpoint Telemetry Reference

What the AegisX Windows agent collects, how it maps to the server's normalized
event model, and the privacy boundaries. Matches the collectors in
[`aegisx-agent/src/aegisx_agent/collectors/`](../aegisx-agent/src/aegisx_agent/collectors).

## Collectors

| Collector | Module | Mechanism | Platform |
|---|---|---|---|
| Process | `process_collector.py` | `psutil` snapshot diff (new PIDs) | all |
| Network | `network_collector.py` | `psutil.net_connections` (new outbound ESTABLISHED) | all |
| Auth / Event log | `eventlog_collector.py` | `wevtutil` Security channel | Windows |
| Persistence | `persistence_collector.py` | `winreg` Run keys + `schtasks` | Windows |

All collectors:
- prime a baseline on first poll (no backfill flood), then emit only **new**
  activity on subsequent polls;
- are wrapped in `safe_collect()` so a collector error can never crash the agent;
- are event-diff based — no full-disk scans, no packet capture.

## Event types → server model

Each collected event is normalized (client-side `normalize.py`, then server-side
`NormalizationService`) into a `NormalizedEvent` row. Fields used:
`agent_id, timestamp, event_type, severity, host, user, process, parent_process,
command_line, file_path, hash_md5, hash_sha256, src_ip, dst_ip, dst_port,
domain, raw`.

### Process — `process_creation`
- `process` (name), `file_path` (exe), `parent_process`, `command_line`
  (if `agent.report ... ` enabled), `user`, `raw.pid`, `raw.ppid`.
- Feeds rules: Office→scripting-host, Encoded PowerShell, Suspicious path.

Relationship the correlation engine can reconstruct:
```
WINWORD.EXE → powershell.exe → suspicious-child.exe
```

### Network — `network_connection`
- `src_ip`, `dst_ip`, `dst_port`, owning `process`, `raw.proto=tcp`.
- **Metadata only** — packet contents are never captured.
- Feeds rule: Suspicious outbound C2 port (4444/4445/8443/9001/1337/31337…).

### Authentication / account — `authentication`, `user_account_change`
From Windows Security event IDs:
| Event ID | Meaning | Mapped type / severity |
|---|---|---|
| 4624 | Successful logon | authentication / info |
| 4625 | Failed logon | authentication / warning |
| 4634, 4647 | Logoff | authentication / info |
| 4672 | Special privileges assigned | authentication / info |
| 4720 | Account created | user_account_change / warning |
| 4726 | Account deleted | user_account_change / warning |
| 4740 | Account lockout | authentication / warning |
- Fields: `user` (TargetUserName), `src_ip` (IpAddress), `raw.logon_type`,
  `raw.windows_event_id`.
- Failed-logon bursts are the basis for brute-force correlation.

### Persistence — `persistence`
- Newly-added registry autoruns (HKLM/HKCU `...\Run`, `...\RunOnce`) and newly
  created scheduled tasks.
- Fields: `process`/`file_path` (value/target), `raw.mechanism`
  (`registry_run_key` | `scheduled_task`), `raw.location`.
- Only *new* entries are reported (the security-relevant signal).

## Privacy & data minimization

The agent collects security-relevant metadata only. It does **not** collect:
- packet payloads or full network captures;
- file contents or document bodies;
- passwords, private keys, tokens, or browser cookies/history;
- keystrokes or screen contents.

The logged-in `username` is sent only when `agent.report_username: true`
(default **false**). The per-agent credential is stored locally and never
transmitted in telemetry or written to logs.

## Bounded resource usage

- Offline events are held in a **bounded** queue (`agent.buffer_max_events`,
  default 10 000); when full, the oldest events are dropped and a drop counter is
  tracked. Disk cannot grow without limit.
- Heartbeats report the agent's own CPU%/memory% and queue depth so the SOC can
  confirm the agent stays lightweight.
- Poll/flush/heartbeat cadences are configurable.
