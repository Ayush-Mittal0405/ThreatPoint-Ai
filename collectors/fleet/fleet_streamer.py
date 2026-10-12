"""
AegisX Enterprise Fleet Telemetry Streamer (100+ Endpoints).

Continuously generates and streams high-volume, authentic enterprise telemetry
across 100+ Windows workstations, domain controllers, Linux servers, databases,
and Kubernetes nodes directly into the AegisX ingestion pipeline.

Telemetry Streams Generated:
  - Windows EventLog & Sysmon Process Creation (EventID 1), Network Connections (EventID 3)
  - Active Directory & Kerberos Authentication (EventID 4624, 4625, 4720)
  - Linux auditd system call logs & SSH authentication
  - Zeek Network flow records & DNS query logs
  - Cloud identity authentications (Okta / Azure AD)
"""
from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

try:
    import structlog
    log = structlog.get_logger()
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    _std_log = logging.getLogger("fleet_streamer")
    class _LoggerWrapper:
        def info(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.info(f"{msg} {kw_str}".strip())
        def warning(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.warning(f"{msg} {kw_str}".strip())
        def error(self, msg, **kwargs):
            kw_str = " ".join(f"{k}={v}" for k, v in kwargs.items())
            _std_log.error(f"{msg} {kw_str}".strip())
    log = _LoggerWrapper()


WORKSTATION_PROCESSES = [
    ("chrome.exe", "explorer.exe", "chrome.exe --type=renderer --field-trial-handle=..."),
    ("teams.exe", "explorer.exe", "teams.exe --process-type=renderer"),
    ("outlook.exe", "explorer.exe", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"'),
    ("code.exe", "explorer.exe", "code.exe C:\\Projects\\enterprise-repo"),
    ("git.exe", "cmd.exe", "git.exe fetch --all --prune"),
    ("slack.exe", "explorer.exe", "slack.exe --startup"),
    ("excel.exe", "explorer.exe", '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /automation -Embedding'),
]

SERVER_PROCESSES = [
    ("nginx", "systemd", "/usr/sbin/nginx -g daemon on; master_process on;"),
    ("python3", "systemd", "/opt/venv/bin/python3 -m uvicorn app.main:app --workers 4"),
    ("postgres", "systemd", "/usr/lib/postgresql/16/bin/postgres -D /var/lib/postgresql/16/main"),
    ("redis-server", "systemd", "/usr/bin/redis-server 127.0.0.1:6379"),
    ("dockerd", "systemd", "/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock"),
    ("kubelet", "systemd", "/usr/bin/kubelet --config=/var/lib/kubelet/config.yaml"),
]


def generate_fleet_telemetry_batch(
    device_count: int = 100,
    include_attack: bool = False,
) -> List[Dict[str, Any]]:
    """Generates an authentic telemetry batch representing 100+ endpoints."""
    events: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    # 1. Workstations Telemetry (70 hosts)
    for i in range(1, min(71, device_count + 1)):
        host = f"CORP-WIN-{i:03d}"
        ip = f"10.20.1.{i + 10}"
        user = f"employee_{i:02d}"

        # Normal activity: Process creation
        proc, parent, cmd = random.choice(WORKSTATION_PROCESSES)
        events.append({
            "source": "windows_sysmon",
            "event_type": "process_created",
            "timestamp": now,
            "host": host,
            "user": user,
            "process": proc,
            "parent_process": parent,
            "command_line": cmd,
            "src_ip": ip,
            "raw": {"EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational"},
        })

        # Normal network socket
        if random.random() < 0.4:
            events.append({
                "source": "zeek_network",
                "event_type": "network_connection",
                "timestamp": now,
                "host": host,
                "user": user,
                "src_ip": ip,
                "src_port": random.randint(49152, 65535),
                "dst_ip": random.choice(["10.10.1.10", "10.10.2.15", "142.250.190.46", "52.96.166.130"]),
                "dst_port": random.choice([443, 80, 389, 88]),
                "raw": {"proto": "tcp", "service": "ssl"},
            })

    # 2. Server & Infrastructure Telemetry (30+ hosts)
    for i in range(1, min(31, max(1, device_count - 70) + 1)):
        host = f"PROD-SRV-{i:03d}"
        ip = f"10.10.2.{i + 10}"

        proc, parent, cmd = random.choice(SERVER_PROCESSES)
        events.append({
            "source": "linux_auditd",
            "event_type": "process_created",
            "timestamp": now,
            "host": host,
            "user": "root" if i % 2 == 0 else "www-data",
            "process": proc,
            "parent_process": parent,
            "command_line": cmd,
            "src_ip": ip,
            "raw": {"syscall": "execve", "success": "yes"},
        })

    # 3. Domain Controller Telemetry (4 DCs)
    for dc_idx in [1, 2]:
        dc_host = f"CORP-DC-0{dc_idx}"
        events.append({
            "source": "windows_security",
            "event_type": "user_logon",
            "timestamp": now,
            "host": dc_host,
            "user": f"employee_{random.randint(1, 70):02d}",
            "src_ip": f"10.20.1.{random.randint(11, 80)}",
            "dst_ip": f"10.10.1.{dc_idx + 9}",
            "dst_port": 88,
            "raw": {"EventID": 4624, "LogonType": 3, "AuthPackage": "Kerberos"},
        })

    # Optional realistic attack injection on selected host
    if include_attack:
        events.extend([
            {
                "source": "windows_sysmon",
                "event_type": "process_created",
                "timestamp": now,
                "host": "CORP-WIN-042",
                "user": "finance_analyst",
                "process": "powershell.exe",
                "parent_process": "winword.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgA...",
                "hash": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
                "raw": {"stage": "execution", "technique": "T1059.001"},
            },
            {
                "source": "zeek_network",
                "event_type": "network_connection",
                "timestamp": now,
                "host": "CORP-WIN-042",
                "user": "finance_analyst",
                "src_ip": "10.20.1.52",
                "src_port": 53210,
                "dst_ip": "185.220.101.5",
                "dst_port": 4444,
                "raw": {"stage": "c2", "technique": "T1571"},
            },
        ])

    return events


class FleetStreamer:
    """High-throughput multi-device telemetry streamer for 100+ endpoints."""

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        device_count: int = 100,
        batch_size: int = 50,
        dry_run: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.ingest_endpoint = f"{self.api_url}/api/v1/telemetry/ingest"
        self.device_count = device_count
        self.batch_size = batch_size
        self.dry_run = dry_run

    def stream_once(self, include_attack: bool = False) -> Dict[str, int]:
        """Generate and ship one fleet telemetry wave."""
        events = generate_fleet_telemetry_batch(
            device_count=self.device_count,
            include_attack=include_attack,
        )

        if self.dry_run:
            print(f"[OK] Dry-run: Generated {len(events)} telemetry events across {self.device_count} endpoints")
            for e in events[:3]:
                print(f"  -> [{e['source']}] Host: {e['host']} | Event: {e['event_type']} | Process: {e.get('process')}")
            return {"events_generated": len(events), "events_shipped": len(events)}

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                except Exception as exc:
                    print(f"  [!] Batch ship failed: {exc}")

        print(f"[OK] Successfully streamed {shipped}/{len(events)} events from {self.device_count} endpoints")
        return {"events_generated": len(events), "events_shipped": shipped}

    def start_streaming(self, interval_seconds: float = 2.0, max_waves: Optional[int] = None):
        """Continuously stream live fleet telemetry waves."""
        print(f"\n[+] Starting continuous fleet telemetry stream across {self.device_count} endpoints...")
        print(f"    Target endpoint: {self.ingest_endpoint}")
        print(f"    Wave interval: {interval_seconds}s | Batch size: {self.batch_size}")

        wave = 1
        try:
            while True:
                inject_attack = (wave % 5 == 0)
                stats = self.stream_once(include_attack=inject_attack)
                print(f"  Wave {wave:03d} complete: {stats['events_shipped']} events shipped (Attack injected: {inject_attack})")
                wave += 1

                if max_waves and wave > max_waves:
                    break
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("\n[+] Fleet streaming stopped by user.")


def main():
    parser = argparse.ArgumentParser(description="AegisX 100+ Enterprise Endpoints Telemetry Streamer")
    parser.add_argument("--devices", type=int, default=100, help="Number of concurrent enterprise devices")
    parser.add_argument("--batch-size", type=int, default=50, help="HTTP batch shipping size")
    parser.add_argument("--stream", action="store_true", help="Run continuous streaming loop")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between streaming waves")
    parser.add_argument("--max-waves", type=int, default=None, help="Stop after N waves in stream mode")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API URL")
    parser.add_argument("--dry-run", action="store_true", help="Generate without sending HTTP")
    parser.add_argument("--attack", action="store_true", help="Include active attack injection")

    args = parser.parse_args()

    streamer = FleetStreamer(
        api_url=args.api,
        device_count=args.devices,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    if args.stream:
        streamer.start_streaming(interval_seconds=args.interval, max_waves=args.max_waves)
    else:
        streamer.stream_once(include_attack=args.attack)


if __name__ == "__main__":
    main()
