"""
Linux Telemetry Collector — monitors authentication logs (/var/log/auth.log,
/var/log/secure) and /proc process activity, normalizes them to AegisX
NormalizedEvent schema, and forwards them to the AegisX Ingestion API.

Usage:
    python linux_collector.py --api http://localhost:8000 --auth-log /var/log/auth.log --proc-scan
    python linux_collector.py --dry-run --once

Features:
  - SSH successful and failed login parsing (passwords & public keys)
  - Sudo command execution tracking
  - User and group account creation / modification monitoring
  - Periodic /proc process table snapshots
  - Resilient log tailing with file offset checkpointing
  - Batching and asynchronous HTTP forwarding
"""
from __future__ import annotations

import argparse
import glob
import os
import pwd
import re
import socket
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
import structlog

log = structlog.get_logger()

# ── Regex Patterns for Linux Auth Logs ────────────────────────────────────────

# SSH Accepted Login
SSH_ACCEPTED_RE = re.compile(
    r"sshd\[\d+\]: Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# SSH Failed Login (valid or invalid user)
SSH_FAILED_RE = re.compile(
    r"sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# SSH Invalid User Attempt
SSH_INVALID_USER_RE = re.compile(
    r"sshd\[\d+\]: Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# Sudo Command Execution
SUDO_CMD_RE = re.compile(
    r"sudo:\s+(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<cmd>.+)"
)

# User Account Created
USER_ADD_RE = re.compile(
    r"useradd\[\d+\]: new user: name=(?P<user>\S+)|new user: name=(?P<user2>\S+), UID="
)

# Group Modification
GROUP_ADD_RE = re.compile(
    r"groupadd\[\d+\]: new group: name=(?P<group>\S+)|usermod\[\d+\]: add '(?P<user>\S+)' to group '(?P<mod_group>\S+)'"
)

# PAM Session Opened / Closed
PAM_SESSION_RE = re.compile(
    r"pam_unix\((?P<service>[^:]+):session\): session (?P<action>opened|closed) for user (?P<user>\S+)"
)

# Syslog Timestamp parser (e.g. 'Aug 29 22:45:00' or ISO format)
SYSLOG_TS_RE = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.+)$"
)

MONTH_MAP = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _parse_syslog_timestamp(month_str: str, day_str: str, time_str: str) -> str:
    """Convert syslog standard timestamp (without year) to ISO8601 UTC string."""
    now = datetime.now(timezone.utc)
    month = MONTH_MAP.get(month_str, now.month)
    day = int(day_str)
    hour, minute, second = map(int, time_str.split(":"))
    try:
        dt = datetime(now.year, month, day, hour, minute, second, tzinfo=timezone.utc)
        # Year wrap-around check if log is from previous year
        if dt > now:
            dt = datetime(now.year - 1, month, day, hour, minute, second, tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return now.isoformat()


def parse_auth_line(line: str, default_host: str = "") -> Optional[Dict[str, Any]]:
    """
    Parse a single line from /var/log/auth.log or /var/log/secure.
    Returns NormalizedEvent dict or None if line is not security-relevant.
    """
    line = line.strip()
    if not line:
        return None

    timestamp = datetime.now(timezone.utc).isoformat()
    host = default_host or socket.gethostname()
    message = line

    syslog_match = SYSLOG_TS_RE.match(line)
    if syslog_match:
        m = syslog_match.groupdict()
        timestamp = _parse_syslog_timestamp(m["month"], m["day"], m["time"])
        host = m["host"]
        message = m["rest"]

    # 1. SSH Accepted
    m_ssh_acc = SSH_ACCEPTED_RE.search(message)
    if m_ssh_acc:
        d = m_ssh_acc.groupdict()
        return {
            "source": "linux_auth",
            "event_type": "user_logon",
            "timestamp": timestamp,
            "host": host,
            "user": d["user"],
            "src_ip": d["ip"],
            "dst_port": int(d["port"]),
            "raw": {"message": line, "protocol": "ssh", "auth_result": "success"},
        }

    # 2. SSH Failed
    m_ssh_fail = SSH_FAILED_RE.search(message)
    if m_ssh_fail:
        d = m_ssh_fail.groupdict()
        return {
            "source": "linux_auth",
            "event_type": "user_logon_failed",
            "timestamp": timestamp,
            "host": host,
            "user": d["user"],
            "src_ip": d["ip"],
            "dst_port": int(d["port"]),
            "raw": {"message": line, "protocol": "ssh", "auth_result": "failed"},
        }

    # 3. SSH Invalid User
    m_ssh_inv = SSH_INVALID_USER_RE.search(message)
    if m_ssh_inv:
        d = m_ssh_inv.groupdict()
        return {
            "source": "linux_auth",
            "event_type": "user_logon_failed",
            "timestamp": timestamp,
            "host": host,
            "user": d["user"],
            "src_ip": d["ip"],
            "dst_port": int(d["port"]),
            "raw": {"message": line, "protocol": "ssh", "invalid_user": True},
        }

    # 4. Sudo Command Execution
    m_sudo = SUDO_CMD_RE.search(message)
    if m_sudo:
        d = m_sudo.groupdict()
        cmd = d["cmd"].strip()
        proc_name = cmd.split()[0] if cmd else "sudo"
        return {
            "source": "linux_sudo",
            "event_type": "process_creation",
            "timestamp": timestamp,
            "host": host,
            "user": d["user"],
            "process": proc_name,
            "command_line": f"sudo (as {d['target_user']}) {cmd}",
            "raw": {"message": line, "target_user": d["target_user"], "command": cmd},
        }

    # 5. User Account Created
    m_useradd = USER_ADD_RE.search(message)
    if m_useradd:
        user = m_useradd.group("user") or m_useradd.group("user2")
        return {
            "source": "linux_auth",
            "event_type": "user_account_created",
            "timestamp": timestamp,
            "host": host,
            "user": user,
            "raw": {"message": line},
        }

    # 6. Group Modification
    m_group = GROUP_ADD_RE.search(message)
    if m_group:
        return {
            "source": "linux_auth",
            "event_type": "user_account_change",
            "timestamp": timestamp,
            "host": host,
            "user": m_group.group("user"),
            "raw": {"message": line, "group": m_group.group("group") or m_group.group("mod_group")},
        }

    # 7. PAM Session
    m_pam = PAM_SESSION_RE.search(message)
    if m_pam:
        d = m_pam.groupdict()
        ev_type = "user_logon" if d["action"] == "opened" else "user_logoff"
        return {
            "source": f"linux_pam_{d['service']}",
            "event_type": ev_type,
            "timestamp": timestamp,
            "host": host,
            "user": d["user"],
            "raw": {"message": line, "service": d["service"], "action": d["action"]},
        }

    return None


# ── Process Telemetry Scanner (/proc or ps) ────────────────────────────────────

def scan_linux_processes(host: str = "") -> List[Dict[str, Any]]:
    """
    Read active processes from /proc or fall back to ps command.
    Returns list of NormalizedEvent process_creation dicts.
    """
    events: List[Dict[str, Any]] = []
    host = host or socket.gethostname()
    now_iso = datetime.now(timezone.utc).isoformat()

    if os.path.exists("/proc"):
        for pid_dir in glob.glob("/proc/[0-9]*"):
            try:
                pid = int(os.path.basename(pid_dir))
                cmdline_file = os.path.join(pid_dir, "cmdline")
                stat_file = os.path.join(pid_dir, "stat")
                status_file = os.path.join(pid_dir, "status")

                if not os.path.exists(cmdline_file):
                    continue

                with open(cmdline_file, "rb") as f:
                    cmd_bytes = f.read()
                cmdline = cmd_bytes.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
                if not cmdline:
                    continue

                # Process name
                proc_name = cmdline.split()[0]

                # User extraction via UID
                user_name = "unknown"
                ppid = None
                if os.path.exists(status_file):
                    with open(status_file, "r", errors="ignore") as f:
                        for s_line in f:
                            if s_line.startswith("Uid:"):
                                uid = int(s_line.split()[1])
                                try:
                                    user_name = pwd.getpwuid(uid).pw_name
                                except Exception:
                                    user_name = str(uid)
                            elif s_line.startswith("PPid:"):
                                ppid = int(s_line.split()[1])

                events.append({
                    "source": "linux_proc",
                    "event_type": "process_creation",
                    "timestamp": now_iso,
                    "host": host,
                    "user": user_name,
                    "process": proc_name,
                    "command_line": cmdline,
                    "raw": {"pid": pid, "ppid": ppid},
                })
            except (PermissionError, FileNotFoundError, ProcessLookupError):
                continue
            except Exception:
                continue

    return events


# ── Collector Engine ──────────────────────────────────────────────────────────

class LinuxCollector:
    """
    Tails Linux authentication logs and captures process snapshots,
    transmitting batches to the AegisX ingestion endpoint.
    """

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        auth_log_path: Optional[str] = None,
        enable_proc_scan: bool = True,
        batch_size: int = 50,
        dry_run: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.ingest_endpoint = f"{self.api_url}/api/v1/telemetry/ingest"
        self.auth_log_path = auth_log_path or self._auto_detect_auth_log()
        self.enable_proc_scan = enable_proc_scan
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.host = socket.gethostname()
        self._file_offset = 0

    def _auto_detect_auth_log(self) -> Optional[str]:
        candidates = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]
        for c in candidates:
            if os.path.exists(c) and os.access(c, os.R_OK):
                return c
        return None

    def read_new_log_events(self) -> List[Dict[str, Any]]:
        """Read newly appended lines from the log file since last offset."""
        if not self.auth_log_path or not os.path.exists(self.auth_log_path):
            return []

        events = []
        try:
            with open(self.auth_log_path, "r", encoding="utf-8", errors="ignore") as f:
                # Handle log rotation (file size shrunk)
                f.seek(0, os.SEEK_END)
                cur_size = f.tell()
                if cur_size < self._file_offset:
                    self._file_offset = 0

                f.seek(self._file_offset)
                lines = f.readlines()
                self._file_offset = f.tell()

                for line in lines:
                    ev = parse_auth_line(line, default_host=self.host)
                    if ev:
                        events.append(ev)
        except Exception as exc:
            log.warning("Failed reading auth log", error=str(exc), path=self.auth_log_path)

        return events

    def ship_events(self, events: List[Dict[str, Any]]) -> int:
        """Send events to AegisX API in batches."""
        if not events:
            return 0

        if self.dry_run:
            log.info("Dry-run: skipping HTTP dispatch", count=len(events))
            for e in events[:3]:
                log.info("Sample event", event_type=e["event_type"], user=e.get("user"), host=e.get("host"))
            return len(events)

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped event batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed to ship event batch", error=str(exc), count=len(chunk))
        return shipped

    def run_once(self) -> Dict[str, int]:
        """Execute a single collection cycle."""
        auth_events = self.read_new_log_events()
        proc_events = scan_linux_processes(self.host) if self.enable_proc_scan else []

        all_events = auth_events + proc_events
        shipped = self.ship_events(all_events)

        return {
            "auth_events_found": len(auth_events),
            "proc_events_found": len(proc_events),
            "events_shipped": shipped,
        }

    def run_loop(self, interval_seconds: int = 5) -> None:
        """Continuously collect and ship telemetry."""
        log.info(
            "Starting LinuxCollector loop",
            auth_log=self.auth_log_path,
            proc_scan=self.enable_proc_scan,
            api_url=self.api_url,
            interval=interval_seconds,
        )
        try:
            while True:
                stats = self.run_once()
                if stats["events_shipped"] > 0:
                    log.info("Collection cycle finished", **stats)
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            log.info("LinuxCollector stopped by user")


# ── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AegisX Linux Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API base URL")
    parser.add_argument("--auth-log", default=None, help="Path to auth.log / secure")
    parser.add_argument("--proc-scan", action="store_true", default=True, help="Scan /proc processes")
    parser.add_argument("--no-proc-scan", dest="proc_scan", action="store_false")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval in seconds")
    parser.add_argument("--batch-size", type=int, default=50, help="Max events per HTTP batch")
    parser.add_argument("--dry-run", action="store_true", help="Print parsed events without shipping")
    parser.add_argument("--once", action="store_true", help="Run a single pass and exit")

    args = parser.parse_args()

    collector = LinuxCollector(
        api_url=args.api,
        auth_log_path=args.auth_log,
        enable_proc_scan=args.proc_scan,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    if args.once:
        stats = collector.run_once()
        print(f"Collection complete: {stats}")
    else:
        collector.run_loop(interval_seconds=args.interval)


if __name__ == "__main__":
    main()
