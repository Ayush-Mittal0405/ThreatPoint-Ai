"""
Network collector — emits `network_connection` events for new outbound TCP
connections. Metadata only (src/dst IP, dst port, protocol, owning process);
packet contents are never captured.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

from .base import Collector

try:
    import psutil  # type: ignore
    _HAVE_PSUTIL = True
except Exception:  # pragma: no cover
    _HAVE_PSUTIL = False


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip == "::1" or ip == "0.0.0.0" or ip == "::"


class NetworkCollector(Collector):
    name = "network"
    supported = _HAVE_PSUTIL

    def __init__(self, logger=None):
        super().__init__(logger)
        self._seen: Set[Tuple] = set()
        self._primed = False

    def collect(self) -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        current: Set[Tuple] = set()

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Requires elevation on some platforms; degrade quietly.
            return []

        for c in conns:
            if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
                continue
            r_ip = c.raddr.ip
            r_port = c.raddr.port
            if _is_loopback(r_ip):
                continue
            key = (c.pid, r_ip, r_port, c.laddr.port if c.laddr else None)
            current.add(key)
            if key in self._seen:
                continue
            if not self._primed:
                continue

            proc_name = None
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = None

            events.append({
                "event_type": "network_connection",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": c.laddr.ip if c.laddr else None,
                "dst_ip": r_ip,
                "dst_port": r_port,
                "process": proc_name,
                "raw": {"proto": "tcp", "pid": c.pid, "src_port": c.laddr.port if c.laddr else None},
            })

        self._seen = current
        self._primed = True
        return events
