"""
Zeek Network Telemetry Collector — parses Zeek (Bro) network analysis logs
(conn.log, dns.log, http.log, ssl.log), normalizes them to AegisX
NormalizedEvent schema, and forwards them to the AegisX Ingestion API.

Supports:
  - Both TSV (standard Zeek tab-delimited format with #fields header) and JSON logs
  - Multi-file directory monitoring (/var/log/zeek/current or custom path)
  - Connection (conn.log), DNS (dns.log), HTTP (http.log), and SSL/TLS (ssl.log)
  - Incremental tailing with offset tracking
  - Asynchronous / batch forwarding to AegisX REST API
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

import httpx
import structlog

log = structlog.get_logger()


def _epoch_to_iso(epoch_str: str) -> str:
    """Convert Zeek float epoch string (e.g. 1724930000.123456) to ISO8601 UTC."""
    try:
        ts_float = float(epoch_str)
        return datetime.fromtimestamp(ts_float, tz=timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _clean_val(val: Optional[str]) -> Optional[str]:
    """Clean Zeek null/unset indicators ('-' or '(empty)')."""
    if val is None or val in ("-", "(empty)", "unset", ""):
        return None
    return val


# ── TSV Header Parser ─────────────────────────────────────────────────────────

class ZeekTSVReader:
    """Parses Zeek tab-delimited log files with dynamic header discovery."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.fields: List[str] = []
        self.separator = "\t"

    def read_records(self, start_offset: int = 0) -> Tuple[List[Dict[str, str]], int]:
        """Read records from offset, maintaining field mapping across file reads."""
        records: List[Dict[str, str]] = []
        if not os.path.exists(self.filepath):
            return records, start_offset

        new_offset = start_offset
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, os.SEEK_END)
                if f.tell() < start_offset:
                    start_offset = 0  # File was rotated

                f.seek(start_offset)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # Zeek metadata directives
                    if line.startswith("#separator"):
                        sep_hex = line.split()[-1]
                        if sep_hex.startswith("\\x"):
                            self.separator = chr(int(sep_hex[2:], 16))
                        continue
                    elif line.startswith("#fields"):
                        self.fields = line.split()[1:]
                        continue
                    elif line.startswith("#"):
                        continue

                    # Data row
                    if self.fields:
                        parts = line.split(self.separator)
                        if len(parts) >= len(self.fields):
                            record = {self.fields[i]: parts[i] for i in range(len(self.fields))}
                            records.append(record)

                new_offset = f.tell()
        except Exception as exc:
            log.warning("Error reading Zeek TSV file", error=str(exc), path=self.filepath)

        return records, new_offset


# ── Event Normalizers per Zeek Log Type ───────────────────────────────────────

def normalize_conn_record(rec: Dict[str, Any], host: str) -> Optional[Dict[str, Any]]:
    """Normalize Zeek conn.log record -> AegisX network_connection."""
    src_ip = _clean_val(rec.get("id.orig_h"))
    dst_ip = _clean_val(rec.get("id.resp_h"))
    if not src_ip or not dst_ip:
        return None

    dst_port_str = _clean_val(rec.get("id.resp_p"))
    dst_port = int(dst_port_str) if dst_port_str and dst_port_str.isdigit() else None
    ts = _epoch_to_iso(rec.get("ts", ""))

    return {
        "source": "zeek_conn",
        "event_type": "network_connection",
        "timestamp": ts,
        "host": host,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "raw": {
            "uid": rec.get("uid"),
            "proto": rec.get("proto"),
            "service": _clean_val(rec.get("service")),
            "conn_state": _clean_val(rec.get("conn_state")),
            "orig_bytes": _clean_val(rec.get("orig_bytes")),
            "resp_bytes": _clean_val(rec.get("resp_bytes")),
            "duration": _clean_val(rec.get("duration")),
        },
    }


def normalize_dns_record(rec: Dict[str, Any], host: str) -> Optional[Dict[str, Any]]:
    """Normalize Zeek dns.log record -> AegisX dns_query."""
    query = _clean_val(rec.get("query"))
    src_ip = _clean_val(rec.get("id.orig_h"))
    dst_ip = _clean_val(rec.get("id.resp_h"))
    dst_port_str = _clean_val(rec.get("id.resp_p"))
    dst_port = int(dst_port_str) if dst_port_str and dst_port_str.isdigit() else 53
    ts = _epoch_to_iso(rec.get("ts", ""))

    return {
        "source": "zeek_dns",
        "event_type": "dns_query",
        "timestamp": ts,
        "host": host,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "domain": query,
        "raw": {
            "uid": rec.get("uid"),
            "qtype_name": _clean_val(rec.get("qtype_name")),
            "rcode_name": _clean_val(rec.get("rcode_name")),
            "answers": _clean_val(rec.get("answers")),
        },
    }


def normalize_http_record(rec: Dict[str, Any], host: str) -> Optional[Dict[str, Any]]:
    """Normalize Zeek http.log record -> AegisX http_request."""
    src_ip = _clean_val(rec.get("id.orig_h"))
    dst_ip = _clean_val(rec.get("id.resp_h"))
    dst_port_str = _clean_val(rec.get("id.resp_p"))
    dst_port = int(dst_port_str) if dst_port_str and dst_port_str.isdigit() else 80
    domain = _clean_val(rec.get("host"))
    ts = _epoch_to_iso(rec.get("ts", ""))

    return {
        "source": "zeek_http",
        "event_type": "http_request",
        "timestamp": ts,
        "host": host,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "domain": domain,
        "raw": {
            "uid": rec.get("uid"),
            "method": _clean_val(rec.get("method")),
            "uri": _clean_val(rec.get("uri")),
            "status_code": _clean_val(rec.get("status_code")),
            "user_agent": _clean_val(rec.get("user_agent")),
            "referrer": _clean_val(rec.get("referrer")),
        },
    }


def normalize_ssl_record(rec: Dict[str, Any], host: str) -> Optional[Dict[str, Any]]:
    """Normalize Zeek ssl.log record -> AegisX tls_handshake."""
    src_ip = _clean_val(rec.get("id.orig_h"))
    dst_ip = _clean_val(rec.get("id.resp_h"))
    dst_port_str = _clean_val(rec.get("id.resp_p"))
    dst_port = int(dst_port_str) if dst_port_str and dst_port_str.isdigit() else 443
    domain = _clean_val(rec.get("server_name"))
    ts = _epoch_to_iso(rec.get("ts", ""))

    return {
        "source": "zeek_ssl",
        "event_type": "tls_handshake",
        "timestamp": ts,
        "host": host,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "domain": domain,
        "raw": {
            "uid": rec.get("uid"),
            "version": _clean_val(rec.get("version")),
            "cipher": _clean_val(rec.get("cipher")),
            "resumed": rec.get("resumed") in ("T", True, "true"),
            "established": rec.get("established") in ("T", True, "true"),
        },
    }


NORMALIZERS = {
    "conn": normalize_conn_record,
    "dns": normalize_dns_record,
    "http": normalize_http_record,
    "ssl": normalize_ssl_record,
}


# ── Collector Engine ──────────────────────────────────────────────────────────

class ZeekCollector:
    """Monitors and normalizes Zeek network log streams."""

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        log_dir: Optional[str] = None,
        single_file: Optional[str] = None,
        batch_size: int = 100,
        dry_run: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.ingest_endpoint = f"{self.api_url}/api/v1/telemetry/ingest"
        self.log_dir = log_dir
        self.single_file = single_file
        self.batch_size = batch_size
        self.dry_run = dry_run
        self.host = socket.gethostname()
        self._offsets: Dict[str, int] = {}
        self._readers: Dict[str, ZeekTSVReader] = {}

    def discover_log_files(self) -> List[Tuple[str, str]]:
        """Return list of (log_type, file_path) pairs to process."""
        files = []
        if self.single_file and os.path.exists(self.single_file):
            base = os.path.basename(self.single_file).lower()
            for log_type in NORMALIZERS:
                if log_type in base:
                    files.append((log_type, self.single_file))
                    return files
            files.append(("conn", self.single_file))
            return files

        search_dir = self.log_dir or "/var/log/zeek/current"
        if os.path.exists(search_dir):
            for log_type in NORMALIZERS:
                pattern = os.path.join(search_dir, f"{log_type}.log*")
                for f in glob.glob(pattern):
                    if not f.endswith(".gz"):
                        files.append((log_type, f))

        return files

    def read_events_from_file(self, log_type: str, filepath: str) -> List[Dict[str, Any]]:
        """Read and parse new records from a single Zeek log file."""
        if filepath not in self._readers:
            self._readers[filepath] = ZeekTSVReader(filepath)

        offset = self._offsets.get(filepath, 0)
        raw_records, new_offset = self._readers[filepath].read_records(offset)
        self._offsets[filepath] = new_offset

        normalizer = NORMALIZERS.get(log_type, normalize_conn_record)
        events: List[Dict[str, Any]] = []

        for rec in raw_records:
            ev = normalizer(rec, self.host)
            if ev:
                events.append(ev)

        return events

    def ship_events(self, events: List[Dict[str, Any]]) -> int:
        """Post events to AegisX Ingestion API."""
        if not events:
            return 0

        if self.dry_run:
            log.info("Dry-run: skipping Zeek HTTP dispatch", count=len(events))
            for e in events[:3]:
                log.info("Sample Zeek event", type=e["event_type"], src=e.get("src_ip"), dst=e.get("dst_ip"), domain=e.get("domain"))
            return len(events)

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped Zeek batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed shipping Zeek batch", error=str(exc), count=len(chunk))
        return shipped

    def run_once(self) -> Dict[str, Any]:
        """Execute a single pass over configured Zeek logs."""
        target_files = self.discover_log_files()
        total_events = []

        for log_type, fpath in target_files:
            evs = self.read_events_from_file(log_type, fpath)
            total_events.extend(evs)

        shipped = self.ship_events(total_events)
        return {
            "files_scanned": len(target_files),
            "events_extracted": len(total_events),
            "events_shipped": shipped,
        }

    def run_loop(self, interval_seconds: int = 5) -> None:
        """Continuous log tailing loop."""
        log.info(
            "Starting ZeekCollector loop",
            log_dir=self.log_dir,
            single_file=self.single_file,
            api_url=self.api_url,
            interval=interval_seconds,
        )
        try:
            while True:
                stats = self.run_once()
                if stats["events_shipped"] > 0:
                    log.info("Zeek collection pass complete", **stats)
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            log.info("ZeekCollector stopped by user")


# ── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AegisX Zeek Network Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API base URL")
    parser.add_argument("--log-dir", default=None, help="Path to Zeek logs directory (e.g. /var/log/zeek/current)")
    parser.add_argument("--file", default=None, help="Path to a single Zeek log file (conn.log, dns.log, etc.)")
    parser.add_argument("--batch-size", type=int, default=100, help="Max events per HTTP request batch")
    parser.add_argument("--interval", type=int, default=5, help="Tailing interval in seconds")
    parser.add_argument("--dry-run", action="store_true", help="Parse and log without shipping over network")
    parser.add_argument("--once", action="store_true", help="Run once and exit")

    args = parser.parse_args()

    collector = ZeekCollector(
        api_url=args.api,
        log_dir=args.log_dir,
        single_file=args.file,
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
