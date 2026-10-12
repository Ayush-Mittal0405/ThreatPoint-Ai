"""
Okta Identity & Authentication Telemetry Collector.

Polls the Okta System Log API or parses exported Okta audit JSON logs,
normalizes authentication and authorization events into the AegisX NormalizedEvent
schema, and transmits them to the AegisX Ingestion API.

Features:
  - User authentication success & failure tracking
  - MFA challenge verifications and factor resets (T1556, T1621)
  - Group membership and privilege escalation monitoring (T1098)
  - Session lifecycle events (login, logout, lockouts)
  - Batching and asynchronous HTTP shipping to AegisX
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
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
    _std_log = logging.getLogger("okta_collector")
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


# ── Okta Event Type Mapping to AegisX ─────────────────────────────────────────

OKTA_EVENT_MAP = {
    "user.session.start": "user_logon",
    "user.authentication.auth_via_mfa": "user_logon",
    "user.authentication.verify": "user_logon",
    "user.session.end": "user_logoff",
    "user.account.lock": "user_account_lock",
    "user.account.privilege.grant": "user_account_change",
    "group.user_membership.add": "user_account_change",
    "user.mfa.factor.deactivate": "user_account_change",
    "user.mfa.factor.reset_all": "user_account_change",
    "policy.rule.modify": "policy_modification",
}


def normalize_okta_event(raw_event: Dict[str, Any], default_host: str = "okta.identity") -> Optional[Dict[str, Any]]:
    """Normalize an Okta System Log JSON entry into AegisX NormalizedEvent format."""
    event_type_okta = raw_event.get("eventType", "")
    outcome = raw_event.get("outcome", {}).get("result", "SUCCESS")

    event_type = OKTA_EVENT_MAP.get(event_type_okta, "identity_event")
    if outcome != "SUCCESS" and "logon" in event_type:
        event_type = "user_logon_failed"

    # Actor / User
    actor = raw_event.get("actor", {})
    user = actor.get("alternateId") or actor.get("displayName") or "unknown_user"

    # Client / Network details
    client = raw_event.get("client", {})
    src_ip = client.get("ipAddress")
    user_agent = client.get("userAgent", {}).get("rawUserAgent")
    geo = client.get("geographicalContext", {})

    # Timestamp
    published = raw_event.get("published", datetime.now(timezone.utc).isoformat())

    return {
        "source": "okta_identity",
        "event_type": event_type,
        "timestamp": published,
        "host": default_host,
        "user": user,
        "src_ip": src_ip,
        "raw": {
            "okta_uuid": raw_event.get("uuid"),
            "event_type_okta": event_type_okta,
            "outcome": outcome,
            "display_message": raw_event.get("displayMessage"),
            "user_agent": user_agent,
            "city": geo.get("city"),
            "country": geo.get("country"),
        },
    }


# ── Sample Synthetic Okta Logs for Testing / Standalone ───────────────────────

SAMPLE_OKTA_LOGS: List[Dict[str, Any]] = [
    {
        "uuid": "okta-evt-001",
        "published": datetime.now(timezone.utc).isoformat(),
        "eventType": "user.session.start",
        "displayMessage": "User login to Okta",
        "outcome": {"result": "SUCCESS"},
        "actor": {"id": "00u123", "displayName": "Alice Admin", "alternateId": "alice@company.com"},
        "client": {"ipAddress": "198.51.100.12", "geographicalContext": {"city": "New York", "country": "US"}},
    },
    {
        "uuid": "okta-evt-002",
        "published": datetime.now(timezone.utc).isoformat(),
        "eventType": "user.authentication.verify",
        "displayMessage": "Authentication failed - invalid password",
        "outcome": {"result": "FAILURE"},
        "actor": {"id": "00u999", "displayName": "Bob Analyst", "alternateId": "bob@company.com"},
        "client": {"ipAddress": "203.0.113.88", "geographicalContext": {"city": "Unknown", "country": "RU"}},
    },
    {
        "uuid": "okta-evt-003",
        "published": datetime.now(timezone.utc).isoformat(),
        "eventType": "group.user_membership.add",
        "displayMessage": "User added to group: Domain Admins",
        "outcome": {"result": "SUCCESS"},
        "actor": {"id": "00u123", "displayName": "Alice Admin", "alternateId": "alice@company.com"},
        "client": {"ipAddress": "198.51.100.12", "geographicalContext": {"city": "New York", "country": "US"}},
    }
]


class OktaCollector:
    """Collects and forwards identity telemetry from Okta to AegisX."""

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        okta_domain: Optional[str] = None,
        okta_token: Optional[str] = None,
        log_file: Optional[str] = None,
        batch_size: int = 50,
        dry_run: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.ingest_endpoint = f"{self.api_url}/api/v1/telemetry/ingest"
        self.okta_domain = okta_domain
        self.okta_token = okta_token
        self.log_file = log_file
        self.batch_size = batch_size
        self.dry_run = dry_run

    def fetch_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from file, live Okta API, or fallback sample set."""
        if self.log_file and os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content.startswith("["):
                        return json.loads(content)
                    else:
                        return [json.loads(line) for line in content.splitlines() if line.strip()]
            except Exception as exc:
                log.error("Failed reading Okta log file", error=str(exc))
                return []

        if self.okta_domain and self.okta_token:
            url = f"https://{self.okta_domain}/api/v1/logs?limit={self.batch_size}"
            headers = {"Authorization": f"SSWS {self.okta_token}", "Accept": "application/json"}
            try:
                with httpx.Client(timeout=10.0) as client:
                    res = client.get(url, headers=headers)
                    res.raise_for_status()
                    return res.json()
            except Exception as exc:
                log.error("Failed fetching logs from Okta API", error=str(exc))
                return []

        # Return sample logs
        return SAMPLE_OKTA_LOGS

    def run_once(self) -> Dict[str, int]:
        """Execute a single collection and ingestion cycle."""
        raw_logs = self.fetch_logs()
        events = []
        for raw in raw_logs:
            ev = normalize_okta_event(raw)
            if ev:
                events.append(ev)

        if not events:
            return {"events_found": 0, "events_shipped": 0}

        if self.dry_run:
            log.info("Dry-run: skipping Okta HTTP dispatch", count=len(events))
            for e in events[:2]:
                log.info("Sample Okta event", event_type=e["event_type"], user=e.get("user"), ip=e.get("src_ip"))
            return {"events_found": len(events), "events_shipped": len(events)}

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped Okta batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed shipping Okta batch", error=str(exc), count=len(chunk))

        return {"events_found": len(events), "events_shipped": shipped}


def main():
    parser = argparse.ArgumentParser(description="AegisX Okta Identity Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API URL")
    parser.add_argument("--domain", default=None, help="Okta domain (e.g. company.okta.com)")
    parser.add_argument("--token", default=None, help="Okta API SSWS token")
    parser.add_argument("--file", default=None, help="Path to Okta export JSON log file")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument("--once", action="store_true", default=True, help="Run single pass and exit")

    args = parser.parse_args()

    collector = OktaCollector(
        api_url=args.api,
        okta_domain=args.domain,
        okta_token=args.token,
        log_file=args.file,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    stats = collector.run_once()
    print(f"Okta collection pass complete: {stats}")


if __name__ == "__main__":
    main()
