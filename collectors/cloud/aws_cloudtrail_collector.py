"""
AWS CloudTrail Telemetry Collector.

Collects AWS CloudTrail JSON events (IAM privilege escalation, console logins,
security group modifications, S3 bucket permission changes, and logging tampering),
normalizes them into the AegisX NormalizedEvent schema, and forwards them to the API.

Targeted MITRE ATT&CK Cloud Techniques:
  - T1078.004: Valid Accounts: Cloud Accounts
  - T1098: Account Manipulation (IAM AttachUserPolicy, CreateAccessKey)
  - T1562.008: Impair Defenses: Disable Cloud Logs (StopLogging, DeleteTrail)
  - T1530: Data from Cloud Storage (S3 policy modification)
"""
from __future__ import annotations

import argparse
import json
import os
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
    _std_log = logging.getLogger("cloudtrail_collector")
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


CLOUDTRAIL_EVENT_MAP = {
    "ConsoleLogin": "user_logon",
    "CreateUser": "user_account_change",
    "DeleteUser": "user_account_change",
    "AttachUserPolicy": "user_account_change",
    "AttachRolePolicy": "user_account_change",
    "PutUserPolicy": "user_account_change",
    "CreateAccessKey": "user_account_change",
    "AuthorizeSecurityGroupIngress": "network_policy_change",
    "RevokeSecurityGroupIngress": "network_policy_change",
    "AuthorizeSecurityGroupEgress": "network_policy_change",
    "PutBucketPolicy": "cloud_storage_event",
    "PutBucketAcl": "cloud_storage_event",
    "DeleteBucket": "cloud_storage_event",
    "StopLogging": "defense_evasion_cloud",
    "DeleteTrail": "defense_evasion_cloud",
}


def normalize_cloudtrail_event(raw: Dict[str, Any], default_host: str = "aws.cloudtrail") -> Optional[Dict[str, Any]]:
    """Normalize a CloudTrail record into AegisX NormalizedEvent format."""
    event_name = raw.get("eventName", "")
    event_time = raw.get("eventTime", datetime.now(timezone.utc).isoformat())

    # User / Identity
    user_identity = raw.get("userIdentity", {})
    user = (
        user_identity.get("userName")
        or user_identity.get("principalId")
        or user_identity.get("arn", "").split("/")[-1]
        or "aws_iam_user"
    )

    src_ip = raw.get("sourceIPAddress")
    user_agent = raw.get("userAgent")
    error_code = raw.get("errorCode")

    event_type = CLOUDTRAIL_EVENT_MAP.get(event_name, "cloud_audit_event")
    if event_name == "ConsoleLogin":
        response_elem = raw.get("responseElements", {})
        if response_elem and response_elem.get("ConsoleLogin") == "Failure":
            event_type = "user_logon_failed"
        elif error_code:
            event_type = "user_logon_failed"

    region = raw.get("awsRegion", "us-east-1")
    host = f"aws.{region}.{raw.get('recipientAccountId', 'account')}"

    return {
        "source": "aws_cloudtrail",
        "event_type": event_type,
        "timestamp": event_time,
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "raw": {
            "event_id": raw.get("eventID"),
            "event_name": event_name,
            "event_source": raw.get("eventSource"),
            "aws_region": region,
            "error_code": error_code,
            "error_message": raw.get("errorMessage"),
            "user_agent": user_agent,
            "request_parameters": raw.get("requestParameters"),
            "user_identity": user_identity,
        },
    }


# ── Sample Synthetic CloudTrail Records ───────────────────────────────────────

SAMPLE_CLOUDTRAIL_RECORDS: List[Dict[str, Any]] = [
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "arn": "arn:aws:iam::123456789012:user/attacker_session",
            "userName": "attacker_session",
        },
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "eventSource": "iam.amazonaws.com",
        "eventName": "AttachUserPolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.45",
        "userAgent": "aws-cli/2.13.0 Python/3.11.4",
        "requestParameters": {
            "userName": "attacker_session",
            "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        },
        "responseElements": None,
        "eventID": "ct-evt-001",
    },
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE2",
            "userName": "victim_dev",
        },
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.99",
        "responseElements": {"ConsoleLogin": "Failure"},
        "errorMessage": "Failed authentication",
        "eventID": "ct-evt-002",
    },
    {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLE",
            "userName": "attacker_session",
        },
        "eventTime": datetime.now(timezone.utc).isoformat(),
        "eventSource": "cloudtrail.amazonaws.com",
        "eventName": "StopLogging",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.45",
        "requestParameters": {"name": "prod-security-trail"},
        "eventID": "ct-evt-003",
    },
]


class CloudTrailCollector:
    """Collects and ingests AWS CloudTrail records into AegisX."""

    def __init__(
        self,
        api_url: str = "http://localhost:8000",
        log_file: Optional[str] = None,
        batch_size: int = 50,
        dry_run: bool = False,
    ):
        self.api_url = api_url.rstrip("/")
        self.ingest_endpoint = f"{self.api_url}/api/v1/telemetry/ingest"
        self.log_file = log_file
        self.batch_size = batch_size
        self.dry_run = dry_run

    def fetch_records(self) -> List[Dict[str, Any]]:
        """Read records from local JSON file or return sample attack set."""
        if self.log_file and os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "Records" in data:
                        return data["Records"]
                    elif isinstance(data, list):
                        return data
            except Exception as exc:
                log.error("Failed loading CloudTrail log file", error=str(exc))
                return []

        return SAMPLE_CLOUDTRAIL_RECORDS

    def run_once(self) -> Dict[str, int]:
        """Process and ship CloudTrail logs to AegisX."""
        raw_records = self.fetch_records()
        events = []
        for raw in raw_records:
            ev = normalize_cloudtrail_event(raw)
            if ev:
                events.append(ev)

        if not events:
            return {"events_found": 0, "events_shipped": 0}

        if self.dry_run:
            log.info("Dry-run: skipping CloudTrail HTTP dispatch", count=len(events))
            for e in events[:2]:
                log.info("Sample CloudTrail event", event_type=e["event_type"], user=e.get("user"), host=e.get("host"))
            return {"events_found": len(events), "events_shipped": len(events)}

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped CloudTrail batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed shipping CloudTrail batch", error=str(exc), count=len(chunk))

        return {"events_found": len(events), "events_shipped": shipped}


def main():
    parser = argparse.ArgumentParser(description="AegisX AWS CloudTrail Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API URL")
    parser.add_argument("--file", default=None, help="Path to CloudTrail JSON log file")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument("--once", action="store_true", default=True, help="Run single pass and exit")

    args = parser.parse_args()

    collector = CloudTrailCollector(
        api_url=args.api,
        log_file=args.file,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    stats = collector.run_once()
    print(f"CloudTrail collection pass complete: {stats}")


if __name__ == "__main__":
    main()
