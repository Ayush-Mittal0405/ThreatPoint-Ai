"""
Google Cloud Platform (GCP) Cloud Audit Logs Telemetry Collector.

Collects and parses GCP Cloud Audit Logs (Admin Activity & System Events),
normalizing IAM service account abuse, permission changes, firewall updates,
and storage access into the AegisX NormalizedEvent schema.

Targeted MITRE ATT&CK Cloud Techniques:
  - T1098: Account Manipulation (CreateServiceAccountKey, SetIamPolicy)
  - T1078.004: Valid Accounts: Cloud Accounts
  - T1562.008: Impair Defenses: Disable Cloud Logs (DeleteSink)
  - T1530: Data from Cloud Storage
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

try:
    import structlog
    log = structlog.get_logger()
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    _std_log = logging.getLogger("gcp_collector")
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


GCP_METHOD_MAP = {
    "google.iam.admin.v1.CreateServiceAccountKey": "user_account_change",
    "google.iam.admin.v1.CreateServiceAccount": "user_account_change",
    "SetIamPolicy": "policy_modification",
    "google.iam.admin.v1.SetIamPolicy": "policy_modification",
    "v1.compute.firewalls.insert": "network_policy_change",
    "v1.compute.firewalls.patch": "network_policy_change",
    "storage.setIamPermissions": "cloud_storage_event",
    "storage.buckets.update": "cloud_storage_event",
    "google.logging.v2.ConfigServiceV2.DeleteSink": "defense_evasion_cloud",
}


def normalize_gcp_event(raw: Dict[str, Any], default_host: str = "gcp.cloud.audit") -> Optional[Dict[str, Any]]:
    """Normalize a GCP Cloud Audit Log JSON entry into AegisX NormalizedEvent format."""
    proto = raw.get("protoPayload", {})
    method_name = proto.get("methodName", "")
    service_name = proto.get("serviceName", "gcp.googleapis.com")

    auth_info = proto.get("authenticationInfo", {})
    user = auth_info.get("principalEmail", "unknown_gcp_principal")

    request_metadata = proto.get("requestMetadata", {})
    src_ip = request_metadata.get("callerIp")
    user_agent = request_metadata.get("callerSuppliedUserAgent")

    resource_name = proto.get("resourceName")
    timestamp = raw.get("timestamp", datetime.now(timezone.utc).isoformat())

    event_type = GCP_METHOD_MAP.get(method_name, "cloud_audit_event")

    # Status check
    status = proto.get("status", {})
    status_code = status.get("code", 0)  # 0 is OK in gRPC

    resource = raw.get("resource", {})
    labels = resource.get("labels", {})
    project_id = labels.get("project_id", "project")
    host = f"gcp.{project_id}.{service_name.split('.')[0]}"

    return {
        "source": "gcp_cloud_audit",
        "event_type": event_type,
        "timestamp": timestamp,
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "raw": {
            "insert_id": raw.get("insertId"),
            "log_name": raw.get("logName"),
            "service_name": service_name,
            "method_name": method_name,
            "resource_name": resource_name,
            "user_agent": user_agent,
            "status_code": status_code,
            "request_payload": proto.get("request"),
        },
    }


# ── Sample Synthetic GCP Audit Logs ───────────────────────────────────────────

SAMPLE_GCP_LOGS: List[Dict[str, Any]] = [
    {
        "insertId": "gcp-evt-001",
        "logName": "projects/prod-cloud-sec/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource": {"type": "service_account", "labels": {"project_id": "prod-cloud-sec"}},
        "protoPayload": {
            "serviceName": "iam.googleapis.com",
            "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
            "resourceName": "projects/prod-cloud-sec/serviceAccounts/backup-sa@prod-cloud-sec.iam.gserviceaccount.com",
            "authenticationInfo": {"principalEmail": "compromised_admin@company.com"},
            "requestMetadata": {"callerIp": "198.51.100.89", "callerSuppliedUserAgent": "gcloud-cli/450.0.0"},
            "status": {"code": 0},
        },
    },
    {
        "insertId": "gcp-evt-002",
        "logName": "projects/prod-cloud-sec/logs/cloudaudit.googleapis.com%2Factivity",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "resource": {"type": "logging_sink", "labels": {"project_id": "prod-cloud-sec"}},
        "protoPayload": {
            "serviceName": "logging.googleapis.com",
            "methodName": "google.logging.v2.ConfigServiceV2.DeleteSink",
            "resourceName": "projects/prod-cloud-sec/sinks/siem-export-sink",
            "authenticationInfo": {"principalEmail": "compromised_admin@company.com"},
            "requestMetadata": {"callerIp": "198.51.100.89"},
            "status": {"code": 0},
        },
    },
]


class GCPAuditCollector:
    """Collects and ingests GCP Cloud Audit Logs into AegisX."""

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

    def fetch_logs(self) -> List[Dict[str, Any]]:
        """Fetch logs from file or return sample attack set."""
        if self.log_file and os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                    if content.startswith("["):
                        return json.loads(content)
                    else:
                        return [json.loads(line) for line in content.splitlines() if line.strip()]
            except Exception as exc:
                log.error("Failed loading GCP log file", error=str(exc))
                return []

        return SAMPLE_GCP_LOGS

    def run_once(self) -> Dict[str, int]:
        """Normalize and forward GCP audit logs to AegisX."""
        raw_records = self.fetch_logs()
        events = []
        for raw in raw_records:
            ev = normalize_gcp_event(raw)
            if ev:
                events.append(ev)

        if not events:
            return {"events_found": 0, "events_shipped": 0}

        if self.dry_run:
            log.info("Dry-run: skipping GCP HTTP dispatch", count=len(events))
            for e in events[:2]:
                log.info("Sample GCP event", event_type=e["event_type"], user=e.get("user"), host=e.get("host"))
            return {"events_found": len(events), "events_shipped": len(events)}

        shipped = 0
        with httpx.Client(timeout=10.0) as client:
            for i in range(0, len(events), self.batch_size):
                chunk = events[i : i + self.batch_size]
                try:
                    res = client.post(self.ingest_endpoint, json={"events": chunk})
                    res.raise_for_status()
                    shipped += len(chunk)
                    log.info("Shipped GCP batch", count=len(chunk), status=res.status_code)
                except Exception as exc:
                    log.error("Failed shipping GCP batch", error=str(exc), count=len(chunk))

        return {"events_found": len(events), "events_shipped": shipped}


def main():
    parser = argparse.ArgumentParser(description="AegisX GCP Cloud Audit Telemetry Collector")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API URL")
    parser.add_argument("--file", default=None, help="Path to GCP Audit JSON log file")
    parser.add_argument("--batch-size", type=int, default=50, help="Batch size")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument("--once", action="store_true", default=True, help="Run single pass and exit")

    args = parser.parse_args()

    collector = GCPAuditCollector(
        api_url=args.api,
        log_file=args.file,
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    stats = collector.run_once()
    print(f"GCP collection pass complete: {stats}")


if __name__ == "__main__":
    main()
