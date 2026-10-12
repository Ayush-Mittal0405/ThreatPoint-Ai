"""
Unit tests for GCP Cloud Audit Collector.
"""
import pytest
from collectors.cloud.gcp_audit_collector import normalize_gcp_event, GCPAuditCollector, SAMPLE_GCP_LOGS


class TestGCPAuditCollector:
    def test_normalize_create_service_account_key(self):
        raw = {
            "insertId": "gcp-001",
            "timestamp": "2026-08-29T12:00:00Z",
            "resource": {"labels": {"project_id": "soc-lab-prod"}},
            "protoPayload": {
                "serviceName": "iam.googleapis.com",
                "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
                "authenticationInfo": {"principalEmail": "compromised_user@corp.com"},
                "requestMetadata": {"callerIp": "198.51.100.45", "callerSuppliedUserAgent": "gcloud/400"},
            },
        }
        event = normalize_gcp_event(raw)
        assert event["source"] == "gcp_cloud_audit"
        assert event["event_type"] == "user_account_change"
        assert event["user"] == "compromised_user@corp.com"
        assert event["host"] == "gcp.soc-lab-prod.iam"
        assert event["src_ip"] == "198.51.100.45"

    def test_normalize_delete_logging_sink(self):
        raw = {
            "insertId": "gcp-002",
            "timestamp": "2026-08-29T12:05:00Z",
            "resource": {"labels": {"project_id": "soc-lab-prod"}},
            "protoPayload": {
                "serviceName": "logging.googleapis.com",
                "methodName": "google.logging.v2.ConfigServiceV2.DeleteSink",
                "authenticationInfo": {"principalEmail": "attacker@corp.com"},
                "requestMetadata": {"callerIp": "198.51.100.45"},
            },
        }
        event = normalize_gcp_event(raw)
        assert event["event_type"] == "defense_evasion_cloud"
        assert event["user"] == "attacker@corp.com"

    def test_gcp_collector_dry_run(self):
        collector = GCPAuditCollector(dry_run=True)
        stats = collector.run_once()
        assert stats["events_found"] == len(SAMPLE_GCP_LOGS)
        assert stats["events_shipped"] == len(SAMPLE_GCP_LOGS)
