"""
Unit tests for Cloud & Identity Collectors (Okta & AWS CloudTrail).
"""
import pytest
from collectors.identity.okta_collector import normalize_okta_event, OktaCollector, SAMPLE_OKTA_LOGS
from collectors.cloud.aws_cloudtrail_collector import (
    normalize_cloudtrail_event,
    CloudTrailCollector,
    SAMPLE_CLOUDTRAIL_RECORDS,
)


class TestOktaCollector:
    def test_normalize_okta_login_success(self):
        raw = {
            "uuid": "okta-123",
            "published": "2026-08-29T12:00:00Z",
            "eventType": "user.session.start",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "alice@company.com"},
            "client": {"ipAddress": "198.51.100.12"},
        }
        event = normalize_okta_event(raw)
        assert event["source"] == "okta_identity"
        assert event["event_type"] == "user_logon"
        assert event["user"] == "alice@company.com"
        assert event["src_ip"] == "198.51.100.12"

    def test_normalize_okta_login_failure(self):
        raw = {
            "uuid": "okta-456",
            "published": "2026-08-29T12:01:00Z",
            "eventType": "user.authentication.verify",
            "outcome": {"result": "FAILURE"},
            "actor": {"alternateId": "attacker@evil.com"},
            "client": {"ipAddress": "203.0.113.50"},
        }
        event = normalize_okta_event(raw)
        assert event["event_type"] == "user_logon_failed"
        assert event["user"] == "attacker@evil.com"
        assert event["src_ip"] == "203.0.113.50"

    def test_normalize_okta_privilege_escalation(self):
        raw = {
            "uuid": "okta-789",
            "published": "2026-08-29T12:02:00Z",
            "eventType": "group.user_membership.add",
            "outcome": {"result": "SUCCESS"},
            "actor": {"alternateId": "admin@company.com"},
            "client": {"ipAddress": "198.51.100.12"},
        }
        event = normalize_okta_event(raw)
        assert event["event_type"] == "user_account_change"

    def test_okta_collector_dry_run(self):
        collector = OktaCollector(dry_run=True)
        stats = collector.run_once()
        assert stats["events_found"] == len(SAMPLE_OKTA_LOGS)
        assert stats["events_shipped"] == len(SAMPLE_OKTA_LOGS)


class TestCloudTrailCollector:
    def test_normalize_cloudtrail_console_login_success(self):
        raw = {
            "eventTime": "2026-08-29T12:00:00Z",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012",
            "userIdentity": {"userName": "dev_user"},
            "sourceIPAddress": "198.51.100.22",
            "responseElements": {"ConsoleLogin": "Success"},
        }
        event = normalize_cloudtrail_event(raw)
        assert event["source"] == "aws_cloudtrail"
        assert event["event_type"] == "user_logon"
        assert event["user"] == "dev_user"
        assert event["host"] == "aws.us-east-1.123456789012"
        assert event["src_ip"] == "198.51.100.22"

    def test_normalize_cloudtrail_console_login_failure(self):
        raw = {
            "eventTime": "2026-08-29T12:01:00Z",
            "eventName": "ConsoleLogin",
            "awsRegion": "us-west-2",
            "recipientAccountId": "123456789012",
            "userIdentity": {"userName": "root"},
            "sourceIPAddress": "203.0.113.88",
            "responseElements": {"ConsoleLogin": "Failure"},
        }
        event = normalize_cloudtrail_event(raw)
        assert event["event_type"] == "user_logon_failed"
        assert event["user"] == "root"

    def test_normalize_cloudtrail_iam_policy_attachment(self):
        raw = {
            "eventTime": "2026-08-29T12:05:00Z",
            "eventName": "AttachUserPolicy",
            "awsRegion": "us-east-1",
            "userIdentity": {"userName": "attacker"},
            "sourceIPAddress": "198.51.100.45",
            "requestParameters": {"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        }
        event = normalize_cloudtrail_event(raw)
        assert event["event_type"] == "user_account_change"
        assert event["user"] == "attacker"

    def test_normalize_cloudtrail_defense_evasion(self):
        raw = {
            "eventTime": "2026-08-29T12:10:00Z",
            "eventName": "StopLogging",
            "awsRegion": "us-east-1",
            "userIdentity": {"userName": "attacker"},
            "sourceIPAddress": "198.51.100.45",
        }
        event = normalize_cloudtrail_event(raw)
        assert event["event_type"] == "defense_evasion_cloud"

    def test_cloudtrail_collector_dry_run(self):
        collector = CloudTrailCollector(dry_run=True)
        stats = collector.run_once()
        assert stats["events_found"] == len(SAMPLE_CLOUDTRAIL_RECORDS)
        assert stats["events_shipped"] == len(SAMPLE_CLOUDTRAIL_RECORDS)
