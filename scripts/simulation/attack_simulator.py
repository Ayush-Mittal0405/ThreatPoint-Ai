"""
AegisX Red Team Attack Simulator & Telemetry Emulation Engine.

Simulates realistic, multi-stage cyber attacks and streams normalized telemetry
directly into the AegisX ingestion pipeline to demonstrate autonomous detection,
multi-agent investigation, attack story graph generation, and automated response.

Supported Scenarios:
  1. Spearphishing Macro -> PowerShell C2 Execution (T1566.001 -> T1059.001 -> T1571)
  2. Cloud Identity Compromise -> Defense Evasion (T1078.004 -> T1562.001)
  3. Ransomware Staging & Inhibit System Recovery (T1490 -> T1082 -> T1486)
"""
from __future__ import annotations

import argparse
import json
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
    _std_log = logging.getLogger("attack_simulator")
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


def build_scenario_1(host: str = "CORP-WIN-01", user: str = "alice.smith") -> List[Dict[str, Any]]:
    """Scenario 1: Spearphishing Attachment -> PowerShell -> C2 Beaconing."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "source": "windows_sysmon",
            "event_type": "process_created",
            "timestamp": now,
            "host": host,
            "user": user,
            "process": "winword.exe",
            "parent_process": "explorer.exe",
            "command_line": '"C:\\Program Files\\Microsoft Office\\Office16\\winword.exe" C:\\Users\\alice\\Downloads\\Q3_Invoice_Overdue.docm',
            "raw": {"stage": "initial_access", "technique": "T1566.001"},
        },
        {
            "source": "windows_sysmon",
            "event_type": "process_created",
            "timestamp": now,
            "host": host,
            "user": user,
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
            "hash": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
            "raw": {"stage": "execution", "technique": "T1059.001"},
        },
        {
            "source": "zeek_network",
            "event_type": "network_connection",
            "timestamp": now,
            "host": host,
            "user": user,
            "process": "powershell.exe",
            "src_ip": "10.0.4.12",
            "src_port": 52100,
            "dst_ip": "185.220.101.5",
            "dst_port": 4444,
            "raw": {"stage": "command_and_control", "technique": "T1571"},
        },
        {
            "source": "windows_sysmon",
            "event_type": "process_created",
            "timestamp": now,
            "host": host,
            "user": user,
            "process": "whoami.exe",
            "parent_process": "powershell.exe",
            "command_line": "whoami.exe /all",
            "raw": {"stage": "discovery", "technique": "T1033"},
        },
    ]


def build_scenario_2(user: str = "cloud_admin@enterprise.com") -> List[Dict[str, Any]]:
    """Scenario 2: Cloud Identity Compromise -> Persistence & Evasion."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "source": "okta_identity",
            "event_type": "user_logon",
            "timestamp": now,
            "host": "okta.enterprise.com",
            "user": user,
            "src_ip": "198.51.100.45",
            "raw": {"stage": "initial_access", "technique": "T1078.004", "mfa_result": "PASS_BYPASS"},
        },
        {
            "source": "gcp_cloud_audit",
            "event_type": "user_account_change",
            "timestamp": now,
            "host": "gcp.prod-infra.iam",
            "user": user,
            "src_ip": "198.51.100.45",
            "command_line": "CreateServiceAccountKey for persistence-backdoor@prod-infra.iam.gserviceaccount.com",
            "raw": {"stage": "persistence", "technique": "T1098.001"},
        },
        {
            "source": "aws_cloudtrail",
            "event_type": "defense_evasion_cloud",
            "timestamp": now,
            "host": "aws.us-east-1.cloudtrail",
            "user": user,
            "src_ip": "198.51.100.45",
            "command_line": "StopLogging on trail arn:aws:cloudtrail:us-east-1:123456789012:trail/security-trail",
            "raw": {"stage": "defense_evasion", "technique": "T1562.001"},
        },
    ]


def build_scenario_3(host: str = "FINANCE-DB-02", user: str = "SYSTEM") -> List[Dict[str, Any]]:
    """Scenario 3: Ransomware Staging -> Shadow Copy Destruction."""
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "source": "crowdstrike_edr",
            "event_type": "process_created",
            "timestamp": now,
            "host": host,
            "user": user,
            "process": "vssadmin.exe",
            "parent_process": "cmd.exe",
            "command_line": "vssadmin.exe delete shadows /all /quiet",
            "raw": {"stage": "impact", "technique": "T1490"},
        },
        {
            "source": "windows_sysmon",
            "event_type": "process_created",
            "timestamp": now,
            "host": host,
            "user": user,
            "process": "bcdedit.exe",
            "parent_process": "cmd.exe",
            "command_line": "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures",
            "raw": {"stage": "impact", "technique": "T1490"},
        },
        {
            "source": "sentinelone_edr",
            "event_type": "file_event",
            "timestamp": now,
            "host": host,
            "user": user,
            "file_path": "C:\\Users\\admin\\Documents\\Quarterly_Financials.xlsx.locked",
            "command_line": "mass file encryption detected",
            "raw": {"stage": "impact", "technique": "T1486"},
        },
    ]


class AttackSimulator:
    """Simulates multi-stage attack scenarios and streams telemetry to AegisX."""

    def __init__(self, api_url: str = "http://localhost:8000", dry_run: bool = False):
        self.api_url = api_url.rstrip("/")
        self.ingest_endpoint = f"{self.api_url}/api/v1/telemetry/ingest"
        self.dry_run = dry_run

    def run_scenario(self, scenario_id: int, interval_seconds: float = 0.5) -> Dict[str, Any]:
        """Execute a specific attack scenario."""
        if scenario_id == 1:
            events = build_scenario_1()
            name = "Spearphishing Macro & C2 Execution"
        elif scenario_id == 2:
            events = build_scenario_2()
            name = "Cloud Identity Compromise & Evasion"
        elif scenario_id == 3:
            events = build_scenario_3()
            name = "Ransomware Staging & Shadow Copy Destruction"
        else:
            raise ValueError(f"Unknown scenario ID: {scenario_id}")

        print(f"\n[+] Emulating Scenario {scenario_id}: {name}")
        print(f"    Total attack stages: {len(events)}")

        shipped = 0
        for idx, ev in enumerate(events, 1):
            stage = ev.get("raw", {}).get("stage", "stage")
            technique = ev.get("raw", {}).get("technique", "N/A")
            print(f"  -> [{idx}/{len(events)}] Stage: {stage.upper()} ({technique}) | Process: {ev.get('process') or ev.get('event_type')}")

            if not self.dry_run:
                try:
                    with httpx.Client(timeout=10.0) as client:
                        res = client.post(self.ingest_endpoint, json={"events": [ev]})
                        res.raise_for_status()
                        shipped += 1
                except Exception as exc:
                    print(f"    [!] Shipping failed: {exc}")
            else:
                shipped += 1

            if interval_seconds > 0 and idx < len(events):
                time.sleep(interval_seconds)

        return {"scenario": scenario_id, "name": name, "stages": len(events), "shipped": shipped}


def main():
    parser = argparse.ArgumentParser(description="AegisX Red Team Attack Simulator")
    parser.add_argument("--scenario", type=int, default=1, choices=[1, 2, 3], help="Scenario number to run")
    parser.add_argument("--all", action="store_true", help="Run all scenarios sequentially")
    parser.add_argument("--api", default="http://localhost:8000", help="AegisX API base URL")
    parser.add_argument("--interval", type=float, default=0.2, help="Seconds between stage dispatches")
    parser.add_argument("--dry-run", action="store_true", help="Print telemetry without sending")
    parser.add_argument("--export-dataset", action="store_true", help="Export simulated attack scenarios to JSON format")

    args = parser.parse_args()

    if args.export_dataset:
        scenarios = {
            "scenario_1_phishing_macro": build_scenario_1(),
            "scenario_2_cloud_compromise": build_scenario_2(),
            "scenario_3_ransomware": build_scenario_3(),
        }
        print(json.dumps(scenarios, indent=2))
        return

    simulator = AttackSimulator(api_url=args.api, dry_run=args.dry_run)

    if args.all:
        for s in [1, 2, 3]:
            res = simulator.run_scenario(s, interval_seconds=args.interval)
            print(f"    Scenario {s} finished: {res}")
    else:
        res = simulator.run_scenario(args.scenario, interval_seconds=args.interval)
        print(f"\n[OK] Attack emulation finished successfully: {res}")



if __name__ == "__main__":
    main()
