"""
Unit tests for Enterprise Fleet Management (100+ Endpoints) and Active Containment.
"""
import asyncio
import pytest
from app.api.v1.endpoints.fleet import (
    build_enterprise_fleet,
    list_fleet_devices,
    get_device_detail,
    execute_device_action,
    execute_bulk_action,
    get_fleet_stats,
    DeviceActionRequest,
    BulkActionRequest,
    _FLEET_STORE,
)
from collectors.fleet.fleet_streamer import (
    generate_fleet_telemetry_batch,
    FleetStreamer,
)


class TestFleetManagement:
    def test_build_enterprise_fleet_contains_100_plus_endpoints(self):
        devices = build_enterprise_fleet()
        assert len(devices) >= 100
        # Check workstations
        workstations = [d for d in devices if d["device_type"] == "workstation"]
        assert len(workstations) >= 70
        # Check domain controllers
        dcs = [d for d in devices if d["device_type"] == "domain_controller"]
        assert len(dcs) >= 4
        # Check production servers and database nodes
        servers = [d for d in devices if d["device_type"] in ["server", "database", "k8s_node"]]
        assert len(servers) >= 30

    def test_list_fleet_devices_filtering(self):
        # Filter by department
        res_fin = asyncio.run(list_fleet_devices(department="Finance"))
        assert res_fin["total"] >= 15
        assert all("Finance" in d["department"] for d in res_fin["devices"])

        # Filter by OS
        res_win = asyncio.run(list_fleet_devices(os="Windows 11"))
        assert res_win["total"] >= 70
        assert all("Windows 11" in d["os"] for d in res_win["devices"])

        # Search by hostname
        res_search = asyncio.run(list_fleet_devices(search="CORP-ENG-05"))
        assert res_search["total"] == 1
        assert res_search["devices"][0]["hostname"] == "CORP-ENG-05"

    def test_get_device_detail(self):
        target_id = list(_FLEET_STORE.keys())[0]
        detail = asyncio.run(get_device_detail(target_id))
        assert "device" in detail
        assert "processes" in detail
        assert "network_sockets" in detail
        assert len(detail["processes"]) >= 3

    def test_execute_device_containment_actions(self):
        target_id = list(_FLEET_STORE.keys())[5]

        # 1. Isolate host
        res_iso = asyncio.run(execute_device_action(
            target_id,
            DeviceActionRequest(action="isolate_host", analyst="Lead Incident Responder")
        ))
        assert res_iso["status"] == "success"
        assert res_iso["device"]["containment_status"] == "isolated"
        assert res_iso["audit_entry"]["action"] == "isolate_host"

        # 2. Un-isolate host
        res_uniso = asyncio.run(execute_device_action(
            target_id,
            DeviceActionRequest(action="unisolate_host", analyst="Lead Incident Responder")
        ))
        assert res_uniso["status"] == "success"
        assert res_uniso["device"]["containment_status"] == "normal"

        # 3. Kill process
        res_kill = asyncio.run(execute_device_action(
            target_id,
            DeviceActionRequest(action="kill_process", target="powershell.exe")
        ))
        assert res_kill["status"] == "success"
        assert "powershell.exe" in res_kill["audit_entry"]["target"]

    def test_execute_bulk_actions(self):
        target_ids = list(_FLEET_STORE.keys())[10:14]
        res_bulk = asyncio.run(execute_bulk_action(
            BulkActionRequest(device_ids=target_ids, action="isolate_host")
        ))
        assert res_bulk["status"] == "success"
        assert res_bulk["affected_count"] == len(target_ids)

    def test_get_fleet_stats(self):
        stats = asyncio.run(get_fleet_stats())
        assert stats.total_devices >= 100
        assert stats.online_count >= 90
        assert "Engineering" in stats.departments
        assert stats.avg_cpu_pct > 0


    def test_fleet_telemetry_streamer(self):
        events = generate_fleet_telemetry_batch(device_count=100, include_attack=True)
        assert len(events) >= 100
        # Verify events contain valid sources
        sources = {e["source"] for e in events}
        assert "windows_sysmon" in sources
        assert "linux_auditd" in sources

        # Dry-run execution
        streamer = FleetStreamer(device_count=100, dry_run=True)
        stats = streamer.stream_once(include_attack=True)
        assert stats["events_generated"] >= 100
        assert stats["events_shipped"] == stats["events_generated"]
