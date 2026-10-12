import pytest

from aegisx_agent.config import Config


def test_defaults():
    cfg = Config.from_dict({})
    assert cfg.server.url.startswith("https://")
    assert cfg.agent.batch_size == 100
    assert cfg.collectors.process is True
    assert cfg.agent.report_username is False  # privacy default


def test_from_dict_overrides():
    cfg = Config.from_dict({
        "server": {"url": "https://soc.example:8443", "verify_tls": False},
        "agent": {"batch_size": 25, "buffer_max_events": 500},
        "collectors": {"network": False},
        "enrollment": {"token": "abc12345"},
    })
    assert cfg.server.url == "https://soc.example:8443"
    assert cfg.server.verify_tls is False
    assert cfg.agent.batch_size == 25
    assert cfg.collectors.network is False
    assert cfg.enrollment_token == "abc12345"


def test_env_override(monkeypatch):
    monkeypatch.setenv("AEGISX_AGENT_SERVER_URL", "https://env.example")
    monkeypatch.setenv("AEGISX_AGENT_ENROLLMENT_TOKEN", "env-token-123")
    monkeypatch.setenv("AEGISX_AGENT_HEARTBEAT_INTERVAL", "45")
    cfg = Config.from_dict({})
    cfg._apply_env()
    assert cfg.server.url == "https://env.example"
    assert cfg.enrollment_token == "env-token-123"
    assert cfg.agent.heartbeat_interval_seconds == 45


def test_validate_rejects_plain_http_to_remote():
    cfg = Config.from_dict({"server": {"url": "http://soc.example"}})
    with pytest.raises(ValueError):
        cfg.validate()


def test_validate_allows_http_localhost():
    cfg = Config.from_dict({"server": {"url": "http://127.0.0.1:8008"}})
    cfg.validate()  # no raise


def test_validate_buffer_must_hold_a_batch():
    cfg = Config.from_dict({"agent": {"batch_size": 100, "buffer_max_events": 10}})
    with pytest.raises(ValueError):
        cfg.validate()
