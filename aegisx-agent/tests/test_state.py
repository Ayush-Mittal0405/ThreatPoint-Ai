from aegisx_agent.state import AgentState, StateStore


def test_roundtrip(tmp_path):
    store = StateStore(str(tmp_path))
    assert store.load().enrolled is False

    store.save(AgentState(agent_id="AGT-1", agent_token="secret", enrolled_at="now",
                          server_url="https://x"))
    loaded = store.load()
    assert loaded.enrolled is True
    assert loaded.agent_id == "AGT-1"
    assert loaded.agent_token == "secret"


def test_clear(tmp_path):
    store = StateStore(str(tmp_path))
    store.save(AgentState(agent_id="AGT-1", agent_token="secret"))
    store.clear()
    assert store.load().enrolled is False


def test_corrupt_state_is_safe(tmp_path):
    store = StateStore(str(tmp_path))
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{ not json", encoding="utf-8")
    assert store.load().enrolled is False
