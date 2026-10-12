from aegisx_agent.buffer import EventBuffer


def _ev(i):
    return {"event_type": "process_creation", "n": i}


def test_enqueue_and_peek(tmp_path):
    buf = EventBuffer(str(tmp_path / "b.jsonl"), max_events=100)
    buf.enqueue_many([_ev(i) for i in range(5)])
    assert buf.size == 5
    batch = buf.peek_batch(3)
    assert [e["n"] for e in batch] == [0, 1, 2]


def test_commit_removes_from_front(tmp_path):
    buf = EventBuffer(str(tmp_path / "b.jsonl"), max_events=100)
    buf.enqueue_many([_ev(i) for i in range(5)])
    buf.commit(2)
    assert [e["n"] for e in buf.peek_batch(10)] == [2, 3, 4]


def test_bounded_drops_oldest(tmp_path):
    buf = EventBuffer(str(tmp_path / "b.jsonl"), max_events=3)
    buf.enqueue_many([_ev(i) for i in range(5)])
    assert buf.size == 3
    assert buf.dropped_total == 2
    assert [e["n"] for e in buf.peek_batch(10)] == [2, 3, 4]


def test_persist_and_reload(tmp_path):
    path = str(tmp_path / "b.jsonl")
    buf = EventBuffer(path, max_events=100)
    buf.enqueue_many([_ev(i) for i in range(4)])
    buf.persist()

    buf2 = EventBuffer(path, max_events=100)
    assert buf2.size == 4
    assert [e["n"] for e in buf2.peek_batch(10)] == [0, 1, 2, 3]


def test_corrupt_file_starts_clean(tmp_path):
    path = tmp_path / "b.jsonl"
    path.write_text("not json at all\n{broken", encoding="utf-8")
    buf = EventBuffer(str(path), max_events=100)
    assert buf.size == 0
