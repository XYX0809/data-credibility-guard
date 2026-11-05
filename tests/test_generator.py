from src.datasource.generator import (
    HOST_POOL,
    METRIC_RANGES,
    generate_normal_events,
    load_jsonl,
    save_jsonl,
)
from src.datasource.schema import EVENT_TYPES


def test_count_and_determinism():
    a = generate_normal_events(50)
    b = generate_normal_events(50)
    assert len(a) == 50
    assert [e.to_dict() for e in a] == [e.to_dict() for e in b]


def test_seq_monotonic():
    events = generate_normal_events(20, start_seq=100)
    assert [e.seq_no for e in events] == list(range(100, 120))


def test_ts_strictly_increasing():
    events = generate_normal_events(30)
    stamps = [e.ts for e in events]
    assert stamps == sorted(stamps)
    assert len(set(stamps)) == len(stamps)


def test_fields_sane():
    for e in generate_normal_events(30):
        assert e.host in HOST_POOL
        assert e.event_type in EVENT_TYPES
        assert e.source_id == f"agent-{e.host}"
        assert set(e.metrics) == set(METRIC_RANGES)
        for k, (lo, hi) in METRIC_RANGES.items():
            assert lo <= e.metrics[k] <= hi


def test_save_load_roundtrip(tmp_path):
    events = generate_normal_events(10)
    path = tmp_path / "sample.jsonl"
    save_jsonl(path, events)
    loaded = load_jsonl(path)
    assert loaded == [e.to_dict() for e in events]
