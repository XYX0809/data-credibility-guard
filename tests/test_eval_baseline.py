"""评测脚手架测试：基线口径与关键检出行为。"""
from tools.eval_baseline import boundary_ids, evaluate_case, rule_flag_b1
from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import sign
from src.features.extractor import FeatureExtractor
from src.pollution.log_deletion import inject_log_deletion
from src.pollution.source_forgery import inject_source_forgery
from src.pollution.timestamp_tamper import inject_timestamp_tamper

KEY = b"test-secret"


def _mini_dataset():
    stream = [sign(e.to_dict(), KEY) for e in generate_normal_events(300, seed=7)]
    return stream[:100], stream[100:150], stream[150:210]


def test_boundary_ids_finds_gap_edges():
    events = [{"event_id": f"e{i}", "seq_no": s} for i, s in enumerate([1, 2, 3, 7, 8, 12])]
    assert boundary_ids(events) == ["e3", "e5"]


def test_rule_flag_b1_semantics():
    clean = {
        "host_naming_compliance": 1.0,
        "format_compliance": 1.0,
        "seq_gap_ratio": 0.0,
        "range_violation_ratio": 0.0,
    }
    assert not rule_flag_b1(clean)
    assert rule_flag_b1({**clean, "host_naming_compliance": 0.0})
    assert rule_flag_b1({**clean, "seq_gap_ratio": 0.9})
    assert rule_flag_b1({**clean, "range_violation_ratio": 0.5})


def test_b0_b1_b2_on_rollback():
    train, clean, base = _mini_dataset()
    res = inject_timestamp_tamper(base, mode="rollback", ratio=0.3, seed=1)
    m = evaluate_case(train, clean, res.events, res.affected_event_ids, KEY)
    assert m["B0"][0] == 0.0
    assert m["B1"][0] == 0.0  # 仅规则看不出时间戳篡改
    assert m["B2"][0] == 1.0  # HMAC 必拦
    assert m["B2"][1] <= 0.05


def test_b1_catches_rename_and_deletion():
    train, clean, base = _mini_dataset()
    res = inject_source_forgery(base, mode="rename_host", ratio=0.3, seed=2)
    m = evaluate_case(train, clean, res.events, res.affected_event_ids, KEY)
    assert m["B1"][0] == 1.0

    del_res = inject_log_deletion(base, mode="block", ratio=0.2, seed=3)
    m = evaluate_case(train, clean, del_res.events, boundary_ids(del_res.events), KEY)
    assert m["B1"][0] == 1.0
    assert m["B2"][0] == 1.0


def test_b1_misses_impersonate():
    train, clean, base = _mini_dataset()
    res = inject_source_forgery(base, mode="impersonate", ratio=0.3, seed=4)
    m = evaluate_case(train, clean, res.events, res.affected_event_ids, KEY)
    assert m["B1"][0] == 0.0
    assert m["B2"][0] == 1.0


def test_false_positive_on_clean_segment():
    train, clean, base = _mini_dataset()
    ext = FeatureExtractor(key=KEY)
    flags = [rule_flag_b1(f) for f in ext.extract_all(clean)]
    assert sum(flags) / len(flags) <= 0.05
