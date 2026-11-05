"""三层评分引擎测试：合成公式、规则兜底、统计层、端到端污染响应。"""
import random

import pytest

from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import sign
from src.engine.iforest_layer import StatLayer
from src.engine.rule_layer import evaluate_rules
from src.engine.scorer import CredibilityEngine, combine_scores
from src.features.extractor import FEATURE_NAMES
from src.pollution.log_deletion import inject_log_deletion
from src.pollution.timestamp_tamper import inject_timestamp_tamper

KEY = b"test-secret"


def _clean_features(**overrides):
    feats = {
        "hmac_status": 1.0,
        "ts_monotonic_violation": 0.0,
        "ts_skew": 0.0,
        "seq_gap_ratio": 0.0,
        "host_naming_compliance": 1.0,
        "source_consistency": 1.0,
        "format_compliance": 1.0,
        "missing_field_ratio": 0.0,
        "numeric_noise_level": 0.3,
        "range_violation_ratio": 0.0,
        "event_rate_anomaly": 0.1,
        "baseline_deviation": 0.3,
    }
    feats.update(overrides)
    return feats


@pytest.fixture
def stream():
    return [sign(e.to_dict(), KEY) for e in generate_normal_events(400)]


@pytest.fixture
def engine(stream):
    return CredibilityEngine.train(stream[:200], key=KEY)


# ---------- 合成公式 ----------


def test_combine_scores_plain():
    score, blocked = combine_scores(100, 100, 100, veto=False)
    assert score == pytest.approx(100.0)
    assert not blocked


def test_combine_scores_weighted():
    score, _ = combine_scores(100, 50, 100, veto=False)
    assert score == pytest.approx(80.0)


def test_combine_scores_veto_caps_at_30():
    score, blocked = combine_scores(100, 100, 100, veto=True)
    assert score == pytest.approx(30.0)
    assert blocked


def test_combine_scores_threshold_boundary():
    _, blocked = combine_scores(100, 50, 100, veto=False)  # 80 分
    assert not blocked
    _, blocked = combine_scores(0, 100, 100, veto=True)  # 压到 30
    assert blocked


# ---------- 规则兜底 ----------


def test_rules_clean():
    r = evaluate_rules(_clean_features())
    assert r.score == 100.0
    assert r.hits == []
    assert not r.veto


def test_rules_hostname_penalty_only():
    r = evaluate_rules(_clean_features(host_naming_compliance=0.0))
    assert r.score == pytest.approx(85.0)
    assert r.hits == ["hostname_nonstandard"]
    assert not r.veto


def test_rules_hostname_plus_other_escalates_veto():
    r = evaluate_rules(
        _clean_features(host_naming_compliance=0.0, format_compliance=0.5)
    )
    assert r.veto
    assert "format_broken" in r.hits and "hostname_nonstandard" in r.hits


def test_rules_floors():
    assert evaluate_rules(_clean_features(hmac_status=0.0)).score == 10.0
    assert evaluate_rules(_clean_features(format_compliance=0.5)).score == 20.0
    assert evaluate_rules(_clean_features(seq_gap_ratio=0.9)).score == 30.0


# ---------- 统计层 ----------


def test_stat_layer_separates_outliers():
    rng = random.Random(42)
    normal = [
        [1.0, 0.0, 0.0, 1.0, 1.0] + [0.3 + rng.uniform(-0.05, 0.05) for _ in range(7)]
        for _ in range(100)
    ]
    layer = StatLayer().fit(normal)
    typical = sum(layer.score(v) for v in normal[:20]) / 20
    assert typical >= 60.0
    assert layer.score([0.0, 1.0, 1.0, 0.0, 0.0] + [1.0] * 7) <= 30.0


def test_stat_layer_requires_fit():
    with pytest.raises(RuntimeError):
        StatLayer().score([0.0] * 12)


# ---------- 端到端 ----------


def test_clean_stream_scores_high(engine, stream):
    results = engine.evaluate_all(stream[200:400])
    scores = [r.score for r in results]
    assert sum(scores) / len(scores) >= 85.0
    assert sum(1 for s in scores if s >= 80.0) / len(scores) >= 0.9
    assert sum(1 for r in results if r.blocked) / len(results) <= 0.05
    assert all(not r.veto for r in results)


def test_tampered_events_blocked_exactly(engine, stream):
    res = inject_timestamp_tamper(stream[200:400], mode="rollback", ratio=0.2, seed=1)
    results = engine.evaluate_all(res.events)
    bad = set(res.affected_event_ids)
    by_id = {r.event_id: r for r in results}

    for eid in bad:
        assert by_id[eid].blocked
        assert by_id[eid].score <= 40.0
        assert by_id[eid].veto

    blocked_ids = {r.event_id for r in results if r.blocked}
    assert blocked_ids == bad  # 未篡改事件即使邻居异常也不误伤


def test_deletion_gap_boundary_blocked(engine, stream):
    batch = stream[200:400]
    res = inject_log_deletion(batch, mode="block", ratio=0.2, seed=2)
    results = engine.evaluate_all(res.events)

    deleted_seqs = set(res.detail["deleted_seq_nos"])
    boundary = min(
        (r for r in results), key=lambda r: abs(_seq_of(res.events, r) - max(deleted_seqs))
    )
    boundary_seq = _seq_of(res.events, boundary)
    assert boundary_seq == max(deleted_seqs) + 1

    assert boundary.blocked
    assert "seq_gap_large" in boundary.rule_hits
    assert sum(1 for r in results if r.blocked) <= 3


def _seq_of(events, result):
    for e in events:
        if e["event_id"] == result.event_id:
            return e["seq_no"]
    raise AssertionError("event_id 不在批次中")


def test_engine_deterministic(stream):
    a = CredibilityEngine.train(stream[:200], key=KEY).evaluate_all(stream[200:210])
    b = CredibilityEngine.train(stream[:200], key=KEY).evaluate_all(stream[200:210])
    assert [r.score for r in a] == [r.score for r in b]


def test_result_carries_explain_payload(engine, stream):
    r = engine.evaluate(stream[200])
    assert set(r.features) == set(FEATURE_NAMES)
    assert r.s_hmac == 100.0
    assert 0.0 <= r.s_stat <= 100.0
    assert 0.0 <= r.s_rule <= 100.0
