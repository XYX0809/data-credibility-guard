"""污染注入器测试：含 HMAC 威胁模型集成用例（改必报、删不报）。"""
import copy
from datetime import datetime, timedelta

import pytest

from src.datasource.generator import METRIC_RANGES, generate_normal_events
from src.engine.hmac_layer import sign, verify
from src.features.extractor import HOST_NAME_RE, FeatureExtractor
from src.pollution.log_deletion import inject_log_deletion
from src.pollution.noise_injection import inject_noise
from src.pollution.source_forgery import inject_source_forgery
from src.pollution.timestamp_tamper import inject_timestamp_tamper

KEY = b"test-secret"


@pytest.fixture
def events():
    return [e.to_dict() for e in generate_normal_events(100)]


# ---------- 时间戳篡改 ----------


def test_ratio_zero_noop(events):
    res = inject_timestamp_tamper(events, ratio=0)
    assert res.events == events
    assert res.affected_event_ids == []


def test_tamper_deterministic(events):
    a = inject_timestamp_tamper(events, mode="rollback", seed=7)
    b = inject_timestamp_tamper(events, mode="rollback", seed=7)
    assert a.events == b.events
    assert a.affected_event_ids == b.affected_event_ids


def test_tamper_input_not_mutated(events):
    snapshot = copy.deepcopy(events)
    inject_timestamp_tamper(events, mode="skew", ratio=0.5)
    assert events == snapshot


def test_tamper_keeps_event_count(events):
    res = inject_timestamp_tamper(events, mode="shuffle", ratio=0.3)
    assert len(res.events) == len(events)


def test_rollback_moves_ts_earlier(events):
    orig = {e["event_id"]: e["ts"] for e in events}
    res = inject_timestamp_tamper(events, mode="rollback", ratio=0.2, seed=1)
    assert res.affected_event_ids
    for e in res.events:
        if e["event_id"] in res.affected_event_ids:
            assert datetime.fromisoformat(e["ts"]) < datetime.fromisoformat(orig[e["event_id"]])


def test_rollback_breaks_monotonicity(events):
    res = inject_timestamp_tamper(events, mode="rollback", ratio=0.2, seed=1)
    stamps = [e["ts"] for e in res.events]
    assert stamps != sorted(stamps)


def test_skew_shifts_by_months(events):
    orig = {e["event_id"]: datetime.fromisoformat(e["ts"]) for e in events}
    res = inject_timestamp_tamper(events, mode="skew", ratio=0.2, seed=3)
    assert res.affected_event_ids
    for e in res.events:
        if e["event_id"] in res.affected_event_ids:
            delta = abs(datetime.fromisoformat(e["ts"]) - orig[e["event_id"]])
            assert delta >= timedelta(days=30)


def test_shuffle_keeps_timestamp_multiset(events):
    res = inject_timestamp_tamper(events, mode="shuffle", ratio=0.3, seed=5)
    assert sorted(e["ts"] for e in res.events) == sorted(e["ts"] for e in events)
    assert res.affected_event_ids


def test_hmac_field_left_stale(events):
    signed = [sign(e, KEY) for e in events]
    res = inject_timestamp_tamper(signed, mode="rollback", ratio=0.2, seed=1)
    orig_hmac = {e["event_id"]: e["hmac"] for e in signed}
    assert all(e["hmac"] == orig_hmac[e["event_id"]] for e in res.events)


# ---------- 日志删除 ----------


def test_deletion_ratio_zero_noop(events):
    res = inject_log_deletion(events, ratio=0)
    assert res.events == events
    assert res.affected_event_ids == []


def test_deletion_deterministic(events):
    a = inject_log_deletion(events, ratio=0.25, seed=9)
    b = inject_log_deletion(events, ratio=0.25, seed=9)
    assert a.events == b.events
    assert a.affected_event_ids == b.affected_event_ids


def test_random_deletion_removes_k(events):
    res = inject_log_deletion(events, mode="random", ratio=0.2, seed=1)
    assert len(res.events) == 80
    assert len(res.affected_event_ids) == 20


def test_kept_events_identical_including_hmac(events):
    signed = [sign(e, KEY) for e in events]
    res = inject_log_deletion(signed, mode="random", ratio=0.2, seed=1)
    orig = {e["event_id"]: e for e in signed}
    for e in res.events:
        assert e == orig[e["event_id"]]


def test_deletion_leaves_seq_gaps(events):
    res = inject_log_deletion(events, mode="random", ratio=0.2, seed=1)
    seqs = [e["seq_no"] for e in res.events]
    assert seqs != list(range(seqs[0], seqs[0] + len(seqs)))


def test_block_deletion_is_contiguous(events):
    res = inject_log_deletion(events, mode="block", ratio=0.2, seed=2)
    seqs = res.detail["deleted_seq_nos"]
    assert seqs == list(range(seqs[0], seqs[-1] + 1))
    assert len(seqs) == 20


def test_deletion_input_not_mutated(events):
    snapshot = copy.deepcopy(events)
    inject_log_deletion(events, ratio=0.4, seed=4)
    assert events == snapshot


# ---------- 威胁模型集成 ----------


def test_hmac_catches_tamper_but_not_deletion(events):
    signed = [sign(e, KEY) for e in events[:50]]

    deleted = inject_log_deletion(signed, ratio=0.2, seed=1)
    assert all(verify(e, KEY) for e in deleted.events), "删除后剩余日志 HMAC 应全部有效（L1 无感）"

    tampered = inject_timestamp_tamper(signed, mode="rollback", ratio=0.2, seed=1)
    bad = set(tampered.affected_event_ids)
    for e in tampered.events:
        assert verify(e, KEY) == (e["event_id"] not in bad), "篡改事件必须被 HMAC 拦下"


# ---------- 来源伪造 ----------


def test_forgery_ratio_zero_noop(events):
    res = inject_source_forgery(events, ratio=0)
    assert res.events == events
    assert res.affected_event_ids == []


def test_rename_host_flags_naming_and_consistency(events):
    res = inject_source_forgery(events, mode="rename_host", ratio=0.3, seed=1)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    bad = set(res.affected_event_ids)
    assert bad
    for e, f in zip(res.events, rows):
        if e["event_id"] in bad:
            assert not HOST_NAME_RE.match(e["host"])
            assert f["host_naming_compliance"] == 0.0
            assert f["source_consistency"] == 0.0


def test_forge_source_only_consistency(events):
    res = inject_source_forgery(events, mode="forge_source", ratio=0.3, seed=2)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    bad = set(res.affected_event_ids)
    assert bad
    for e, f in zip(res.events, rows):
        if e["event_id"] in bad:
            assert f["host_naming_compliance"] == 1.0
            assert f["source_consistency"] == 0.0


def test_impersonate_looks_compliant_but_hmac_fails(events):
    signed = [sign(e, KEY) for e in events]
    res = inject_source_forgery(signed, mode="impersonate", ratio=0.3, seed=3)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    bad = set(res.affected_event_ids)
    assert bad
    for e, f in zip(res.events, rows):
        if e["event_id"] in bad:
            assert f["host_naming_compliance"] == 1.0
            assert f["source_consistency"] == 1.0
            assert f["hmac_status"] == 0.0  # 冒充外观合规，只有 HMAC 抓得住


def test_forgery_breaks_hmac(events):
    signed = [sign(e, KEY) for e in events]
    res = inject_source_forgery(signed, mode="rename_host", ratio=0.2, seed=4)
    bad = set(res.affected_event_ids)
    for e in res.events:
        assert verify(e, KEY) == (e["event_id"] not in bad)


# ---------- 噪声注入 ----------


def test_spike_out_of_range(events):
    res = inject_noise(events, mode="spike", ratio=0.2, seed=1)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    bad = set(res.affected_event_ids)
    assert len(bad) == 20
    for e, f in zip(res.events, rows):
        if e["event_id"] in bad:
            assert f["range_violation_ratio"] == 1.0


def test_jitter_raises_noise_feature(events):
    res = inject_noise(events, mode="jitter", ratio=0.5, seed=2)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    clean_rows = FeatureExtractor(key=KEY).extract_all(events)
    jitter_mean = sum(f["numeric_noise_level"] for f in rows) / len(rows)
    clean_mean = sum(f["numeric_noise_level"] for f in clean_rows) / len(clean_rows)
    assert jitter_mean > clean_mean + 0.15
    assert max(f["numeric_noise_level"] for f in rows) > 0.5


def test_noise_deterministic_and_input_not_mutated(events):
    snapshot = copy.deepcopy(events)
    a = inject_noise(events, mode="spike", ratio=0.4, seed=5)
    b = inject_noise(events, mode="spike", ratio=0.4, seed=5)
    c = inject_source_forgery(events, mode="rename_host", ratio=0.4, seed=5)
    assert a.events == b.events
    assert a.affected_event_ids == b.affected_event_ids
    assert events == snapshot
    assert c.events is not events


def test_mask_makes_benign_and_stale_hmac(events):
    signed = [sign(e, KEY) for e in events]
    res = inject_noise(signed, mode="mask", ratio=0.3, seed=6)
    bad = set(res.affected_event_ids)
    assert bad
    for e in res.events:
        if e["event_id"] in bad:
            m = e["metrics"]
            # 抹平到量程低位 5%-30% 的温和区间
            assert m["cpu"] <= METRIC_RANGES["cpu"][1] * 0.35
            assert m["conn_count"] <= METRIC_RANGES["conn_count"][1] * 0.35
            assert not verify(e, KEY)  # 伪装破坏签名，HMAC 抓得住
