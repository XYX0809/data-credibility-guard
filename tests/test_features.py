"""12 特征提取测试：正常基线、两类污染的特征响应、边界与合规语义。"""
import copy

import pytest

from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import sign
from src.features.extractor import (
    FEATURE_NAMES,
    HIGHER_IS_WORSE,
    FeatureExtractor,
    features_to_vector,
)
from src.pollution.log_deletion import inject_log_deletion
from src.pollution.timestamp_tamper import inject_timestamp_tamper

KEY = b"test-secret"


@pytest.fixture
def signed():
    return [sign(e.to_dict(), KEY) for e in generate_normal_events(200)]


def test_feature_names_locked():
    assert len(FEATURE_NAMES) == 12
    assert set(FEATURE_NAMES) == set(HIGHER_IS_WORSE)


def test_vector_order(signed):
    feats = FeatureExtractor(key=KEY).observe(signed[0])
    vec = features_to_vector(feats)
    assert vec == [feats[name] for name in FEATURE_NAMES]


def test_normal_stream_baseline(signed):
    rows = FeatureExtractor(key=KEY).extract_all(signed)
    for f in rows:
        assert all(0.0 <= v <= 1.0 for v in f.values())
        assert f["hmac_status"] == 1.0
        assert f["missing_field_ratio"] == 0.0
        assert f["format_compliance"] == 1.0
        assert f["host_naming_compliance"] == 1.0
        assert f["source_consistency"] == 1.0
        assert f["range_violation_ratio"] == 0.0
        assert f["ts_monotonic_violation"] == 0.0
        assert f["seq_gap_ratio"] == 0.0
        assert f["ts_skew"] < 0.01


def test_values_bounded_under_pollution(signed):
    tampered = inject_timestamp_tamper(signed, mode="skew", ratio=0.3, seed=2).events
    deleted = inject_log_deletion(signed, mode="block", ratio=0.2, seed=2).events
    for batch in (tampered, deleted):
        for f in FeatureExtractor(key=KEY).extract_all(batch):
            assert all(0.0 <= v <= 1.0 for v in f.values())


def test_tamper_raises_ts_features(signed):
    res = inject_timestamp_tamper(signed, mode="rollback", ratio=0.2, seed=1)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    bad = set(res.affected_event_ids)
    hit = [f for e, f in zip(res.events, rows) if e["event_id"] in bad]
    assert sum(f["ts_skew"] for f in hit) / len(hit) > 0.3
    assert max(f["ts_skew"] for f in hit) >= 0.9
    assert max(f["ts_monotonic_violation"] for f in rows) >= 0.9
    # 篡改点之前的前缀不受影响，必须保持干净（其后的邻居事件间隔异常属正常响应）
    first_bad = min(i for i, e in enumerate(res.events) if e["event_id"] in bad)
    assert all(f["ts_skew"] < 0.01 for f in rows[:first_bad])


def test_tamper_breaks_hmac_status(signed):
    res = inject_timestamp_tamper(signed, mode="skew", ratio=0.2, seed=4)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    bad = set(res.affected_event_ids)
    for e, f in zip(res.events, rows):
        assert f["hmac_status"] == (0.0 if e["event_id"] in bad else 1.0)


def test_deletion_raises_seq_gap(signed):
    res = inject_log_deletion(signed, mode="block", ratio=0.2, seed=2)
    rows = FeatureExtractor(key=KEY).extract_all(res.events)
    assert max(f["seq_gap_ratio"] for f in rows) == 1.0
    assert sum(1 for f in rows if f["seq_gap_ratio"] > 0) <= 2


def test_host_naming_and_whitelist(signed):
    event = copy.deepcopy(signed[0])
    event["host"] = "BAD_HOST"
    assert FeatureExtractor(key=KEY).observe(event)["host_naming_compliance"] == 0.0
    assert (
        FeatureExtractor(key=KEY, whitelist=("BAD_HOST",)).observe(event)[
            "host_naming_compliance"
        ]
        == 1.0
    )


def test_missing_fields_detected(signed):
    event = copy.deepcopy(signed[0])
    del event["user"]
    f = FeatureExtractor(key=KEY).observe(event)
    assert f["missing_field_ratio"] == pytest.approx(1 / 10)
    assert f["format_compliance"] < 1.0


def test_range_violation(signed):
    event = copy.deepcopy(signed[0])
    event["metrics"] = {"cpu": 999.0, "mem": -5.0, "conn_count": 10**6}
    assert FeatureExtractor(key=KEY).observe(event)["range_violation_ratio"] == 1.0


def test_noise_zigzag_elevated(signed):
    ext = FeatureExtractor(key=KEY)
    rows = []
    for i, base in enumerate(signed[:6]):
        event = copy.deepcopy(base)
        event["metrics"] = {
            "cpu": 5.0 if i % 2 == 0 else 95.0,
            "mem": 20.0 if i % 2 == 0 else 90.0,
            "conn_count": 1.0 if i % 2 == 0 else 500.0,
        }
        rows.append(ext.observe(event))
    assert rows[-1]["numeric_noise_level"] > 0.8


def test_baseline_deviation_outlier(signed):
    ext = FeatureExtractor(key=KEY)
    for e in signed[:30]:
        ext.observe(e)
    outlier = copy.deepcopy(signed[30])
    outlier["metrics"] = {"cpu": 999.0, "mem": -50.0, "conn_count": 10**6}
    f = ext.observe(outlier)
    assert f["baseline_deviation"] > 0.9


def test_rate_anomaly_burst(signed):
    ext = FeatureExtractor(key=KEY)
    rows = ext.extract_all(signed[:30])
    burst = []
    for i, base in enumerate(signed[30:40]):
        event = copy.deepcopy(base)
        event["ts"] = f"2026-11-01T09:00:{i:02d}.000000+00:00"
        burst.append(event)
    rows += ext.extract_all(burst)
    assert max(f["event_rate_anomaly"] for f in rows) > 0.5


def test_extractor_deterministic(signed):
    a = FeatureExtractor(key=KEY).extract_all(signed[:50])
    b = FeatureExtractor(key=KEY).extract_all(signed[:50])
    assert a == b
