"""可解释输出测试：可疑度方向归一与推送载荷。"""
import pytest

from src.alert.feed import PAYLOAD_KEYS, result_payload
from src.engine.scorer import ScoreResult
from src.explain.profile import FEATURE_LABELS, suspicion_profile
from src.features.extractor import FEATURE_NAMES


def _features(**overrides):
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


def test_profile_keys_and_order():
    profile = suspicion_profile(_features())
    assert list(profile) == list(FEATURE_NAMES)
    assert set(FEATURE_LABELS) == set(FEATURE_NAMES)


def test_direction_normalization():
    clean = suspicion_profile(_features())
    assert clean["hmac_status"] == 0.0  # 合规向：好事件可疑度为 0
    assert clean["ts_monotonic_violation"] == 0.0
    assert clean["numeric_noise_level"] == pytest.approx(0.3)

    bad = suspicion_profile(_features(hmac_status=0.0, ts_skew=0.9, missing_field_ratio=0.4))
    assert bad["hmac_status"] == 1.0
    assert bad["ts_skew"] == pytest.approx(0.9)
    assert bad["missing_field_ratio"] == pytest.approx(0.4)
    assert bad["host_naming_compliance"] == 0.0


def test_profile_bounds():
    for profile in (
        suspicion_profile(_features()),
        suspicion_profile(_features(hmac_status=0.0, numeric_noise_level=1.0)),
    ):
        assert all(0.0 <= v <= 1.0 for v in profile.values())


def test_payload_carries_suspicions():
    result = ScoreResult(
        event_id="evt-1", score=30.0, blocked=True, veto=True,
        s_hmac=0.0, s_stat=20.0, s_rule=10.0,
        rule_hits=["hmac_invalid"], features=_features(hmac_status=0.0),
    )
    payload = result_payload({"seq_no": 1}, result)
    assert "suspicions" in PAYLOAD_KEYS
    assert set(payload["suspicions"]) == set(FEATURE_NAMES)
    assert payload["suspicions"]["hmac_status"] == 1.0
