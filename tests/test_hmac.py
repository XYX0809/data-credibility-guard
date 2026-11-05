import json

import pytest

from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import canonical_json, load_or_create_key, sign, verify


@pytest.fixture
def key(tmp_path):
    return load_or_create_key(tmp_path / "source.key")


def _signed(key, count=5):
    return [sign(e.to_dict(), key) for e in generate_normal_events(count)]


def test_sign_then_verify_passes(key):
    assert all(verify(e, key) for e in _signed(key))


def test_tamper_any_field_fails(key):
    signed = _signed(key, count=1)[0]
    for field, new_value in [
        ("ts", "2020-01-01T00:00:00+00:00"),
        ("user", "mallory"),
        ("host", "evil-01"),
    ]:
        bad = dict(signed)
        bad[field] = new_value
        assert not verify(bad, key), f"篡改 {field} 后应校验失败"


def test_tamper_metrics_fails(key):
    bad = dict(_signed(key, count=1)[0])
    bad["metrics"] = {**bad["metrics"], "cpu": 99.9}
    assert not verify(bad, key)


def test_missing_hmac_fails(key):
    signed = _signed(key, count=1)[0]
    bad = {k: v for k, v in signed.items() if k != "hmac"}
    assert not verify(bad, key)


def test_wrong_key_fails(key, tmp_path):
    other = load_or_create_key(tmp_path / "other.key")
    assert not verify(_signed(key, count=1)[0], other)


def test_key_order_irrelevant(key):
    signed = _signed(key, count=1)[0]
    shuffled = dict(reversed(list(signed.items())))
    assert verify(shuffled, key)


def test_canonical_json_stable():
    a = {"b": 1, "a": {"y": 2, "x": 3}}
    b = {"a": {"x": 3, "y": 2}, "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_sign_is_deterministic(key):
    signed = _signed(key, count=1)[0]
    body = {k: v for k, v in signed.items() if k != "hmac"}
    assert sign(body, key) == signed
    assert json.dumps(sign(body, key), sort_keys=True) == json.dumps(signed, sort_keys=True)
