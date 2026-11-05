"""大屏推送与服务测试：推送契约、阻断事件、路由与本地依赖。"""
from src.alert.app import WEB_DIR, build_app
from src.alert.feed import PAYLOAD_KEYS, ScoreFeed
from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import sign
from src.engine.scorer import CredibilityEngine
from src.pollution.timestamp_tamper import inject_timestamp_tamper

KEY = b"test-secret"


def _setup():
    stream = [sign(e.to_dict(), KEY) for e in generate_normal_events(300)]
    engine = CredibilityEngine.train(stream[:100], key=KEY)
    return stream, engine


def test_feed_payload_contract():
    stream, engine = _setup()
    collected = []
    feed = ScoreFeed(engine, interval=0, on_emit=lambda name, p: collected.append((name, p)))
    payloads = feed.emit_batch(stream[100:110])
    assert len(payloads) == 10
    assert [name for name, _ in collected] == ["score"] * 10
    for p in payloads:
        assert set(PAYLOAD_KEYS) <= set(p)
        assert 0 <= p["score"] <= 100
        assert p["host"] and p["source_id"]


def test_feed_blocks_polluted():
    stream, engine = _setup()
    polluted = inject_timestamp_tamper(stream[150:250], mode="rollback", ratio=0.3, seed=1)
    collected = []
    feed = ScoreFeed(engine, interval=0, on_emit=lambda name, p: collected.append((name, p)))
    payloads = feed.emit_batch(polluted.events)
    blocked = [p for p in payloads if p["blocked"]]
    assert {p["event_id"] for p in blocked} == set(polluted.affected_event_ids)
    assert sum(1 for name, _ in collected if name == "block") == len(blocked)
    assert all(p["veto"] for p in blocked)


def test_clean_phase_no_blocks():
    stream, engine = _setup()
    payloads = ScoreFeed(engine, interval=0).emit_batch(stream[100:150])
    assert all(not p["blocked"] for p in payloads)


def test_app_routes():
    app, _ = build_app()
    client = app.test_client()
    assert client.get("/").status_code == 200
    assert client.get("/app.js").status_code == 200
    assert b"echarts" in client.get("/").data.lower()


def test_vendor_assets_local():
    for name in ("echarts.min.js", "socket.io.min.js"):
        path = WEB_DIR / "vendor" / name
        assert path.exists() and path.stat().st_size > 30_000
