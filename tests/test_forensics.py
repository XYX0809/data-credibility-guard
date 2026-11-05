"""审计取证测试：证据链完整性、篡改检测、异步落盘、报告生成。"""
import sqlite3

from src.engine.scorer import ScoreResult
from src.forensics.ledger import AuditSink, fetch_blocked, fetch_summary, verify_chain
from src.forensics.report import generate_report


def _result(event_id: str, *, blocked: bool = False, score: float = 95.0) -> ScoreResult:
    return ScoreResult(
        event_id=event_id,
        score=score,
        blocked=blocked,
        veto=blocked,
        s_hmac=100.0 if not blocked else 0.0,
        s_stat=90.0,
        s_rule=100.0 if not blocked else 30.0,
        rule_hits=["hmac_invalid"] if blocked else [],
        features={"hmac_status": 1.0},
    )


def _event(i: int) -> dict:
    return {"event_id": f"evt-{i:04d}", "seq_no": i, "ts": f"2026-11-01T08:{i // 60:02d}:{i % 60:02d}+00:00"}


def _fill(db, n=10, blocked_at=()):
    sink = AuditSink(db, async_mode=False)
    for i in range(1, n + 1):
        sink.record(_event(i), _result(f"evt-{i:04d}", blocked=i in blocked_at, score=30.0 if i in blocked_at else 95.0))
    return sink


def test_chain_ok_after_records(tmp_path):
    db = tmp_path / "audit.db"
    _fill(db, n=10, blocked_at=(3, 7))
    chain = verify_chain(db)
    assert chain == {"ok": True, "checked": 10, "broken_at_id": None}
    s = fetch_summary(db)
    assert s["total"] == 10 and s["blocked"] == 2 and s["vetoed"] == 2


def test_chain_detects_update(tmp_path):
    db = tmp_path / "audit.db"
    _fill(db, n=8, blocked_at=(4,))
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE audit_log SET score = 99 WHERE id = 4")
    chain = verify_chain(db)
    assert not chain["ok"]
    assert chain["broken_at_id"] == 4


def test_chain_detects_delete(tmp_path):
    db = tmp_path / "audit.db"
    _fill(db, n=8, blocked_at=(5,))
    with sqlite3.connect(db) as conn:
        conn.execute("DELETE FROM audit_log WHERE id = 3")
    chain = verify_chain(db)
    assert not chain["ok"]


def test_async_sink_flushes_all(tmp_path):
    db = tmp_path / "audit.db"
    sink = AuditSink(db, async_mode=True, batch_size=4)
    for i in range(1, 21):
        sink.record(_event(i), _result(f"evt-{i:04d}"))
    sink.close()
    assert verify_chain(db) == {"ok": True, "checked": 20, "broken_at_id": None}


def test_report_generated(tmp_path):
    db = tmp_path / "audit.db"
    _fill(db, n=12, blocked_at=(2, 9))
    out = generate_report(db, tmp_path / "report.html")
    html = out.read_text(encoding="utf-8")
    assert "审计取证报告" in html
    assert "完整" in html and "断裂" not in html
    assert "evt-0002" in html
    assert fetch_blocked(db) and fetch_blocked(db)[0]["event_id"] == "evt-0002"
