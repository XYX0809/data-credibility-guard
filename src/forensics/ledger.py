"""⑦ 审计取证：SQLite 证据链（哈希链防篡改）+ 异步落盘（与评分热路径解耦）。

每条记录携带前条哈希与本条哈希：任何修改/删除都会让链条校验失败并定位到断点。
"""
from __future__ import annotations

import hashlib
import json
import queue
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from src.engine.scorer import ScoreResult

GENESIS = "0" * 64


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


class AuditSink:
    """评分结果写入证据链。async_mode=True 时后台线程批量落盘，不拖慢评分。"""

    def __init__(self, db_path: Path, *, async_mode: bool = True, batch_size: int = 50):
        self._db_path = Path(db_path)
        self._batch_size = batch_size
        self._async = async_mode
        self._lock = threading.Lock()
        self._init_db()
        self._prev_hash = self._last_hash()
        self._queue: queue.Queue | None = None
        self._worker: threading.Thread | None = None
        if async_mode:
            self._queue = queue.Queue()
            self._worker = threading.Thread(target=self._drain, daemon=True)
            self._worker.start()

    def _init_db(self) -> None:
        with _connect(self._db_path) as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL,
                    seq_no INTEGER,
                    event_ts TEXT,
                    score REAL,
                    blocked INTEGER,
                    veto INTEGER,
                    s_hmac REAL,
                    s_stat REAL,
                    s_rule REAL,
                    rule_hits TEXT,
                    features TEXT,
                    event_raw TEXT,
                    recorded_at TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    row_hash TEXT NOT NULL
                )"""
            )

    def _last_hash(self) -> str:
        with _connect(self._db_path) as conn:
            row = conn.execute(
                "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return row[0] if row else GENESIS

    def record(self, event: dict, result: ScoreResult) -> None:
        row = self._build_row(event, result)
        if self._async:
            self._queue.put(row)
        else:
            self._insert_batch([row])

    def close(self) -> None:
        if self._worker is not None:
            self._queue.put(None)
            self._worker.join(timeout=10)

    def _build_row(self, event: dict, result: ScoreResult) -> dict:
        with self._lock:
            content = {
                "event_id": result.event_id,
                "seq_no": event.get("seq_no"),
                "event_ts": event.get("ts"),
                "score": round(result.score, 4),
                "blocked": int(result.blocked),
                "veto": int(result.veto),
                "s_hmac": round(result.s_hmac, 4),
                "s_stat": round(result.s_stat, 4),
                "s_rule": round(result.s_rule, 4),
                "rule_hits": result.rule_hits,
                "features": result.features,
                "event_raw": event,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
            prev = self._prev_hash
            row_hash = hashlib.sha256(prev.encode() + _canonical(content)).hexdigest()
            self._prev_hash = row_hash
            return {**content, "prev_hash": prev, "row_hash": row_hash}

    def _insert_batch(self, rows: list[dict]) -> None:
        with _connect(self._db_path) as conn:
            conn.executemany(
                """INSERT INTO audit_log
                   (event_id, seq_no, event_ts, score, blocked, veto,
                    s_hmac, s_stat, s_rule, rule_hits, features, event_raw,
                    recorded_at, prev_hash, row_hash)
                   VALUES (:event_id, :seq_no, :event_ts, :score, :blocked, :veto,
                    :s_hmac, :s_stat, :s_rule, :rule_hits, :features, :event_raw,
                    :recorded_at, :prev_hash, :row_hash)""",
                [
                    {
                        **r,
                        "rule_hits": json.dumps(r["rule_hits"], ensure_ascii=False),
                        "features": json.dumps(r["features"], ensure_ascii=False),
                        "event_raw": json.dumps(r["event_raw"], ensure_ascii=False),
                    }
                    for r in rows
                ],
            )

    def _drain(self) -> None:
        batch: list[dict] = []
        while True:
            item = self._queue.get()
            if item is None:
                break
            batch.append(item)
            if len(batch) >= self._batch_size:
                self._insert_batch(batch)
                batch = []
        if batch:
            self._insert_batch(batch)


def verify_chain(db_path: Path) -> dict:
    """逐条重算哈希链：返回是否完整、检查条数、断点记录 id。"""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT id, event_id, seq_no, event_ts, score, blocked, veto,
                      s_hmac, s_stat, s_rule, rule_hits, features, event_raw,
                      recorded_at, prev_hash, row_hash
               FROM audit_log ORDER BY id"""
        ).fetchall()

    prev = GENESIS
    for checked, row in enumerate(rows, start=1):
        (rid, event_id, seq_no, event_ts, score, blocked, veto,
         s_hmac, s_stat, s_rule, rule_hits, features, event_raw,
         recorded_at, prev_hash, row_hash) = row
        content = {
            "event_id": event_id,
            "seq_no": seq_no,
            "event_ts": event_ts,
            "score": score,
            "blocked": blocked,
            "veto": veto,
            "s_hmac": s_hmac,
            "s_stat": s_stat,
            "s_rule": s_rule,
            "rule_hits": json.loads(rule_hits),
            "features": json.loads(features),
            "event_raw": json.loads(event_raw),
            "recorded_at": recorded_at,
        }
        expected = hashlib.sha256(prev.encode() + _canonical(content)).hexdigest()
        if prev_hash != prev or row_hash != expected:
            return {"ok": False, "checked": checked, "broken_at_id": rid}
        prev = row_hash
    return {"ok": True, "checked": len(rows), "broken_at_id": None}


def fetch_summary(db_path: Path) -> dict:
    with _connect(db_path) as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        blocked = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE blocked = 1"
        ).fetchone()[0]
        vetoed = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE veto = 1"
        ).fetchone()[0]
        window = conn.execute(
            "SELECT MIN(event_ts), MAX(event_ts) FROM audit_log"
        ).fetchone()
        hits_rows = conn.execute(
            "SELECT rule_hits FROM audit_log WHERE rule_hits != '[]'"
        ).fetchall()
    hits: dict[str, int] = {}
    for (raw,) in hits_rows:
        for h in json.loads(raw):
            hits[h] = hits.get(h, 0) + 1
    return {
        "total": total,
        "blocked": blocked,
        "vetoed": vetoed,
        "hits": dict(sorted(hits.items(), key=lambda kv: -kv[1])),
        "window_from": window[0] or "",
        "window_to": window[1] or "",
    }


def fetch_blocked(db_path: Path, limit: int = 200) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT id, event_id, seq_no, event_ts, score, rule_hits, veto, recorded_at
               FROM audit_log WHERE blocked = 1 ORDER BY id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [
        {
            "id": r[0],
            "event_id": r[1],
            "seq_no": r[2],
            "event_ts": r[3],
            "score": r[4],
            "rule_hits": json.loads(r[5]),
            "veto": bool(r[6]),
            "recorded_at": r[7],
        }
        for r in rows
    ]
