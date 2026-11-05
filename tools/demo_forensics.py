"""审计取证演示：落盘 → 链校验完整 → 篡改被发现 → 生成报告。"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.datasource.collector import captured_hosts, load_base_events
from src.engine.hmac_layer import load_or_create_key, sign
from src.engine.scorer import CredibilityEngine
from src.forensics.ledger import AuditSink, fetch_summary, verify_chain
from src.forensics.report import generate_report
from src.pollution.timestamp_tamper import inject_timestamp_tamper


def main() -> None:
    parser = argparse.ArgumentParser(description="审计取证演示")
    parser.add_argument("--db", default=str(Path(__file__).resolve().parent.parent / "data" / "audit.db"))
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "data" / "audit_report.html"))
    args = parser.parse_args()

    db = Path(args.db)
    if db.exists():
        db.unlink()

    key = load_or_create_key()
    stream = [sign(e, key) for e in load_base_events(400)]
    engine = CredibilityEngine.train(stream[:150], key=key, whitelist=captured_hosts())
    batch = inject_timestamp_tamper(stream[150:350], mode="rollback", ratio=0.3, seed=1).events

    sink = AuditSink(db, async_mode=True)
    for e in batch:
        sink.record(e, engine.evaluate(e))
    sink.close()

    s = fetch_summary(db)
    print(f"[1/3] 落盘完成：审计 {s['total']} 条，阻断 {s['blocked']} 条，否决 {s['vetoed']} 条（异步批量写入）")
    chain = verify_chain(db)
    print(f"[2/3] 证据链校验：{'完整' if chain['ok'] else '断裂'}（已查 {chain['checked']} 条）")

    # 模拟内部人员偷偷改掉一条阻断记录的分数
    with sqlite3.connect(db) as conn:
        rid = conn.execute("SELECT id FROM audit_log WHERE blocked = 1 LIMIT 1").fetchone()[0]
        conn.execute("UPDATE audit_log SET score = 99 WHERE id = ?", (rid,))
    chain = verify_chain(db)
    status = "完整" if chain["ok"] else f"断裂（断点 id={chain['broken_at_id']}）"
    print(f"[3/3] 篡改记录 id={rid} 的分数后：链{status}")
    print("      —— 任何事后改动都会被证据链发现，这就是'取证'")

    out = generate_report(db, Path(args.out))
    print(f"取证报告已生成 -> {out}")


if __name__ == "__main__":
    main()
