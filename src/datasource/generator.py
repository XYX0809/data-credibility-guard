"""① 数据源模拟：生成规范命名主机的正常日志流（确定性，可复现）。"""
from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from config.settings import DATA_DIR, RANDOM_STATE
from src.datasource.schema import EVENT_TYPES, LogEvent

HOST_POOL = ("lab-pc-01", "lab-pc-02", "srv-web-01", "srv-db-01", "ops-term-03")
USER_POOL = ("alice", "bob", "carol", "dave", "svc_backup")
IP_PREFIX = "10.20.1."
# 指标物理量程（真实采集值域）：越界 = 物理上不可能的读数
METRIC_RANGES = {"cpu": (0.0, 100.0), "mem": (0.0, 100.0), "conn_count": (0.0, 2000.0)}


def generate_normal_events(
    count: int,
    *,
    seed: int = RANDOM_STATE,
    start_seq: int = 1,
    start_ts: datetime | None = None,
) -> list[LogEvent]:
    rng = random.Random(seed)
    ts = start_ts or datetime(2026, 11, 1, 8, 0, 0, tzinfo=timezone.utc)
    events: list[LogEvent] = []
    for i in range(count):
        seq_no = start_seq + i
        ts = ts + timedelta(seconds=rng.randint(1, 5))
        host = rng.choice(HOST_POOL)
        events.append(
            LogEvent(
                event_id=f"evt-{seq_no:08d}",
                seq_no=seq_no,
                ts=ts.isoformat(),
                host=host,
                source_id=f"agent-{host}",
                event_type=rng.choice(EVENT_TYPES),
                src_ip=f"{IP_PREFIX}{rng.randint(2, 250)}",
                user=rng.choice(USER_POOL),
                metrics={
                    k: round(rng.uniform(lo, hi), 2) for k, (lo, hi) in METRIC_RANGES.items()
                },
            )
        )
    return events


def save_jsonl(path: Path, events: list) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for e in events:
            d = e.to_dict() if isinstance(e, LogEvent) else e
            f.write(json.dumps(d, ensure_ascii=False) + "\n")


def load_jsonl(path: Path) -> list[dict]:
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="生成正常日志数据集（JSONL）")
    parser.add_argument("--count", type=int, default=500)
    parser.add_argument("--out", default=str(DATA_DIR / "normal.jsonl"))
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    args = parser.parse_args()
    events = generate_normal_events(args.count, seed=args.seed)
    save_jsonl(Path(args.out), events)
    print(f"已生成 {len(events)} 条正常日志 -> {args.out}")


if __name__ == "__main__":
    main()
