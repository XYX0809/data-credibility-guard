"""② 污染模拟·时间戳篡改：回拨 / 乱序 / 偏移 三模式。

威胁模型：攻击者无 HMAC 密钥，只能改明文副本、不能重签——
被篡改事件的 hmac 字段原样保留（已失效），由 L1 校验层检出。
本模块只负责"攻击侧"注入。
"""
from __future__ import annotations

import argparse
import copy
import random
from datetime import datetime, timedelta
from pathlib import Path

from config.settings import DATA_DIR, RANDOM_STATE
from src.datasource.generator import load_jsonl, save_jsonl
from src.pollution.common import PollutionResult

MODES = ("rollback", "shuffle", "skew")
ROLLBACK_DAYS = (1, 30)
SKEW_DAYS = (30, 180)


def inject_timestamp_tamper(
    events: list[dict],
    *,
    mode: str = "rollback",
    ratio: float = 0.2,
    seed: int = RANDOM_STATE,
) -> PollutionResult:
    """按比例选中事件篡改时间戳，返回新列表与受影响事件 ID（不修改输入）。

    - rollback：时间戳回拨 1-30 天（制造乱序 + 时钟回拨痕迹）
    - shuffle ：选中事件之间轮转换时间戳（多对乱序，时间戳集合不变）
    - skew    ：时间戳偏移 ±30-180 天（伪造年代/大规模时钟漂移）
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到 {mode!r}")
    if not 0.0 <= ratio <= 1.0:
        raise ValueError("ratio 必须在 0-1 之间")

    rng = random.Random(seed)
    tampered = copy.deepcopy(events)
    k = round(len(tampered) * ratio)
    picked = sorted(rng.sample(range(len(tampered)), k)) if k else []

    if mode == "rollback":
        for i in picked:
            delta = timedelta(days=rng.randint(*ROLLBACK_DAYS))
            tampered[i]["ts"] = (datetime.fromisoformat(tampered[i]["ts"]) - delta).isoformat()
    elif mode == "skew":
        for i in picked:
            days = rng.randint(*SKEW_DAYS)
            if rng.random() < 0.5:
                days = -days
            tampered[i]["ts"] = (
                datetime.fromisoformat(tampered[i]["ts"]) + timedelta(days=days)
            ).isoformat()
    else:  # shuffle：选中子集时间戳整体轮转一位，保证每个都变
        stamps = [tampered[i]["ts"] for i in picked]
        if len(stamps) >= 2:
            stamps = stamps[1:] + stamps[:1]
            for i, ts in zip(picked, stamps):
                tampered[i]["ts"] = ts

    affected = [
        tampered[i]["event_id"]
        for i in range(len(tampered))
        if tampered[i]["ts"] != events[i]["ts"]
    ]
    return PollutionResult(
        events=tampered,
        affected_event_ids=affected,
        mode=mode,
        detail={"ratio": ratio, "picked": k, "seed": seed},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="注入时间戳篡改污染（JSONL）")
    parser.add_argument("--in", dest="src", default=str(DATA_DIR / "normal_signed.jsonl"))
    parser.add_argument("--out", default=str(DATA_DIR / "polluted_ts.jsonl"))
    parser.add_argument("--mode", default="rollback", choices=MODES)
    parser.add_argument("--ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    args = parser.parse_args()
    res = inject_timestamp_tamper(
        load_jsonl(Path(args.src)), mode=args.mode, ratio=args.ratio, seed=args.seed
    )
    save_jsonl(Path(args.out), res.events)
    print(f"[时间戳篡改·{res.mode}] 篡改 {len(res.affected_event_ids)} 条 -> {args.out}")


if __name__ == "__main__":
    main()
