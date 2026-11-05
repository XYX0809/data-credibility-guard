"""② 污染模拟·日志删除：随机抽删 / 整段掩埋。

删除后剩余日志的 HMAC 全部有效（L1 无感），缺口只能靠 seq_no 连续性特征检出。
"""
from __future__ import annotations

import argparse
import copy
import random
from pathlib import Path

from config.settings import DATA_DIR, RANDOM_STATE
from src.datasource.generator import load_jsonl, save_jsonl
from src.pollution.common import PollutionResult

MODES = ("random", "block")


def inject_log_deletion(
    events: list[dict],
    *,
    ratio: float = 0.2,
    seed: int = RANDOM_STATE,
    mode: str = "random",
) -> PollutionResult:
    """按比例删除事件，返回剩余列表与被删事件 ID（不修改输入）。

    - random：随机抽删，产生散点缺口
    - block ：连续整段删除，掩埋某个时间窗口（只剩一个大缺口）
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到 {mode!r}")
    if not 0.0 <= ratio <= 1.0:
        raise ValueError("ratio 必须在 0-1 之间")

    rng = random.Random(seed)
    source = copy.deepcopy(events)
    k = round(len(source) * ratio)
    if k == 0:
        drop: set[int] = set()
    elif mode == "random":
        drop = set(rng.sample(range(len(source)), k))
    else:  # block
        start = rng.randint(0, len(source) - k)
        drop = set(range(start, start + k))

    deleted_ids = [source[i]["event_id"] for i in sorted(drop)]
    deleted_seq_nos = [source[i]["seq_no"] for i in sorted(drop)]
    remaining = [e for i, e in enumerate(source) if i not in drop]
    return PollutionResult(
        events=remaining,
        affected_event_ids=deleted_ids,
        mode=mode,
        detail={
            "ratio": ratio,
            "deleted": k,
            "deleted_seq_nos": deleted_seq_nos,
            "seed": seed,
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="注入日志删除污染（JSONL）")
    parser.add_argument("--in", dest="src", default=str(DATA_DIR / "normal_signed.jsonl"))
    parser.add_argument("--out", default=str(DATA_DIR / "polluted_del.jsonl"))
    parser.add_argument("--mode", default="random", choices=MODES)
    parser.add_argument("--ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    args = parser.parse_args()
    res = inject_log_deletion(
        load_jsonl(Path(args.src)), mode=args.mode, ratio=args.ratio, seed=args.seed
    )
    save_jsonl(Path(args.out), res.events)
    print(f"[日志删除·{res.mode}] 删除 {len(res.affected_event_ids)} 条 -> {args.out}")


if __name__ == "__main__":
    main()
