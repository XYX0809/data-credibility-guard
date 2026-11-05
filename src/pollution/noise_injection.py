"""② 污染模拟·噪声注入：数值高频抖动 / 越界尖峰。

威胁模型：攻击者无 HMAC 密钥，篡改后不能重签——被改事件的 hmac 字段
原样保留（已失效），由 L1 校验层检出；噪声与越界由特征 9/10 量化。
"""
from __future__ import annotations

import argparse
import copy
import random
from pathlib import Path

from config.settings import DATA_DIR, RANDOM_STATE
from src.datasource.generator import METRIC_RANGES, load_jsonl, save_jsonl
from src.pollution.common import PollutionResult

MODES = ("jitter", "spike")


def inject_noise(
    events: list[dict],
    *,
    mode: str = "jitter",
    ratio: float = 0.2,
    seed: int = RANDOM_STATE,
) -> PollutionResult:
    """按比例污染数值字段，返回新列表与受影响事件 ID（不修改输入）。

    - jitter: 数值在合法区间两端交替锯齿（高频噪声，区间内不越界）
    - spike : 数值直接打出合法区间 3-8 倍（越界尖峰）
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到 {mode!r}")
    if not 0.0 <= ratio <= 1.0:
        raise ValueError("ratio 必须在 0-1 之间")

    rng = random.Random(seed)
    noisy = copy.deepcopy(events)
    k = round(len(noisy) * ratio)
    picked = sorted(rng.sample(range(len(noisy)), k)) if k else []

    for seq, i in enumerate(picked):
        metrics = noisy[i].get("metrics")
        if not isinstance(metrics, dict):
            continue
        for key, (lo, hi) in METRIC_RANGES.items():
            if key not in metrics:
                continue
            if mode == "jitter":
                metrics[key] = round(lo + 0.5 if seq % 2 == 0 else hi - 0.5, 2)
            else:  # spike
                metrics[key] = round(hi * rng.uniform(3, 8), 2)

    affected = [
        noisy[i]["event_id"] for i in range(len(noisy)) if noisy[i] != events[i]
    ]
    return PollutionResult(
        events=noisy,
        affected_event_ids=affected,
        mode=mode,
        detail={"ratio": ratio, "picked": k, "seed": seed},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="注入噪声污染（JSONL）")
    parser.add_argument("--in", dest="src", default=str(DATA_DIR / "normal_signed.jsonl"))
    parser.add_argument("--out", default=str(DATA_DIR / "polluted_noise.jsonl"))
    parser.add_argument("--mode", default="jitter", choices=MODES)
    parser.add_argument("--ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    args = parser.parse_args()
    res = inject_noise(
        load_jsonl(Path(args.src)), mode=args.mode, ratio=args.ratio, seed=args.seed
    )
    save_jsonl(Path(args.out), res.events)
    print(f"[噪声注入·{res.mode}] 污染 {len(res.affected_event_ids)} 条 -> {args.out}")


if __name__ == "__main__":
    main()
