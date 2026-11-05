"""② 污染模拟·来源伪造：不规范主机名 / 伪造来源身份 / 冒名顶替。

威胁模型：攻击者无 HMAC 密钥，篡改后不能重签——被改事件的 hmac 字段
原样保留（已失效），由 L1 校验层检出；命名/一致性痕迹由特征 5/6 量化。
所有合成的"坏主机名"均为虚构代号，不使用任何真实默认主机名样例。
"""
from __future__ import annotations

import argparse
import copy
import random
from pathlib import Path

from config.settings import DATA_DIR, RANDOM_STATE
from src.datasource.generator import HOST_POOL, load_jsonl, save_jsonl
from src.pollution.common import PollutionResult

MODES = ("rename_host", "forge_source", "impersonate")


def _unstandard_host(rng: random.Random) -> str:
    """虚构的不规范主机代号：大写杂串+数字，不成规范段式命名。"""
    letters = "".join(rng.choices("QXZJKWV", k=rng.randint(2, 4)))
    return f"{letters}{rng.randint(10, 99)}"


def inject_source_forgery(
    events: list[dict],
    *,
    mode: str = "rename_host",
    ratio: float = 0.2,
    seed: int = RANDOM_STATE,
) -> PollutionResult:
    """按比例伪造事件来源，返回新列表与受影响事件 ID（不修改输入）。

    - rename_host : 主机名换成虚构不规范代号（命名+一致性特征同时触发）
    - forge_source: 来源身份换成与主机不匹配的伪标识（一致性特征触发）
    - impersonate : 冒充其他规范命名主机（命名/一致性均"合规"，只剩 HMAC 能抓）
    """
    if mode not in MODES:
        raise ValueError(f"mode 必须是 {MODES} 之一，收到 {mode!r}")
    if not 0.0 <= ratio <= 1.0:
        raise ValueError("ratio 必须在 0-1 之间")

    rng = random.Random(seed)
    forged = copy.deepcopy(events)
    k = round(len(forged) * ratio)
    picked = sorted(rng.sample(range(len(forged)), k)) if k else []

    for i in picked:
        e = forged[i]
        if mode == "rename_host":
            e["host"] = _unstandard_host(rng)
        elif mode == "forge_source":
            e["source_id"] = f"src_{rng.randint(1000, 9999)}"
        else:  # impersonate
            others = [h for h in HOST_POOL if h != e.get("host")] or list(HOST_POOL)
            fake_host = rng.choice(others)
            e["host"] = fake_host
            e["source_id"] = f"agent-{fake_host}"

    affected = [
        forged[i]["event_id"] for i in range(len(forged)) if forged[i] != events[i]
    ]
    return PollutionResult(
        events=forged,
        affected_event_ids=affected,
        mode=mode,
        detail={"ratio": ratio, "picked": k, "seed": seed},
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="注入来源伪造污染（JSONL）")
    parser.add_argument("--in", dest="src", default=str(DATA_DIR / "normal_signed.jsonl"))
    parser.add_argument("--out", default=str(DATA_DIR / "polluted_src.jsonl"))
    parser.add_argument("--mode", default="rename_host", choices=MODES)
    parser.add_argument("--ratio", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=RANDOM_STATE)
    args = parser.parse_args()
    res = inject_source_forgery(
        load_jsonl(Path(args.src)), mode=args.mode, ratio=args.ratio, seed=args.seed
    )
    save_jsonl(Path(args.out), res.events)
    print(f"[来源伪造·{res.mode}] 伪造 {len(res.affected_event_ids)} 条 -> {args.out}")


if __name__ == "__main__":
    main()
