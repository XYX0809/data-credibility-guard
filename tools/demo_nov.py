"""11 月演示：大屏一键跑『正常流 → 污染流 → 评分实时下跌 → 破阈值阻断』，默认循环回放。"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.alert.app import run_dashboard
from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import load_or_create_key, sign
from src.engine.scorer import CredibilityEngine
from src.pollution.timestamp_tamper import inject_timestamp_tamper


def make_round():
    """每轮重建引擎与数据（同种子可复现），供循环回放。"""
    key = load_or_create_key()
    events = [sign(e.to_dict(), key) for e in generate_normal_events(400)]
    engine = CredibilityEngine.train(events[:100], key=key)
    clean = events[100:250]
    polluted = inject_timestamp_tamper(
        events[250:400], mode="rollback", ratio=0.5, seed=1
    ).events
    return engine, [
        ("正常数据流", clean, 1.5),
        ("注入污染·时间戳篡改", polluted, 0.0),
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="11 月演示：大屏评分实时下跌（默认循环回放）")
    parser.add_argument("--interval", type=float, default=0.05, help="每条事件推送间隔（秒）")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--once", action="store_true", help="只播一轮，不循环")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    mode = "单轮" if args.once else "循环回放"
    print(f"演示就绪（{mode}）：打开 http://127.0.0.1:{args.port}")
    run_dashboard(
        make_round,
        interval=args.interval,
        port=args.port,
        open_browser=not args.no_browser,
        loop=not args.once,
    )


if __name__ == "__main__":
    main()
