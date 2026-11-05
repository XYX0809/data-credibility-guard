"""B0/B1/B2 基线评测脚手架（启动方案 §8-2）：同一污染集出四类检出率/误报率表。

基线定义：
  B0 无验证   —— 全放行，检出恒为 0（对照组）
  B1 仅规则   —— 命名/格式/缺口/越界四条阈值规则（无密码学、无统计模型）
  B2 完整方案 —— HMAC + IsolationForest + 规则兜底三层合成（阈值 60 阻断）

检出口径：篡改/伪造/噪声按受影响事件计；日志删除的被删事件本身不可观测，
按"缺口边界事件"（洞口后的第一条日志）计检出。
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import load_or_create_key, sign
from src.engine.scorer import CredibilityEngine
from src.features.extractor import FeatureExtractor
from src.pollution.log_deletion import inject_log_deletion
from src.pollution.noise_injection import inject_noise
from src.pollution.source_forgery import inject_source_forgery
from src.pollution.timestamp_tamper import inject_timestamp_tamper

TRAIN_COUNT = 400
CLEAN_COUNT = 200
BATCH_COUNT = 200
POLLUTE_RATIO = 0.15

CASES = [
    ("时间戳篡改", inject_timestamp_tamper, {"mode": "rollback"}),
    ("时间戳篡改", inject_timestamp_tamper, {"mode": "shuffle"}),
    ("时间戳篡改", inject_timestamp_tamper, {"mode": "skew"}),
    ("日志删除", inject_log_deletion, {"mode": "random"}),
    ("日志删除", inject_log_deletion, {"mode": "block"}),
    ("来源伪造", inject_source_forgery, {"mode": "rename_host"}),
    ("来源伪造", inject_source_forgery, {"mode": "forge_source"}),
    ("来源伪造", inject_source_forgery, {"mode": "impersonate"}),
    ("噪声注入", inject_noise, {"mode": "jitter"}),
    ("噪声注入", inject_noise, {"mode": "spike"}),
]


def boundary_ids(events: list[dict]) -> list[str]:
    """缺口边界事件：序列号不连续处的下一条（日志删除的可观测痕迹）。"""
    ids: list[str] = []
    prev: int | None = None
    for e in events:
        seq = e.get("seq_no")
        if isinstance(seq, int) and prev is not None and seq - prev > 1:
            ids.append(e["event_id"])
        if isinstance(seq, int):
            prev = seq
    return ids


def rule_flag_b1(features: dict[str, float]) -> bool:
    """B1 阈值规则：命名不合规 / 格式崩坏 / 大缺口 / 数值越界。"""
    return (
        features["host_naming_compliance"] < 1.0
        or features["format_compliance"] < 0.6
        or features["seq_gap_ratio"] >= 0.5
        or features["range_violation_ratio"] > 0.0
    )


def _rates(flags: list[bool], truth: set[str], event_ids: list[str]) -> tuple[float, float]:
    """返回 (检出率, 误报率)。truth 为空视为无可检对象。"""
    flagged = {eid for eid, f in zip(event_ids, flags) if f}
    tp = len(flagged & truth)
    fp = len(flagged - truth)
    fn = len(truth - flagged)
    tn = len(event_ids) - tp - fp - fn
    detect = tp / len(truth) if truth else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return detect, fpr


def _percentile_ms(samples_ms: list[float], q: float) -> float:
    if not samples_ms:
        return 0.0
    ordered = sorted(samples_ms)
    idx = min(int(q * len(ordered)), len(ordered) - 1)
    return ordered[idx]


def evaluate_case(train, clean_eval, batch, truth_ids, key) -> dict:
    """跑三基线，返回该污染用例的指标。"""
    combined = clean_eval + batch
    combined_ids = [e["event_id"] for e in combined]
    clean_ids = {e["event_id"] for e in clean_eval}
    truth = set(truth_ids)
    result = {}

    # B0：全放行
    result["B0"] = (0.0, 0.0, 0.0, 0.0)

    # B1：特征 + 阈值规则
    t0 = time.perf_counter()
    ext = FeatureExtractor(key=key)
    feats = ext.extract_all(combined)
    b1_lat = (time.perf_counter() - t0) * 1000.0 / max(len(combined), 1)
    flags = [rule_flag_b1(f) for f in feats]
    det, _ = _rates(flags, truth, combined_ids)
    fpr_clean = sum(1 for eid, f in zip(combined_ids, flags) if f and eid in clean_ids) / max(len(clean_ids), 1)
    result["B1"] = (det, fpr_clean, b1_lat, b1_lat)

    # B2：三层完整方案
    engine = CredibilityEngine.train(train, key=key)
    lat_ms = []
    flags = []
    for e in combined:
        t0 = time.perf_counter()
        r = engine.evaluate(e)
        lat_ms.append((time.perf_counter() - t0) * 1000.0)
        flags.append(r.blocked)
    det, _ = _rates(flags, truth, combined_ids)
    fpr_clean = sum(1 for eid, f in zip(combined_ids, flags) if f and eid in clean_ids) / max(len(clean_ids), 1)
    result["B2"] = (det, fpr_clean, sum(lat_ms) / max(len(lat_ms), 1), _percentile_ms(lat_ms, 0.95))
    return result


def run_eval(seed: int = 42, ratio: float = POLLUTE_RATIO) -> tuple[str, dict]:
    key = load_or_create_key()
    stream = [sign(e.to_dict(), key) for e in generate_normal_events(
        TRAIN_COUNT + CLEAN_COUNT + BATCH_COUNT, seed=seed
    )]
    train = stream[:TRAIN_COUNT]
    clean_eval = stream[TRAIN_COUNT:TRAIN_COUNT + CLEAN_COUNT]
    base = stream[TRAIN_COUNT + CLEAN_COUNT:]

    rows = []
    type_acc: dict[str, list[tuple[float, float]]] = {}
    b2_lat = []
    for label, inject, kwargs in CASES:
        res = inject(base, ratio=ratio, seed=seed, **kwargs)
        if label == "日志删除":
            truth = boundary_ids(res.events)
        else:
            truth = res.affected_event_ids
        m = evaluate_case(train, clean_eval, res.events, truth, key)
        rows.append((label, kwargs["mode"], m))
        type_acc.setdefault(label, []).append((m["B1"][0], m["B2"][0]))
        b2_lat.append((m["B2"][2], m["B2"][3]))

    lines = [
        "# B0/B1/B2 基线评测报告",
        "",
        f"seed={seed}　污染率={ratio:.0%}　训练 {TRAIN_COUNT} / 干净 {CLEAN_COUNT} / 污染批 {BATCH_COUNT}",
        "",
        "| 污染类型 | 模式 | B0 检出 | B1 检出 | B2 检出 | B1 误报 | B2 误报 |",
        "|---|---|---|---|---|---|---|",
    ]
    for label, mode, m in rows:
        b0, b1, b2 = m["B0"], m["B1"], m["B2"]
        lines.append(
            f"| {label} | {mode} | {b0[0]:.0%} | {b1[0]:.0%} | {b2[0]:.0%} | {b1[1]:.1%} | {b2[1]:.1%} |"
        )
    def _avg(vals):
        return sum(vals) / len(vals) if vals else 0.0

    lines += [
        "",
        "四类类型均值（B1 仅规则）：" + "　".join(
            f"{k} {_avg([x[0] for x in v]):.0%}" for k, v in type_acc.items()
        ),
        "四类类型均值（B2 完整方案）：" + "　".join(
            f"{k} {_avg([x[1] for x in v]):.0%}" for k, v in type_acc.items()
        ),
    ]
    lat_b2 = sum(x[0] for x in b2_lat) / len(b2_lat)
    lat_b2_p95 = sum(x[1] for x in b2_lat) / len(b2_lat)
    lines += [
        "",
        f"B2 时延：均值 {lat_b2:.2f} ms/条，p95 {lat_b2_p95:.2f} ms/条（目标 <100ms）",
        "",
        "口径：日志删除按缺口边界事件计检出；误报率按干净段计。",
    ]
    report = "\n".join(lines) + "\n"
    summary = {
        "type_avg": {k: (sum(x[0] for x in v) / len(v), sum(x[1] for x in v) / len(v)) for k, v in type_acc.items()},
        "b2_latency": (lat_b2, lat_b2_p95),
    }
    return report, summary


def main() -> None:
    parser = argparse.ArgumentParser(description="B0/B1/B2 基线评测")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--ratio", type=float, default=POLLUTE_RATIO)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "data" / "eval_baseline_report.md"))
    args = parser.parse_args()

    report, _ = run_eval(seed=args.seed, ratio=args.ratio)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(report)
    print(f"报告已写入 {out}")


if __name__ == "__main__":
    main()
