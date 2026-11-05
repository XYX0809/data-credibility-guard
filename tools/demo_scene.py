"""名场面脚本（排位赛 10 分钟只演这两幕）。

第一幕：数据投毒骗过 AI —— 威胁读数被抹平，AI 自信输出错误决策。
第二幕：接入验证层 —— 同批污染被拦截，AI 恢复正确。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.aitarget.target_ai import TargetAI, label_threat
from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import load_or_create_key, sign
from src.engine.scorer import CredibilityEngine
from src.pollution.noise_injection import inject_noise

TRAIN_COUNT = 2000
CLEAN_COUNT = 1000
ATTACK_COUNT = 1000


def build_scene(seed: int = 42):
    key = load_or_create_key()
    stream = [sign(e.to_dict(), key) for e in generate_normal_events(
        TRAIN_COUNT + CLEAN_COUNT + ATTACK_COUNT, seed=seed
    )]
    labels = [label_threat(e) for e in stream]

    train = stream[:TRAIN_COUNT]
    train_y = labels[:TRAIN_COUNT]
    clean_test = stream[TRAIN_COUNT:TRAIN_COUNT + CLEAN_COUNT]
    clean_y = labels[TRAIN_COUNT:TRAIN_COUNT + CLEAN_COUNT]
    attack_base = stream[TRAIN_COUNT + CLEAN_COUNT:]
    attack_y = labels[TRAIN_COUNT + CLEAN_COUNT:]

    ai = TargetAI().fit(train, train_y)

    # 攻击侧：把测试段里全部威胁的数值抹平成温和读数
    threat_events = [e for e, y in zip(attack_base, attack_y) if y == 1]
    masked = inject_noise(threat_events, mode="mask", ratio=1.0, seed=seed)
    masked_map = {e["event_id"]: e for e in masked.events}
    attack_batch = [masked_map.get(e["event_id"], e) for e in attack_base]
    return key, ai, train, clean_test, clean_y, attack_batch, attack_y, set(masked.affected_event_ids)


def run_scene(seed: int = 42) -> str:
    key, ai, train, clean_test, clean_y, attack_batch, attack_y, masked_ids = build_scene(seed)
    threat_total = sum(attack_y)

    out = []
    out.append("=" * 62)
    out.append("名场面 · 第一幕：数据投毒骗过 AI")
    out.append("=" * 62)
    out.append(f"靶子 AI 已在 {len(train)} 条干净日志上完成训练（RandomForest，真分类器）")
    out.append(f"测试流 {len(attack_batch)} 条，其中真实威胁 {threat_total} 条")
    out.append(f"攻击者把 {len(masked_ids)} 条威胁的数值特征全部抹平成温和读数……")

    r = ai.evaluate(attack_batch, attack_y)
    fooled = [
        (p, c) for (p, c), y in zip(r["predictions"], attack_y) if y == 1 and p == 0
    ]
    out.append("[无验证层] AI 决策结果：")
    out.append(f"  错误决策 {r['errors']} 条（威胁判为安全 {len(fooled)} 条），"
               f"错误决策平均自信度 {r['avg_conf_wrong']:.1%}")
    out.append(f"  威胁漏判率 {len(fooled) / max(threat_total, 1):.1%} ←— AI 被骗了，而且很自信")

    out.append("")
    out.append("=" * 62)
    out.append("名场面 · 第二幕：验证层拦截，AI 恢复正确")
    out.append("=" * 62)
    engine = CredibilityEngine.train(train, key=key)
    engine.evaluate_all(clean_test)  # 干净段过一遍，衔接流上下文
    results = engine.evaluate_all(attack_batch)
    blocked = {r.event_id for r in results if r.blocked}
    survivors = [e for e in attack_batch if e["event_id"] not in blocked]
    survive_y = [y for e, y in zip(attack_batch, attack_y) if e["event_id"] not in blocked]

    out.append("同批数据流过 HMAC + 三层评分引擎……")
    out.append(f"  拦截污染数据 {len(blocked)} 条（覆盖伪装威胁 "
               f"{len(blocked & masked_ids)}/{len(masked_ids)}），误拦 "
               f"{len(blocked - masked_ids)} 条")
    r2 = ai.evaluate(survivors, survive_y)
    out.append("[验证层后] AI 决策结果：")
    out.append(f"  通过数据 {r2['n']} 条，准确率 {r2['accuracy']:.1%}，错误决策 {r2['errors']} 条")
    out.append(f"  被拦截的 {len(blocked)} 条转阻断告警——AI 恢复正确")
    out.append("=" * 62)

    # 自检：名场面成立的硬指标
    assert len(blocked & masked_ids) == len(masked_ids), "伪装威胁必须全部被拦截"
    assert r2["errors"] == 0, "拦截后 AI 不应再有错误决策"
    return "\n".join(out) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="名场面：污染骗过 AI → 验证层拦截 → AI 恢复")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    print(run_scene(seed=args.seed))


if __name__ == "__main__":
    main()
