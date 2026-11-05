"""④ 三层可信度评分引擎（启动方案 §5）。

score = 0.4×S_hmac + 0.4×S_stat + 0.2×S_rule   （clamp 0-100，高=可信）
否决项（HMAC 校验失败 / 规则升级否决）→ score = min(score, 30)
score < 60 → 阻断

三层贡献（s_hmac/s_stat/s_rule）随结果输出，直接喂模块⑧可解释条形图。
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

from config.settings import DATA_DIR, SCORE_THRESHOLD
from src.datasource.generator import load_jsonl
from src.engine.hmac_layer import load_or_create_key
from src.engine.iforest_layer import StatLayer
from src.engine.rule_layer import evaluate_rules
from src.features.extractor import WINDOW, FeatureExtractor, features_to_vector

WEIGHT_HMAC = 0.4
WEIGHT_STAT = 0.4
WEIGHT_RULE = 0.2
VETO_CAP = 30.0


@dataclass
class ScoreResult:
    event_id: str
    score: float
    blocked: bool
    veto: bool
    s_hmac: float
    s_stat: float
    s_rule: float
    rule_hits: list[str] = field(default_factory=list)
    features: dict[str, float] = field(default_factory=dict)


def combine_scores(
    s_hmac: float,
    s_stat: float,
    s_rule: float,
    *,
    veto: bool,
    threshold: float = SCORE_THRESHOLD,
) -> tuple[float, bool]:
    """合成三层分数 → (score, blocked)。"""
    raw = WEIGHT_HMAC * s_hmac + WEIGHT_STAT * s_stat + WEIGHT_RULE * s_rule
    score = min(raw, VETO_CAP) if veto else raw
    score = max(0.0, min(100.0, score))
    return score, score < threshold


class CredibilityEngine:
    """流式评分：train 用干净日志拟合统计层，之后逐条 evaluate。"""

    def __init__(
        self,
        *,
        key: bytes,
        stat: StatLayer,
        extractor: FeatureExtractor,
        threshold: float = SCORE_THRESHOLD,
    ):
        self._key = key
        self._stat = stat
        self._extractor = extractor
        self._threshold = threshold

    @classmethod
    def train(
        cls,
        clean_events: list[dict],
        *,
        key: bytes,
        whitelist: tuple[str, ...] | set[str] = (),
        window: int = WINDOW,
        threshold: float = SCORE_THRESHOLD,
    ) -> "CredibilityEngine":
        extractor = FeatureExtractor(key=key, window=window, whitelist=whitelist)
        feats = extractor.extract_all(clean_events)
        stat = StatLayer().fit([features_to_vector(f) for f in feats])
        return cls(key=key, stat=stat, extractor=extractor, threshold=threshold)

    def evaluate(self, event: dict) -> ScoreResult:
        feats = self._extractor.observe(event)
        s_hmac = feats["hmac_status"] * 100.0
        s_stat = self._stat.score(features_to_vector(feats))
        rules = evaluate_rules(feats)
        veto = rules.veto or feats["hmac_status"] < 1.0
        score, blocked = combine_scores(
            s_hmac, s_stat, rules.score, veto=veto, threshold=self._threshold
        )
        return ScoreResult(
            event_id=str(event.get("event_id", "")),
            score=score,
            blocked=blocked,
            veto=veto,
            s_hmac=s_hmac,
            s_stat=s_stat,
            s_rule=rules.score,
            rule_hits=rules.hits,
            features=feats,
        )

    def evaluate_all(self, events: list[dict]) -> list[ScoreResult]:
        return [self.evaluate(e) for e in events]


def main() -> None:
    parser = argparse.ArgumentParser(description="三层评分引擎演示")
    parser.add_argument("--clean", default=str(DATA_DIR / "normal_signed.jsonl"))
    parser.add_argument("--target", default=str(DATA_DIR / "polluted_ts.jsonl"))
    args = parser.parse_args()

    key = load_or_create_key()
    clean = load_jsonl(Path(args.clean))
    target = load_jsonl(Path(args.target))
    engine = CredibilityEngine.train(clean, key=key)
    results = engine.evaluate_all(target)

    scores = [r.score for r in results]
    blocked = [r for r in results if r.blocked]
    print(f"训练 {len(clean)} 条干净日志；评分 {len(results)} 条")
    if scores:
        print(f"平均 {sum(scores) / len(scores):.1f} 分，最低 {min(scores):.1f} 分，阻断 {len(blocked)} 条")
    for r in blocked[:5]:
        print(f"  [阻断] {r.event_id} {r.score:.1f} 分 规则{r.rule_hits} 否决={r.veto}")


if __name__ == "__main__":
    main()
