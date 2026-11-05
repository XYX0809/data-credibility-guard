"""L3 规则兜底层：硬规则拉底 + 主机名扣分（启动方案 §5、§9-1 已定口径）。

主机名不规范只扣分（默认 15 分），不做硬否决；与其他异常叠加时才升级为否决。
"""
from __future__ import annotations

from dataclasses import dataclass

from config.settings import HOSTNAME_PENALTY

HMAC_FLOOR = 10.0
FORMAT_FLOOR = 20.0
SEQ_GAP_FLOOR = 30.0
FORMAT_BAD = 0.6


@dataclass
class RuleResult:
    score: float
    hits: list[str]
    veto: bool


def evaluate_rules(
    features: dict[str, float], *, hostname_penalty: float = HOSTNAME_PENALTY
) -> RuleResult:
    """基于 12 特征做规则判定：返回规则分（0-100）、命中清单、是否升级否决。"""
    score = 100.0
    hits: list[str] = []
    other_hit = False

    if features["hmac_status"] < 1.0:
        score = min(score, HMAC_FLOOR)
        hits.append("hmac_invalid")
        other_hit = True
    if features["format_compliance"] < FORMAT_BAD:
        score = min(score, FORMAT_FLOOR)
        hits.append("format_broken")
        other_hit = True
    # 本系统 seq_no 严格连续：出现任何缺口即视为日志删除痕迹
    if features["seq_gap_ratio"] > 0.0:
        score = min(score, SEQ_GAP_FLOOR)
        hits.append("seq_gap")
        other_hit = True

    veto = False
    if features["host_naming_compliance"] < 1.0:
        score -= hostname_penalty
        hits.append("hostname_nonstandard")
        veto = other_hit  # 与其他异常叠加才升级否决

    return RuleResult(score=max(score, 0.0), hits=hits, veto=veto)
