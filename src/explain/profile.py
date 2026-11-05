"""⑧ 可解释输出：12 特征 → 方向归一的可疑度画像（贡献度条形图数据源）。

可疑度越高越可疑：合规向特征取 1-值，可疑向特征取原值，全部落在 [0,1]。
"""
from __future__ import annotations

from src.features.extractor import FEATURE_NAMES, HIGHER_IS_WORSE

FEATURE_LABELS = {
    "hmac_status": "HMAC完整性",
    "ts_monotonic_violation": "时序乱序",
    "ts_skew": "时间偏移",
    "seq_gap_ratio": "序列缺口",
    "host_naming_compliance": "主机名规范",
    "source_consistency": "来源一致",
    "format_compliance": "格式合规",
    "missing_field_ratio": "字段缺失",
    "numeric_noise_level": "数值噪声",
    "range_violation_ratio": "数值越界",
    "event_rate_anomaly": "频率异常",
    "baseline_deviation": "基线偏离",
}


def suspicion_profile(features: dict[str, float]) -> dict[str, float]:
    """按固定顺序返回 {特征名: 可疑度 0-1}，高=可疑。"""
    out: dict[str, float] = {}
    for name in FEATURE_NAMES:
        value = float(features.get(name, 0.0))
        out[name] = value if HIGHER_IS_WORSE[name] else 1.0 - value
    return out
