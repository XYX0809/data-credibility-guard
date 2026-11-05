"""③ 12 特征提取：事件级滑动窗口 + 在线基线，全部归一到 [0,1]。

特征方向（HIGHER_IS_WORSE=True 表示值越大越可疑）：
 1 hmac_status             签名校验通过=1（合规向）
 2 ts_monotonic_violation  窗口内时间戳乱序/回拨次数归一（可疑向）
 3 ts_skew                 到达间隔与窗口中位数的偏差（可疑向）
 4 seq_gap_ratio           序列号缺口比例（可疑向）
 5 host_naming_compliance  主机名规范或白名单=1（合规向）
 6 source_consistency      来源身份与主机绑定一致=1（合规向）
 7 format_compliance       字段格式合规率（合规向）
 8 missing_field_ratio     必填字段缺失率（可疑向）
 9 numeric_noise_level     数值字段高频波动（可疑向）
10 range_violation_ratio   数值越界率（可疑向）
11 event_rate_anomaly      事件频率突变（可疑向）
12 baseline_deviation      与该主机历史画像偏离（可疑向）
"""
from __future__ import annotations

import argparse
import re
from collections import deque
from datetime import datetime
from pathlib import Path
from statistics import median

from config.settings import DATA_DIR, RANDOM_STATE  # noqa: F401  (RANDOM_STATE 供调用方默认值)
from src.datasource.generator import METRIC_RANGES, load_jsonl, save_jsonl
from src.datasource.schema import EVENT_TYPES
from src.engine.hmac_layer import load_or_create_key, verify

FEATURE_NAMES = (
    "hmac_status",
    "ts_monotonic_violation",
    "ts_skew",
    "seq_gap_ratio",
    "host_naming_compliance",
    "source_consistency",
    "format_compliance",
    "missing_field_ratio",
    "numeric_noise_level",
    "range_violation_ratio",
    "event_rate_anomaly",
    "baseline_deviation",
)

HIGHER_IS_WORSE = {
    "hmac_status": False,
    "ts_monotonic_violation": True,
    "ts_skew": True,
    "seq_gap_ratio": True,
    "host_naming_compliance": False,
    "source_consistency": False,
    "format_compliance": False,
    "missing_field_ratio": True,
    "numeric_noise_level": True,
    "range_violation_ratio": True,
    "event_rate_anomaly": True,
    "baseline_deviation": True,
}

WINDOW = 20
SKEW_NORM_SECONDS = 86400.0  # 偏差达 1 天即满格
MONOTONIC_NORM = 3.0
RATE_HISTORY = 60

HOST_NAME_RE = re.compile(r"^[a-z]{2,12}(-[a-z0-9]{1,12}){1,3}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
USER_RE = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
REQUIRED_FIELDS = (
    "event_id",
    "seq_no",
    "ts",
    "host",
    "source_id",
    "event_type",
    "src_ip",
    "user",
    "metrics",
    "schema_ver",
)


def _parse_ts(value) -> datetime | None:
    try:
        return datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def features_to_vector(feats: dict[str, float]) -> list[float]:
    """按固定顺序转成 sklearn 可用的数值向量。"""
    return [float(feats[name]) for name in FEATURE_NAMES]


class FeatureExtractor:
    """流式特征提取：observe 一条算一条，喂给评分引擎。"""

    def __init__(
        self,
        *,
        key: bytes | None = None,
        window: int = WINDOW,
        whitelist: tuple[str, ...] | set[str] = (),
    ):
        self._key = key
        self._window = max(2, window)
        self._whitelist = frozenset(whitelist)
        self._history: deque[dict] = deque(maxlen=self._window)
        self._host_source: dict[str, set[str]] = {}
        self._host_stats: dict[str, dict[str, list[float]]] = {}
        self._rates: deque[float] = deque(maxlen=RATE_HISTORY)

    def observe(self, event: dict) -> dict[str, float]:
        """计算当前事件的 12 特征，然后把事件并入历史（不修改传入对象）。"""
        recent = list(self._history)[-(self._window - 1) :] + [event]
        feats = self._compute(event, recent)
        self._update_state(event, recent)
        return feats

    def extract_all(self, events: list[dict]) -> list[dict[str, float]]:
        """与输入等长对齐：feats[i] 对应 events[i]。"""
        return [self.observe(e) for e in events]

    # ---------- 内部计算 ----------

    def _compute(self, event: dict, recent: list[dict]) -> dict[str, float]:
        f: dict[str, float] = {}

        # 1 完整性
        if self._key is not None:
            ok = verify(event, self._key)
        else:
            ok = bool(event.get("hmac"))
        f["hmac_status"] = 1.0 if ok else 0.0

        # 2/3 时间戳乱序与偏移
        stamps = [_parse_ts(e.get("ts")) for e in recent]
        violations = 0
        prev = None
        for s in stamps:
            if s is None or (prev is not None and s < prev):
                violations += 1
            if s is not None:
                prev = s
        f["ts_monotonic_violation"] = min(violations / MONOTONIC_NORM, 1.0)

        if len(stamps) >= 2 and stamps[-1] is not None and stamps[-2] is not None:
            deltas = [
                (b - a).total_seconds()
                for a, b in zip(stamps, stamps[1:])
                if a is not None and b is not None
            ]
            cur = (stamps[-1] - stamps[-2]).total_seconds()
            med = median(deltas) if deltas else 0.0
            f["ts_skew"] = min(abs(cur - med) / SKEW_NORM_SECONDS, 1.0)
        else:
            f["ts_skew"] = 0.0

        # 4 序列号缺口
        seq = event.get("seq_no")
        prev_seq = self._history[-1].get("seq_no") if self._history else None
        if isinstance(seq, int) and isinstance(prev_seq, int):
            gap = max(0, seq - prev_seq - 1)
            f["seq_gap_ratio"] = min(gap / self._window, 1.0)
        else:
            f["seq_gap_ratio"] = 0.0

        # 5 主机名规范性
        host = event.get("host") or ""
        f["host_naming_compliance"] = (
            1.0 if host in self._whitelist or HOST_NAME_RE.match(host) else 0.0
        )

        # 6 来源一致性
        src = event.get("source_id") or ""
        if src and (src == f"agent-{host}" or src in self._host_source.get(host, ())):
            f["source_consistency"] = 1.0
        else:
            f["source_consistency"] = 0.0

        # 7 格式合规率
        checks = (
            _parse_ts(event.get("ts")) is not None,
            bool(IP_RE.match(event.get("src_ip") or "")),
            event.get("event_type") in EVENT_TYPES,
            bool(USER_RE.match(event.get("user") or "")),
            isinstance(event.get("host"), str) and bool(event.get("host")),
            isinstance(event.get("event_id"), str) and bool(event.get("event_id")),
        )
        f["format_compliance"] = sum(checks) / len(checks)

        # 8 字段缺失率
        missing = sum(1 for name in REQUIRED_FIELDS if event.get(name) in (None, ""))
        f["missing_field_ratio"] = missing / len(REQUIRED_FIELDS)

        # 9 数值噪声（窗口内二阶差分粗度）
        series: dict[str, list[float]] = {k: [] for k in METRIC_RANGES}
        for e in recent:
            m = e.get("metrics") or {}
            for k in series:
                v = m.get(k)
                if isinstance(v, (int, float)):
                    series[k].append(float(v))
        roughs = []
        for k, vals in series.items():
            if len(vals) >= 3:
                width = METRIC_RANGES[k][1] - METRIC_RANGES[k][0]
                d2 = [
                    abs(vals[i] - (vals[i - 1] + vals[i + 1]) / 2)
                    for i in range(1, len(vals) - 1)
                ]
                roughs.append(min((sum(d2) / len(d2)) / width, 1.0))
        f["numeric_noise_level"] = sum(roughs) / len(roughs) if roughs else 0.0

        # 10 数值越界率
        m = event.get("metrics") or {}
        checked = violated = 0
        for k, (lo, hi) in METRIC_RANGES.items():
            v = m.get(k)
            if isinstance(v, (int, float)):
                checked += 1
                if v < lo or v > hi:
                    violated += 1
        f["range_violation_ratio"] = violated / checked if checked else 0.0

        # 11 事件频率突变
        rate = self._local_rate(recent)
        if self._rates:
            med_rate = median(self._rates)
            f["event_rate_anomaly"] = (
                min(abs(rate - med_rate) / med_rate, 1.0) if med_rate > 0 else 0.0
            )
        else:
            f["event_rate_anomaly"] = 0.0

        # 12 历史画像偏离
        stats = self._host_stats.get(host, {})
        z_list = []
        for k, v in m.items():
            if not isinstance(v, (int, float)) or k not in METRIC_RANGES:
                continue
            st = stats.get(k)
            if not st or st[2] < 2:
                continue
            n = st[2]
            mean = st[0] / n
            var = max(st[1] / n - mean * mean, 1e-9)
            z_list.append(min(abs(float(v) - mean) / (var**0.5), 3.0) / 3.0)
        f["baseline_deviation"] = sum(z_list) / len(z_list) if z_list else 0.0

        return f

    def _update_state(self, event: dict, recent: list[dict]) -> None:
        self._history.append(event)
        host = event.get("host") or ""
        src = event.get("source_id") or ""
        if host and src:
            self._host_source.setdefault(host, set()).add(src)
        m = event.get("metrics") or {}
        st = self._host_stats.setdefault(host, {})
        for k, v in m.items():
            if isinstance(v, (int, float)) and k in METRIC_RANGES:
                s = st.setdefault(k, [0.0, 0.0, 0])
                s[0] += float(v)
                s[1] += float(v) * float(v)
                s[2] += 1
        self._rates.append(self._local_rate(recent))

    @staticmethod
    def _local_rate(recent: list[dict]) -> float:
        stamps = [_parse_ts(e.get("ts")) for e in recent]
        stamps = [s for s in stamps if s is not None]
        if len(stamps) < 2:
            return 0.0
        span = (stamps[-1] - stamps[0]).total_seconds()
        return (len(stamps) - 1) / span if span > 0 else 0.0


def main() -> None:
    parser = argparse.ArgumentParser(description="提取 12 特征（JSONL）")
    parser.add_argument("--in", dest="src", default=str(DATA_DIR / "normal_signed.jsonl"))
    parser.add_argument("--out", default=str(DATA_DIR / "features.jsonl"))
    args = parser.parse_args()

    events = load_jsonl(Path(args.src))
    extractor = FeatureExtractor(key=load_or_create_key())
    feats = extractor.extract_all(events)

    import json

    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for e, f in zip(events, feats):
            fh.write(json.dumps({"event_id": e["event_id"], **f}, ensure_ascii=False) + "\n")

    print(f"已提取 {len(feats)} 条特征 -> {path}")
    for name in FEATURE_NAMES:
        mean = sum(row[name] for row in feats) / len(feats) if feats else 0.0
        print(f"  {name:24s} 均值 {mean:.3f}")


if __name__ == "__main__":
    main()
