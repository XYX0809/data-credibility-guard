"""⑥ 大屏推送：评分事件流（大屏服务与测试共用）。"""
from __future__ import annotations

import time
from typing import Callable

from src.engine.scorer import CredibilityEngine, ScoreResult
from src.explain.profile import suspicion_profile

OnEmit = Callable[[str, dict], None]

PAYLOAD_KEYS = (
    "event_id",
    "seq_no",
    "score",
    "blocked",
    "veto",
    "rule_hits",
    "s_hmac",
    "s_stat",
    "s_rule",
    "suspicions",
)


def result_payload(event: dict, result: ScoreResult) -> dict:
    return {
        "event_id": result.event_id,
        "seq_no": event.get("seq_no"),
        "score": round(result.score, 1),
        "blocked": result.blocked,
        "veto": result.veto,
        "rule_hits": result.rule_hits,
        "s_hmac": round(result.s_hmac, 1),
        "s_stat": round(result.s_stat, 1),
        "s_rule": round(result.s_rule, 1),
        "suspicions": {k: round(v, 3) for k, v in suspicion_profile(result.features).items()},
    }


class ScoreFeed:
    """把事件逐条喂给评分引擎，按节拍回调推送（大屏 / 测试共用）。"""

    def __init__(
        self,
        engine: CredibilityEngine,
        *,
        interval: float = 0.05,
        on_emit: OnEmit | None = None,
    ):
        self._engine = engine
        self._interval = interval
        self._on_emit = on_emit or (lambda name, payload: None)

    def emit_batch(self, events: list[dict], *, interval: float | None = None) -> list[dict]:
        pause = self._interval if interval is None else interval
        payloads = []
        for event in events:
            result = self._engine.evaluate(event)
            payload = result_payload(event, result)
            self._on_emit("score", payload)
            if result.blocked:
                self._on_emit("block", payload)
            payloads.append(payload)
            if pause > 0:
                time.sleep(pause)
        return payloads
