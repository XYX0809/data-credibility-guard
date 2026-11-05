"""L2 统计层：IsolationForest 对 12 特征向量打分，归一为 0-100 可信分。

分数越高越可信。用干净数据 fit 后，按干净样本分布做分段线性映射：
  score_samples 的 p1 → 0 分，p5 → 50 分，p50+ → 100 分。
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest

from config.settings import RANDOM_STATE


class StatLayer:
    def __init__(self, *, n_estimators: int = 100, random_state: int = RANDOM_STATE):
        self._model = IsolationForest(
            n_estimators=n_estimators, random_state=random_state
        )
        self._anchors: tuple[float, float, float] | None = None

    def fit(self, vectors: list[list[float]]) -> "StatLayer":
        x = np.asarray(vectors, dtype=float)
        self._model.fit(x)
        samples = self._model.score_samples(x)  # 越高越正常
        p1, p5, p50 = (float(v) for v in np.percentile(samples, [1, 5, 50]))
        self._anchors = (p1, p5, p50)
        return self

    def score(self, vector: list[float]) -> float:
        if self._anchors is None:
            raise RuntimeError("StatLayer 需要先用干净数据 fit")
        s = float(self._model.score_samples([list(vector)])[0])
        p1, p5, p50 = self._anchors
        if p50 <= p1:  # 干净分布零方差（退化）：不低于底线即满分
            return 100.0 if s >= p1 else 0.0
        if s <= p1:
            return 0.0
        if s <= p5:
            return 50.0 * (s - p1) / (p5 - p1) if p5 > p1 else 50.0
        if s <= p50:
            return 50.0 + 50.0 * (s - p5) / (p50 - p5) if p50 > p5 else 100.0
        return 100.0

    def score_many(self, vectors: list[list[float]]) -> list[float]:
        return [self.score(v) for v in vectors]
