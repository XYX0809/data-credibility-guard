"""⑤ 安全决策 AI 靶子：RandomForest 分类器（真模型，非规则引擎）。

决策任务：根据数值特征判断事件是否"威胁"，输出标签与自信度。
攻击面：数值字段被污染（伪装/噪声）时，模型会自信地输出错误决策。
"""
from __future__ import annotations

from sklearn.ensemble import RandomForestClassifier

from config.settings import RANDOM_STATE

AI_FIELDS = ("cpu", "mem", "conn_count")


def label_threat(event: dict) -> int:
    """隐藏真值规则（只用于造数据与评测，AI 本身看不到）。"""
    m = event.get("metrics") or {}
    return int(float(m.get("cpu", 0)) > 65 and float(m.get("conn_count", 0)) > 320)


def ai_vector(event: dict) -> list[float]:
    m = event.get("metrics") or {}
    return [float(m.get(k, 0.0)) for k in AI_FIELDS]


class TargetAI:
    """靶子 AI：在干净数据上训练，被污染数值欺骗时自信输出错误决策。"""

    def __init__(self, *, n_estimators: int = 100, random_state: int = RANDOM_STATE):
        self._model = RandomForestClassifier(
            n_estimators=n_estimators, random_state=random_state
        )

    def fit(self, events: list[dict], labels: list[int]) -> "TargetAI":
        self._model.fit([ai_vector(e) for e in events], labels)
        return self

    def predict(self, event: dict) -> tuple[int, float]:
        """返回 (决策标签, 自信度)。"""
        proba = self._model.predict_proba([ai_vector(event)])[0]
        idx = int(proba.argmax())
        return int(self._model.classes_[idx]), float(proba[idx])

    def evaluate(self, events: list[dict], labels: list[int]) -> dict:
        preds = [self.predict(e) for e in events]
        correct = sum(1 for (p, _), y in zip(preds, labels) if p == y)
        wrong_conf = [c for (p, c), y in zip(preds, labels) if p != y]
        return {
            "n": len(events),
            "accuracy": correct / len(events) if events else 0.0,
            "errors": len(events) - correct,
            "avg_conf_wrong": sum(wrong_conf) / len(wrong_conf) if wrong_conf else 0.0,
            "predictions": preds,
        }
