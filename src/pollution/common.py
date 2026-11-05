"""污染模拟公共类型。"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PollutionResult:
    events: list[dict]  # 污染后的事件（新列表，不修改输入）
    affected_event_ids: list[str]  # 被篡改/删除的事件 ID（评测真值标签）
    mode: str  # 注入模式
    detail: dict = field(default_factory=dict)  # 模式相关参数记录
