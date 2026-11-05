"""日志事件 schema v1.0 —— 12 特征与 HMAC 的计算基准（启动方案 §3）。"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any

SCHEMA_VER = "1.0"
EVENT_TYPES = ("auth_login", "auth_fail", "net_conn", "file_access", "config_change")


@dataclass(frozen=True)
class LogEvent:
    event_id: str
    seq_no: int
    ts: str
    host: str
    source_id: str
    event_type: str
    src_ip: str
    user: str
    metrics: dict[str, float]
    schema_ver: str = SCHEMA_VER

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LogEvent":
        # 边界入口：忽略未知字段（如 hmac 签名字段），只取 schema 内字段
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in names})
