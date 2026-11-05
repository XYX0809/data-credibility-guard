"""① 数据源采集：真实 Windows 事件日志 + 本机性能指标 → 标准事件流。

采集本机 System/Application/Security 通道的真实事件（wevtutil），
事件上附带真实性能指标快照（psutil），映射进统一 schema 后落盘 JSONL。
生成器（generator.py）仅保留做污染注入实验的底料；正式链路一律用真实采集数据。
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from config.settings import DATA_DIR, RANDOM_STATE  # noqa: F401

REAL_DIR = DATA_DIR / "real"
DEFAULT_BASE = REAL_DIR / "base.jsonl"
MANIFEST_PATH = REAL_DIR / "manifest.json"
CHANNELS = ("System", "Application", "Security")

EVENT_ID_RE = re.compile(r"^\d+$")
NS_STRIP = re.compile(r"\sxmlns(:\w+)?=(\"[^\"]*\"|'[^']*')")


def _run_wevtutil(channel: str, count: int) -> str:
    result = subprocess.run(
        ["wevtutil", "qe", channel, f"/c:{count}", "/f:XML", "/rd:true"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
    )
    return result.stdout if result.returncode == 0 else ""


def _parse_events(xml_text: str, channel: str) -> list[dict]:
    """wevtutil XML → 原始字段字典列表（含命名空间剥离）。"""
    if not xml_text.strip():
        return []
    wrapped = NS_STRIP.sub("", f"<root>{xml_text}</root>")
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        return []
    out = []
    for ev in root.iter("Event"):
        system = ev.find("System")
        if system is None:
            continue
        provider = system.find("Provider")
        event_id = (system.findtext("EventID") or "").strip()
        record_id = (system.findtext("EventRecordID") or "").strip()
        computer = (system.findtext("Computer") or "").strip()
        time_el = system.find("TimeCreated")
        ts = (time_el.get("SystemTime") if time_el is not None else "") or ""
        security = system.find("Security")
        user_id = (security.get("UserID") if security is not None else "") or ""
        data = {d.get("Name", ""): (d.text or "").strip() for d in ev.iter("Data")}
        out.append({
            "channel": channel,
            "provider": provider.get("Name", "") if provider is not None else "",
            "event_id": event_id,
            "record_id": record_id,
            "computer": computer,
            "ts": ts,
            "user_id": user_id,
            "data": data,
        })
    return out


def _classify(raw: dict) -> str:
    provider = raw["provider"]
    provider_l = provider.lower()
    eid = raw["event_id"]
    if eid in ("4624", "4625", "4648") or "winlogon" in provider_l or "lsa" in provider_l:
        return "auth_fail" if eid == "4625" else "auth_login"
    if any(k in provider_l for k in ("tcpip", "dns", "dhcp", "network", "ndis")):
        return "net_conn"
    if "service control manager" in provider_l or eid in ("1074", "6005", "6006"):
        return "config_change"
    return "file_access"


def _snapshot_metrics() -> dict:
    """真实性能指标快照（拿不到的项如实置 0）。"""
    try:
        import psutil

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        try:
            conn = len(psutil.net_connections(kind="inet"))
        except Exception:
            conn = 0
        return {"cpu": round(cpu, 2), "mem": round(mem, 2), "conn_count": float(conn)}
    except Exception:
        return {"cpu": 0.0, "mem": 0.0, "conn_count": 0.0}


def _map_event(raw: dict, seq_no: int, metrics: dict) -> dict:
    host = raw["computer"] or platform.node()
    user = raw["data"].get("TargetUserName") or raw["data"].get("User") or (
        "SYSTEM" if raw["channel"] == "System" else ""
    )
    src_ip = raw["data"].get("IpAddress") or raw["data"].get("SourceAddress") or ""
    ts = raw["ts"]
    if ts and ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    if not ts:
        ts = datetime.now(timezone.utc).isoformat()
    return {
        "event_id": f"{raw['channel']}-{raw['record_id'] or seq_no}",
        "seq_no": seq_no,
        "ts": ts,
        "host": host,
        "source_id": raw["provider"] or raw["channel"],
        "event_type": _classify(raw),
        "src_ip": src_ip,
        "user": user,
        "metrics": dict(metrics),
        "schema_ver": "1.0",
    }


def collect(count: int = 800) -> tuple[list[dict], dict]:
    """采集真实事件（多通道按时间排序、全局连续编号）+ 指标快照。"""
    per_channel = max(1, count)  # 每通道各取足量，合并后按时间截断
    raws: list[dict] = []
    used_channels = []
    for channel in CHANNELS:
        xml_text = _run_wevtutil(channel, per_channel)
        parsed = _parse_events(xml_text, channel)
        if parsed:
            used_channels.append(channel)
            raws.extend(parsed)

    raws.sort(key=lambda r: (r["ts"], r["record_id"]))
    metrics = _snapshot_metrics()
    events = [_map_event(r, i + 1, metrics) for i, r in enumerate(raws[:count])]

    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "channels": used_channels,
        "count": len(events),
        "metrics": metrics,
    }
    return events, manifest


def load_base_events(n: int | None = None, path: Path = DEFAULT_BASE) -> list[dict]:
    """读取真实采集的基础数据；缺文件时给出采集命令。"""
    if not Path(path).exists():
        raise FileNotFoundError(
            f"真实数据集不存在：{path}\n请先运行：python -m src.datasource.collector"
        )
    events = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
    return events[:n] if n else events


def captured_hosts(path: Path = MANIFEST_PATH) -> frozenset[str]:
    """采集时刻的主机名清单（供主机名规则白名单用）。"""
    if not Path(path).exists():
        return frozenset()
    return frozenset({json.loads(Path(path).read_text(encoding="utf-8")).get("host", "")} - {""})


def main() -> None:
    parser = argparse.ArgumentParser(description="采集本机真实日志与性能指标")
    parser.add_argument("--count", type=int, default=800)
    parser.add_argument("--out", default=str(DEFAULT_BASE))
    args = parser.parse_args()

    events, manifest = collect(count=args.count)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(e, ensure_ascii=False) for e in events) + "\n", encoding="utf-8"
    )
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已采集 {len(events)} 条真实事件（{'+'.join(manifest['channels'])}）-> {out}")
    print(f"主机：{manifest['host']}　指标快照：{manifest['metrics']}")


if __name__ == "__main__":
    main()
