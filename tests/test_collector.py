"""采集器测试：真实 wevtutil 输出格式的解析与映射。"""
from src.datasource.collector import _classify, _map_event, _parse_events

REAL_FORMAT_XML = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    "<System>"
    "<Provider Name='Service Control Manager' Guid='{555908d1}'/>"
    "<EventID Qualifiers='16384'>7040</EventID>"
    "<TimeCreated SystemTime='2026-11-05T10:55:20.0000000Z'/>"
    "<EventRecordID>21544</EventRecordID>"
    "<Computer>TEST-HOST</Computer>"
    "<Security UserID='S-1-5-18'/>"
    "</System>"
    "<EventData><Data Name='param1'>bits</Data></EventData>"
    "</Event>"
)


def test_parse_real_format_xml():
    raws = _parse_events(REAL_FORMAT_XML, "System")
    assert len(raws) == 1
    r = raws[0]
    assert r["provider"] == "Service Control Manager"
    assert r["event_id"] == "7040"
    assert r["record_id"] == "21544"
    assert r["computer"] == "TEST-HOST"
    assert r["ts"].startswith("2026-11-05T10:55:20")
    assert r["data"]["param1"] == "bits"


def test_map_event_to_schema():
    raws = _parse_events(REAL_FORMAT_XML, "System")
    e = _map_event(raws[0], seq_no=7, metrics={"cpu": 1.0, "mem": 2.0, "conn_count": 3.0})
    assert e["event_id"] == "System-21544"
    assert e["seq_no"] == 7
    assert e["ts"].endswith("+00:00")
    assert e["host"] == "TEST-HOST"
    assert e["source_id"] == "Service Control Manager"
    assert e["event_type"] == "config_change"
    assert e["metrics"]["cpu"] == 1.0
    assert e["schema_ver"] == "1.0"


def test_classify_buckets():
    assert _classify({"provider": "Microsoft-Windows-Security-Auditing", "event_id": "4625", "channel": "Security", "data": {}, "record_id": "1", "computer": "", "ts": "", "user_id": ""}) == "auth_fail"
    assert _classify({"provider": "Microsoft-Windows-TCPIP", "event_id": "4231", "channel": "System", "data": {}, "record_id": "1", "computer": "", "ts": "", "user_id": ""}) == "net_conn"
