from src.datasource.generator import generate_normal_events
from src.datasource.schema import SCHEMA_VER, LogEvent


def test_dict_roundtrip():
    e = generate_normal_events(1)[0]
    restored = LogEvent.from_dict(e.to_dict())
    assert restored == e
    assert restored.schema_ver == SCHEMA_VER


def test_from_dict_drops_unknown_fields():
    d = generate_normal_events(1)[0].to_dict()
    d["hmac"] = "deadbeef"
    d["extra"] = 1
    restored = LogEvent.from_dict(d)
    assert not hasattr(restored, "hmac")
    assert "extra" not in restored.to_dict()
