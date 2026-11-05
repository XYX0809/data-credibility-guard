"""靶子 AI 测试：学习能力、被伪装欺骗、验证层恢复。"""
from src.aitarget.target_ai import TargetAI, ai_vector, label_threat
from src.datasource.generator import generate_normal_events
from src.engine.hmac_layer import sign
from src.engine.scorer import CredibilityEngine
from src.pollution.noise_injection import inject_noise

KEY = b"test-secret"


def _dataset():
    stream = [sign(e.to_dict(), KEY) for e in generate_normal_events(900, seed=11)]
    labels = [label_threat(e) for e in stream]
    return stream, labels


def test_label_rule_and_vector():
    threat = {"metrics": {"cpu": 90.0, "mem": 50.0, "conn_count": 450.0}}
    calm = {"metrics": {"cpu": 20.0, "mem": 50.0, "conn_count": 50.0}}
    assert label_threat(threat) == 1
    assert label_threat(calm) == 0
    assert ai_vector(threat) == [90.0, 50.0, 450.0]


def test_ai_learns_on_clean():
    stream, labels = _dataset()
    assert len(set(labels)) == 2
    ai = TargetAI().fit(stream[:500], labels[:500])
    r = ai.evaluate(stream[500:900], labels[500:900])
    assert r["accuracy"] >= 0.9


def test_masked_threats_fool_ai():
    stream, labels = _dataset()
    ai = TargetAI().fit(stream[:500], labels[:500])
    test = stream[500:900]
    test_y = labels[500:900]
    threats = [e for e, y in zip(test, test_y) if y == 1]
    assert len(threats) >= 20
    masked = inject_noise(threats, mode="mask", ratio=1.0, seed=3)
    masked_map = {e["event_id"]: e for e in masked.events}
    attacked = [masked_map.get(e["event_id"], e) for e in test]

    fooled_conf = []
    for e, y in zip(attacked, test_y):
        if y == 1 and e["event_id"] in masked_map:
            pred, conf = ai.predict(e)
            if pred == 0:
                fooled_conf.append(conf)
    assert len(fooled_conf) >= len(threats) * 0.8
    assert sum(fooled_conf) / len(fooled_conf) >= 0.8  # 自信地输出错误决策


def test_validation_layer_restores_accuracy():
    stream, labels = _dataset()
    ai = TargetAI().fit(stream[:500], labels[:500])
    engine = CredibilityEngine.train(stream[:500], key=KEY)

    test = stream[500:900]
    test_y = labels[500:900]
    threats = [e for e, y in zip(test, test_y) if y == 1]
    masked = inject_noise(threats, mode="mask", ratio=1.0, seed=3)
    masked_map = {e["event_id"]: e for e in masked.events}
    attacked = [masked_map.get(e["event_id"], e) for e in test]

    results = engine.evaluate_all(attacked)
    blocked = {r.event_id for r in results if r.blocked}
    assert set(masked.affected_event_ids) <= blocked  # 伪装全部拦下

    survivors = [e for e in attacked if e["event_id"] not in blocked]
    survive_y = [y for e, y in zip(attacked, test_y) if e["event_id"] not in blocked]
    r = ai.evaluate(survivors, survive_y)
    assert r["accuracy"] >= 0.95


def test_ai_deterministic():
    stream, labels = _dataset()
    a = TargetAI().fit(stream[:500], labels[:500])
    b = TargetAI().fit(stream[:500], labels[:500])
    preds_a = [a.predict(e)[0] for e in stream[500:550]]
    preds_b = [b.predict(e)[0] for e in stream[500:550]]
    assert preds_a == preds_b
