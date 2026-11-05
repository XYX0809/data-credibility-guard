# 数据可信度验证系统（data-credibility-guard）

面向安全决策 AI 的"免疫系统"：在 AI 决策前验证输入数据可信度，拦截数据投毒。
全本地部署、断网可用。项目背景与指标见 `code.txt`，实施细节见 `启动方案-2026.11.md`。

## 环境安装

在线：

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
```

离线（赛期断网）：双击运行 `install_offline.bat`（依赖 `wheels/` 目录，随环境版本重新下载）

## 运行测试

```bash
.venv\Scripts\python -m pytest tests -q
```

## 生成样例数据与污染注入

```bash
.venv\Scripts\python -m src.datasource.generator --count 500 --out data/normal.jsonl
.venv\Scripts\python -m src.engine.hmac_layer sign data/normal.jsonl data/normal_signed.jsonl
.venv\Scripts\python -m src.engine.hmac_layer verify data/normal_signed.jsonl
```

```bash
.venv\Scripts\python -m src.pollution.timestamp_tamper --mode rollback --ratio 0.2 --out data/polluted_ts.jsonl
```

```bash
.venv\Scripts\python -m src.pollution.log_deletion --mode block --ratio 0.2 --out data/polluted_del.jsonl
```

```bash
.venv\Scripts\python -m src.features.extractor --in data/polluted_ts.jsonl --out data/features.jsonl
```

```bash
.venv\Scripts\python -m src.engine.scorer --clean data/normal_signed.jsonl --target data/polluted_ts.jsonl
```

## 目录结构

见 `启动方案-2026.11.md` §2（八模块：数据源模拟 / 污染模拟 / 特征提取 / 校验引擎 / 靶子AI / 阻断告警 / 审计取证 / 可解释输出）
