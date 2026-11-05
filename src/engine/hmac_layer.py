"""L1 HMAC 完整性层：规范化 JSON + HMAC-SHA256 签发/校验（启动方案 §5）。

密钥只在数据源侧持有；攻击模拟侧拿明文日志副本，篡改后无法重签。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

from config.settings import HMAC_KEY_FILE

HMAC_FIELD = "hmac"


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def load_or_create_key(path: Path = HMAC_KEY_FILE) -> bytes:
    path = Path(path)
    if path.exists():
        return bytes.fromhex(path.read_text(encoding="ascii").strip())
    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.hex(), encoding="ascii")
    return key


def sign(event: dict, key: bytes) -> dict:
    body = {k: v for k, v in event.items() if k != HMAC_FIELD}
    sig = hmac.new(key, canonical_json(body), hashlib.sha256).hexdigest()
    return {**body, HMAC_FIELD: sig}


def verify(event: dict, key: bytes) -> bool:
    sig = event.get(HMAC_FIELD)
    if not isinstance(sig, str) or not sig:
        return False
    body = {k: v for k, v in event.items() if k != HMAC_FIELD}
    expected = hmac.new(key, canonical_json(body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected)


def main() -> None:
    parser = argparse.ArgumentParser(description="HMAC 签发/校验 JSONL 日志")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_sign = sub.add_parser("sign", help="对日志文件签发签名")
    p_sign.add_argument("src")
    p_sign.add_argument("dst")
    p_verify = sub.add_parser("verify", help="校验日志文件签名")
    p_verify.add_argument("src")
    args = parser.parse_args()

    key = load_or_create_key()
    src = Path(args.src)

    if args.cmd == "sign":
        events = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line.strip()]
        signed = [sign(e, key) for e in events]
        dst = Path(args.dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in signed) + "\n", encoding="utf-8"
        )
        print(f"已签发 {len(signed)} 条 -> {dst}")
    else:
        events = [json.loads(line) for line in src.read_text(encoding="utf-8").splitlines() if line.strip()]
        ok = sum(1 for e in events if verify(e, key))
        bad = len(events) - ok
        print(f"校验完成：通过 {ok} 条，失败 {bad} 条（共 {len(events)} 条）")
        sys.exit(0 if bad == 0 else 1)


if __name__ == "__main__":
    main()
