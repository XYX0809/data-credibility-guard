"""⑦ 审计取证报告：Jinja2 渲染（含证据链校验结果）。"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.forensics.ledger import fetch_blocked, fetch_summary, verify_chain

ROOT = Path(__file__).resolve().parents[2]
REPORTS_DIR = ROOT / "reports"


def generate_report(db_path: Path, out_html: Path) -> Path:
    summary = fetch_summary(db_path)
    rows = fetch_blocked(db_path)
    chain = verify_chain(db_path)
    env = Environment(
        loader=FileSystemLoader(REPORTS_DIR),
        autoescape=select_autoescape(["html"]),
    )
    html = env.get_template("audit_report.html.j2").render(
        generated_at=datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
        db_name=Path(db_path).name,
        totals=summary,
        chain=chain,
        rows=rows,
    )
    out_html = Path(out_html)
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_html.write_text(html, encoding="utf-8")
    return out_html


def main() -> None:
    parser = argparse.ArgumentParser(description="生成审计取证报告（HTML）")
    parser.add_argument("--db", default=str(ROOT / "data" / "audit.db"))
    parser.add_argument("--out", default=str(ROOT / "data" / "audit_report.html"))
    args = parser.parse_args()
    out = generate_report(Path(args.db), Path(args.out))
    print(f"报告已生成 -> {out}")


if __name__ == "__main__":
    main()
