"""⑥ 大屏服务：Flask + Socket.IO（threading 模式，Windows 最稳）+ ECharts 页面。"""
from __future__ import annotations

import threading
import time
import webbrowser
from pathlib import Path

from flask import Flask, send_from_directory
from flask_socketio import SocketIO

from src.alert.feed import ScoreFeed

WEB_DIR = Path(__file__).resolve().parents[2] / "web"


def build_app() -> tuple[Flask, SocketIO]:
    app = Flask(__name__)
    socketio = SocketIO(app, async_mode="threading")

    @app.get("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/<path:filename>")
    def static_files(filename: str):
        return send_from_directory(WEB_DIR, filename)

    return app, socketio


def run_dashboard(
    make_round,
    *,
    interval: float = 0.05,
    host: str = "127.0.0.1",
    port: int = 5000,
    open_browser: bool = True,
    loop: bool = True,
) -> None:
    """make_round: () -> (engine, phases)，每轮重建；loop=True 循环回放（打开页面永远有数据）。

    phases: [(阶段名, 事件列表, 播完后停顿秒数)]，每轮播完发 feed_done。
    """
    app, socketio = build_app()
    on_emit = lambda name, payload: socketio.emit(name, payload)

    def run_phases() -> None:
        round_index = 0
        while True:
            round_index += 1
            engine, phases = make_round()
            feed = ScoreFeed(engine, interval=interval, on_emit=on_emit)
            socketio.emit("round", {"index": round_index})
            for label, events, gap in phases:
                socketio.emit("phase", {"label": label, "count": len(events)})
                feed.emit_batch(events)
                if gap > 0:
                    time.sleep(gap)
            socketio.emit("feed_done", {})
            if not loop:
                break
            time.sleep(2.5)

    threading.Thread(target=run_phases, daemon=True).start()
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{host}:{port}")).start()
    socketio.run(app, host=host, port=port, allow_unsafe_werkzeug=True)
