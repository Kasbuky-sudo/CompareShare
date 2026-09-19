#!/usr/bin/env python3
"""Compare Share 服务入口。

由 fpk 的 cmd/main 脚本拉起，仅依赖 Python 3 标准库。
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path


def _setup_path() -> None:
    """保证能 import compareshare 包（无论从哪个目录启动）。"""
    here = Path(__file__).resolve().parent
    if str(here) not in sys.path:
        sys.path.insert(0, str(here))


def _configure_logging(verbose: bool) -> None:
    """配置日志。

    文件日志按大小轮转：NAS 应用长期运行，无轮转的日志会持续膨胀
    （实测几天即达数百 KB，长期不清理会占用可观空间）。
    """
    from logging.handlers import RotatingFileHandler

    from compareshare.settings import log_file

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(RotatingFileHandler(
            log_file(), maxBytes=512 * 1024, backupCount=2, encoding="utf-8"))
    except OSError:
        pass

    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare Share server")
    parser.add_argument("--host", default="0.0.0.0", help="监听地址")
    parser.add_argument("--port", type=int, default=None, help="LocalSend 协议端口")
    parser.add_argument("--web-port", type=int, default=None, help="Web 管理端口")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    args = parser.parse_args()

    _setup_path()
    _configure_logging(args.verbose)

    from compareshare.core import AppState
    from compareshare.http_server import run_servers
    from compareshare.settings import Settings

    settings = Settings()
    patch = {}
    if args.port:
        patch["port"] = args.port
    if args.web_port:
        patch["web_port"] = args.web_port
    if patch:
        settings.update(patch)

    state = AppState(settings)
    log = logging.getLogger("compareshare")
    log.info("Compare Share 启动中，设备名 %s", settings.get("alias"))

    state.start()
    servers = run_servers(state, args.host)

    stopping = False

    def _shutdown(signum, _frame):  # noqa: ANN001
        nonlocal stopping
        if stopping:
            return
        stopping = True
        log.info("收到信号 %s，正在停止…", signum)
        state.stop()
        for srv in servers:
            try:
                srv.shutdown()
            except Exception:  # noqa: BLE001
                pass
        time.sleep(0.2)
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown(signal.SIGINT, None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
