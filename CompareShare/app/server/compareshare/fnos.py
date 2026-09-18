"""飞牛 fnOS 开放接口客户端。

目录授权由飞牛系统侧完成（系统 ACL 授权），应用只负责：
  1. 前端通过 @trimjs/web-app 唤起官方目录选择器，用户确认后由系统授权；
  2. 后端通过 Unix socket 上的开放接口回读「官方授权目录列表」，不采信前端传回的路径。

参考：飞牛开发者文档「开放接口调用」章节。
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import socket
import threading
from typing import Any

log = logging.getLogger("compareshare.fnos")

GATEWAY_SOCKET = "/var/run/trim_open_gateway_apiscope.socket"
GATEWAY_PATH = "/api/v1/trimapp"
API_TOKEN_ENV = "TRIM_API_TOKEN"


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 10.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:  # noqa: D102
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class FnosError(RuntimeError):
    pass


class FnosOpenApi:
    """飞牛开放接口的最小客户端（仅依赖标准库）。"""

    def __init__(self, app_name: str) -> None:
        self.app_name = app_name
        self._counter = 0
        self._lock = threading.Lock()

    # ---- 基础设施 ----------------------------------------------------

    def available(self) -> bool:
        return os.path.exists(GATEWAY_SOCKET)

    def _next_req_id(self) -> str:
        with self._lock:
            self._counter += 1
            return str(self._counter)

    def call(self, req: str, data: dict[str, Any] | None = None) -> Any:
        token = os.environ.get(API_TOKEN_ENV, "").strip()
        if not token:
            names = sorted(k for k in os.environ if k.startswith("TRIM"))
            raise FnosError(
                f"环境变量 {API_TOKEN_ENV} 不可用，当前脚本可能不是由飞牛启动"
                f"（可见的 TRIM_ 变量：{names or '无'}）"
            )
        if not self.available():
            raise FnosError(f"未找到开放接口 socket：{GATEWAY_SOCKET}")

        payload = json.dumps(
            {
                "reqId": self._next_req_id(),
                "req": req,
                "appName": self.app_name,
                "data": data or {},
            },
            ensure_ascii=False,
        ).encode("utf-8")

        conn = _UnixHTTPConnection(GATEWAY_SOCKET)
        try:
            conn.request(
                "POST",
                GATEWAY_PATH,
                body=payload,
                headers={
                    "Host": "localhost",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {token}",
                    "Content-Length": str(len(payload)),
                },
            )
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", "replace")
        except OSError as exc:
            raise FnosError(f"开放接口调用失败：{exc}") from exc
        finally:
            conn.close()

        if resp.status != 200:
            raise FnosError(f"开放接口返回 HTTP {resp.status}: {raw[:200]}")

        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise FnosError(f"开放接口返回内容无法解析：{raw[:200]}") from exc

        code = body.get("code", 0)
        if code != 0:
            raise FnosError(f"{req} 返回错误码 {code}: {body.get('msg', '')}")
        return body.get("data")

    # ---- 具体接口 ----------------------------------------------------

    def user_accessible_folders(self, uid: int) -> list[str]:
        """用户在应用设置里授权的目录（用户作用域）。"""
        data = self.call("trim.file.getUserAccessibleFolders", {"uid": int(uid)})
        return _extract_paths(data)

    def shared_accessible_folders(self) -> list[str]:
        """管理员授权的共享目录（应用作用域）。"""
        data = self.call("trim.file.getSharedAccessibleFolders", {})
        return _extract_paths(data)

    def convert_path(self, paths: list[str], language: str = "zh-CN") -> dict[str, str]:
        """把 /vol1/1000/xxx 转换成用户可读的语义路径。"""
        if not paths:
            return {}
        data = self.call(
            "trim.file.convertPath", {"path": list(paths), "language": language}
        )
        mapping: dict[str, str] = {}
        for item in (data or {}).get("result", []) or []:
            raw = item.get("path")
            semantic = item.get("semanticPath") or raw
            if raw:
                mapping[raw] = semantic
        return mapping

    def check_user_acl(self, uid: int, paths: list[str]) -> dict[str, Any]:
        if not paths:
            return {}
        data = self.call("trim.file.checkUserACL", {"uid": int(uid), "path": list(paths)})
        return data or {}


def _extract_paths(data: Any) -> list[str]:
    if not data:
        return []
    if isinstance(data, list):
        return [p for p in data if isinstance(p, str)]
    if isinstance(data, dict):
        for key in ("paths", "path", "folders", "list"):
            value = data.get(key)
            if isinstance(value, list):
                return [p for p in value if isinstance(p, str)]
            if isinstance(value, str):
                return [value]
    return []


def debug_env() -> dict[str, Any]:
    """返回飞牛相关环境变量的可见情况，用于排查授权不可用的原因。"""
    names = sorted(k for k in os.environ if k.startswith("TRIM"))
    return {
        "available": os.path.exists(GATEWAY_SOCKET),
        "has_token": bool(os.environ.get(API_TOKEN_ENV, "").strip()),
        "trim_vars": names,
        "uid": os.environ.get("TRIM_RUN_UID") or os.environ.get("TRIM_UID") or "",
        "username": os.environ.get("TRIM_RUN_USERNAME") or os.environ.get("TRIM_USERNAME") or "",
        "socket": GATEWAY_SOCKET,
    }


def is_safe_path(path: str) -> bool:
    """校验来自开放接口的路径，拒绝相对路径与可疑片段。"""
    if not path or not path.startswith("/"):
        return False
    if "\x00" in path or "\\" in path:
        return False
    parts = [seg for seg in path.split("/") if seg]
    return all(seg not in (".", "..") for seg in parts)
