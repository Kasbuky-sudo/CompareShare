"""HTTP 服务：LocalSend 协议端点 + Web 管理 API + 静态前端。"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .core import AppState
from .protocol import PROTOCOL_VERSION, DeviceInfo
from .receiver import ReceiveError
from .sender import SendError
from .tls import cert_paths

log = logging.getLogger("compareshare.http")

WEBUI_DIR = Path(__file__).resolve().parent / "webui"
MAX_JSON_BODY = 4 * 1024 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "CompareShare"
    protocol_version = "HTTP/1.1"

    # ---- 基础设施 ----------------------------------------------------

    @property
    def state(self) -> AppState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D102
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self._cors()
        self.end_headers()

    def _cors(self) -> None:
        # 允许飞牛桌面以 iframe 方式嵌入
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_JSON_BODY:
            raise ReceiveError(400, "Invalid body")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise ReceiveError(400, "Invalid body") from exc
        if not isinstance(data, dict):
            raise ReceiveError(400, "Invalid body")
        return data

    def _query(self) -> dict[str, str]:
        parsed = urllib.parse.urlparse(self.path)
        return {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}

    def _path(self) -> str:
        return urllib.parse.urlparse(self.path).path

    # ---- 方法分发 ----------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send_empty(204)

    def do_GET(self) -> None:  # noqa: N802
        path = self._path()
        try:
            if path.startswith("/api/localsend/v1/info") or path.startswith(
                "/api/localsend/v2/info"
            ):
                return self._send_json(200, self.state.self_info().to_json())
            if path == "/api/localsend/v2/download":
                return self._handle_download()
            if path.startswith("/api/"):
                return self._handle_web_get(path)
            return self._serve_static(path)
        except ReceiveError as exc:
            return self._send_json(exc.status, {"message": exc.message})
        except Exception:  # noqa: BLE001
            log.exception("GET %s 处理失败", path)
            return self._send_json(500, {"message": "Internal error"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        path = self._path()
        try:
            if path == "/api/localsend/v2/register":
                return self._handle_register()
            if path == "/api/localsend/v2/prepare-upload":
                return self._handle_prepare_upload()
            if path == "/api/localsend/v2/upload":
                return self._handle_upload()
            if path == "/api/localsend/v2/cancel":
                return self._handle_cancel()
            if path == "/api/localsend/v2/prepare-download":
                return self._handle_prepare_download()
            if path.startswith("/api/"):
                return self._handle_web_post(path)
            return self._send_json(404, {"message": "Not found"})
        except ReceiveError as exc:
            return self._send_json(exc.status, {"message": exc.message})
        except SendError as exc:
            return self._send_json(400, {"message": str(exc)})
        except Exception:  # noqa: BLE001
            log.exception("POST %s 处理失败", path)
            return self._send_json(500, {"message": "Internal error"})

    # ---- LocalSend 协议 ----------------------------------------------

    def _handle_register(self) -> None:
        body = self._read_json()
        info = DeviceInfo.from_json(body)
        if info.alias:
            self.state.note_peer(info, self.client_address[0], "register")
            # 回访：让对方也看到我（协议允许，便于双向发现）
            self._callback_announce(info)
        self._send_json(200, self.state.self_info().to_register_response())

    def _callback_announce(self, info: DeviceInfo) -> None:
        """向主动注册的设备反向注册，使其设备列表里也出现本机。"""
        if not info.port or not info.alias:
            return

        def _worker() -> None:
            from . import sender as sender_mod
            try:
                client = sender_mod.PeerClient(
                    host=self.client_address[0],
                    port=info.port,
                    protocol=info.protocol,
                    self_info=self.state.self_info,
                    fingerprint=info.fingerprint or None,
                )
                client.register()
            except Exception as exc:  # noqa: BLE001 - 回访失败不影响主流程
                log.debug("回访 %s 失败：%s", self.client_address[0], exc)

        threading.Thread(target=_worker, daemon=True).start()

    def _handle_prepare_upload(self) -> None:
        body = self._read_json()
        query = self._query()
        result = self.state.receiver.prepare_upload(
            body, self.client_address[0], query.get("pin")
        )
        if result is None:
            return self._send_empty(204)
        self._send_json(200, result)

    def _handle_upload(self) -> None:
        query = self._query()
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0

        session_id = query.get("sessionId", "")
        file_id = query.get("fileId", "")
        token = query.get("token", "")
        if not session_id or not file_id or not token:
            raise ReceiveError(400, "Missing parameters")

        try:
            self.state.receiver.upload(
                session_id=session_id,
                file_id=file_id,
                token=token,
                body=self.rfile,
                remote_addr=self.client_address[0],
                content_length=length or None,
            )
        finally:
            # 出错时请求体可能没读完，关闭连接避免残留数据污染后续请求
            self.close_connection = True
        self._send_empty(200)

    def _handle_cancel(self) -> None:
        query = self._query()
        self.state.receiver.clear_session(query.get("sessionId"))
        self._send_empty(200)

    def _handle_prepare_download(self) -> None:
        query = self._query()
        pin = query.get("pin")
        expected = str(self.state.settings.get("pin") or "")
        if expected and pin != expected:
            raise ReceiveError(401, "PIN required or invalid")

        body = b""
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > 0:
                body = self.rfile.read(min(length, MAX_JSON_BODY))
        except (ValueError, OSError):
            body = b""

        files = self.state.list_share_files()
        import uuid

        session_id = str(uuid.uuid4())
        with self.state.lock:
            self.state.download_sessions = getattr(self.state, "download_sessions", {})
            self.state.download_sessions[session_id] = {
                fid: item for fid, item in ((f["id"], f) for f in files)
            }
            # 只保留最近 50 个下载会话
            if len(self.state.download_sessions) > 50:
                for key in list(self.state.download_sessions)[:-50]:
                    self.state.download_sessions.pop(key, None)

        self._send_json(
            200,
            {
                "info": self.state.self_info().to_json(),
                "sessionId": session_id,
                "files": {f["id"]: f for f in files},
            },
        )

    def _handle_download(self) -> None:
        query = self._query()
        session_id = query.get("sessionId", "")
        file_id = query.get("fileId", "")

        sessions = getattr(self.state, "download_sessions", {})
        session = sessions.get(session_id)
        if not session or file_id not in session:
            raise ReceiveError(403, "Invalid token or IP")

        target = self.state.resolve_share_file(file_id)
        if target is None:
            raise ReceiveError(403, "Invalid token or IP")

        size = target.stat().st_size
        quoted = urllib.parse.quote(target.name)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header(
            "Content-Disposition", f"attachment; filename*=UTF-8''{quoted}"
        )
        self._cors()
        self.end_headers()

        with open(target, "rb") as fh:
            while True:
                chunk = fh.read(512 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)

    # ---- Web 管理 API -------------------------------------------------

    def _handle_web_get(self, path: str) -> None:
        state = self.state
        if path == "/api/status":
            return self._send_json(200, state.status())
        if path == "/api/config":
            return self._send_json(200, {"config": state.settings.as_dict()})
        if path == "/api/peers":
            return self._send_json(200, {"peers": state.list_peers()})
        if path == "/api/files":
            return self._send_json(200, {"files": state.list_share_files()})
        if path == "/api/transfers":
            return self._send_json(200, {"transfers": state.transfers[:100]})
        if path == "/api/auth/paths":
            uid = self._query().get("uid")
            payload = state.authorized_paths(
                int(uid) if uid and uid.isdigit() else None
            )
            from .fnos import debug_env
            payload["debug"] = debug_env()
            return self._send_json(200, payload)
        if path == "/api/browse":
            return self._send_json(200, self._browse(state))
        return self._send_json(404, {"message": "Not found"})

    def _browse(self, state: AppState) -> dict[str, Any]:
        """在已授权范围内浏览目录，供前端选择要发送的文件。"""
        raw = self._query().get("path", "")
        roots = [str(state.settings.download_dir())]
        try:
            auth = state.authorized_paths()
            roots += list(auth.get("user") or []) + list(auth.get("shared") or [])
        except Exception:  # noqa: BLE001 - 授权查询失败不影响收件目录浏览
            pass
        roots += state.share_dirs()

        def _allowed(target: Path) -> bool:
            try:
                resolved = target.resolve()
            except OSError:
                return False
            for root in roots:
                try:
                    root_resolved = Path(root).resolve()
                except OSError:
                    continue
                if resolved == root_resolved or str(resolved).startswith(
                    str(root_resolved) + os.sep
                ):
                    return True
            return False

        if not raw:
            entries = []
            for root in dict.fromkeys(roots):
                p = Path(root)
                if p.is_dir():
                    entries.append({"name": p.name or str(p), "path": str(p), "dir": True})
            return {"path": "", "parent": None, "entries": entries, "roots": roots}

        target = Path(raw)
        if not _allowed(target) or not target.is_dir():
            return {"path": raw, "parent": None, "entries": [], "error": "路径未授权或不存在"}

        entries: list[dict[str, Any]] = []
        try:
            for item in sorted(
                target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
            ):
                if item.name.startswith("."):
                    continue
                try:
                    is_dir = item.is_dir()
                    size = 0 if is_dir else item.stat().st_size
                except OSError:
                    continue
                entries.append(
                    {"name": item.name, "path": str(item), "dir": is_dir, "size": size}
                )
                if len(entries) >= 2000:
                    break
        except OSError as exc:
            return {"path": raw, "parent": None, "entries": [], "error": str(exc)}

        parent = str(target.parent) if _allowed(target.parent) else None
        return {"path": raw, "parent": parent, "entries": entries}

    def _handle_web_post(self, path: str) -> None:
        state = self.state
        if path == "/api/config":
            body = self._read_json()
            updated = state.settings.update(body)
            if "https" in body or "port" in body:
                state._init_identity()
            return self._send_json(200, {"config": updated})

        if path == "/api/pin":
            body = self._read_json()
            if body.get("clear"):
                state.settings.clear_pin()
            else:
                state.settings.ensure_pin()
            return self._send_json(200, {"pin": state.settings.get("pin")})

        if path == "/api/announce":
            state.discovery.announce_now()
            return self._send_json(200, {"ok": True})

        if path == "/api/scan":
            return self._send_json(200, state.scan_network())

        if path == "/api/send":
            body = self._read_json()
            peer_key = str(body.get("peer", ""))
            paths = body.get("paths") or []
            if not isinstance(paths, list) or not paths:
                return self._send_json(400, {"message": "未提供文件路径"})
            try:
                record = state.send_files(
                    peer_key, [str(p) for p in paths], body.get("pin") or None
                )
            except SendError as exc:
                return self._send_json(400, {"message": str(exc)})
            return self._send_json(200, {"transfer": record})

        if path == "/api/peers/remove":
            body = self._read_json()
            removed = state.remove_peer(str(body.get("peer", "")))
            return self._send_json(200, {"removed": removed})

        if path == "/api/session/cancel":
            body = self._read_json()
            ok = state.receiver.clear_session(body.get("sessionId"))
            return self._send_json(200, {"cancelled": ok})

        return self._send_json(404, {"message": "Not found"})

    # ---- 静态资源 ----------------------------------------------------

    def _serve_static(self, path: str) -> None:
        if path in ("/", ""):
            path = "/index.html"

        rel = path.lstrip("/")
        if ".." in rel.split("/"):
            return self._send_json(403, {"message": "Forbidden"})

        candidate = (WEBUI_DIR / rel).resolve()
        try:
            if not str(candidate).startswith(str(WEBUI_DIR.resolve())):
                return self._send_json(403, {"message": "Forbidden"})
        except OSError:
            return self._send_json(403, {"message": "Forbidden"})

        if not candidate.is_file():
            return self._send_json(404, {"message": "Not found"})

        ctype, _ = mimetypes.guess_type(candidate.name)
        if candidate.suffix == ".js":
            # ESM 模块必须声明为 JavaScript 类型，否则浏览器拒绝执行
            ctype = "text/javascript"
        body = candidate.read_bytes()
        self.send_response(200)
        if ctype and ctype.startswith("text"):
            content_type = f"{ctype}; charset=utf-8"
        else:
            content_type = ctype or "application/octet-stream"
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self._cors()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


def _build_server_context() -> ssl.SSLContext:
    """构造服务端 TLS 上下文。

    LocalSend 在 HTTPS 模式下双方都用自签证书，身份靠指纹固定（fingerprint
    pinning）而非 CA 链。所以服务端不能向客户端索要并要求可验证的证书：
    Python 的 CERT_OPTIONAL 会用系统 CA 去校验客户端的自签证书，失败后回
    `unknown_ca` 告警；TLS 1.3 下客户端证书在握手之后才发送，客户端表现为
    `received fatal alert: UnknownCA`（手机端遇到的就是这个）。

    标准库不支持自定义客户端证书校验回调，因此这里用 CERT_NONE：不索要客户端
    证书。官方客户端在对方未请求时不会发送证书，连接照常建立；身份仍由上层按
    协议里的 fingerprint 字段判断。
    """
    cert, key = cert_paths()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


class ShareServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], state: AppState, use_tls: bool) -> None:
        self.state = state
        super().__init__(address, Handler)
        if use_tls:
            ctx = _build_server_context()
            self.socket = ctx.wrap_socket(self.socket, server_side=True)


def run_servers(state: AppState, host: str = "0.0.0.0") -> None:
    """启动协议端口与 Web 端口。"""
    use_tls = state.settings.effective_https()
    protocol_server = ShareServer((host, state.port), state, use_tls)
    web_server = ShareServer((host, state.web_port), state, False)

    threads = [
        threading.Thread(
            target=protocol_server.serve_forever, daemon=True, name="protocol-http"
        ),
        threading.Thread(target=web_server.serve_forever, daemon=True, name="web-http"),
    ]
    for t in threads:
        t.start()

    log.info(
        "协议端口 %s:%d（%s），Web 端口 %s:%d",
        host, state.port, "HTTPS" if use_tls else "HTTP", host, state.web_port,
    )
    return protocol_server, web_server  # type: ignore[return-value]
