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

    # 单次 socket 读写的超时。上传大文件时按块读取，块间不应长时间无数据；
    # 若对端声明的长度大于实际发送量，靠这个超时终止等待，避免连接挂死。
    # 取 5 分钟：足够容忍慢速网络下单个块的间隔，又能及时释放僵死连接。
    timeout = 300

    # ---- 基础设施 ----------------------------------------------------

    @property
    def state(self) -> AppState:
        return self.server.state  # type: ignore[attr-defined]

    def setup(self) -> None:
        super().setup()
        try:
            self.connection.settimeout(self.timeout)
        except OSError:
            pass

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
            # 二维码：手机扫码直达上传页
            if path == "/api/qrcode.svg":
                return self._handle_qrcode()
            if path.startswith("/api/"):
                return self._handle_web_get(path)
            # 浏览器上传页（手机不装应用也能传文件）
            if path in ("/upload", "/upload/", "/upload.html"):
                return self._serve_webui_file("upload.html")
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
            # 回访让对方也能看到本机。必须节流：
            # 对方收到回访后同样会回访本机，若不限速两边会无限互相注册。
            self.state.reply_register(info, self.client_address[0])
        self._send_json(200, self.state.self_info().to_register_response())

    def _handle_prepare_upload(self) -> None:
        # 浏览器上传页与 LocalSend 客户端共用此端点；
        # 关闭「浏览器上传」只拦截网页来源，不影响 LocalSend 客户端。
        if not self.state.settings.get("web_upload", True) and self._is_browser():
            raise ReceiveError(403, "Web upload disabled")
        body = self._read_json()
        query = self._query()
        result = self.state.receiver.prepare_upload(
            body, self.client_address[0], query.get("pin")
        )
        if result is None:
            return self._send_empty(204)
        self._send_json(200, result)

    def _is_browser(self) -> bool:
        """区分网页上传与 LocalSend 客户端。

        浏览器发起的 fetch/XHR 一定带 Origin（跨源）或 Referer（同源），
        而 LocalSend 客户端是原生 HTTP 请求，两者都不带。
        据此判断来源，避免误伤客户端。
        """
        origin = self.headers.get("Origin") or ""
        referer = self.headers.get("Referer") or ""
        if origin.startswith("http"):
            return True
        return "/upload" in referer

    def _handle_upload(self) -> None:
        query = self._query()
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0

        # 官方客户端可能用流式 body，此时没有 Content-Length，
        # 而是 Transfer-Encoding: chunked。这种请求体需要先解码分块格式，
        # 否则会把分块长度标记当成文件内容写进去（校验和因此不匹配）。
        transfer_encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        chunked = "chunked" in transfer_encoding

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
                chunked=chunked,
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
        if path == "/api/web-upload":
            # 上传页启动时查询：是否开启、是否需要 PIN、本机地址
            return self._send_json(200, {
                "enabled": bool(state.settings.get("web_upload", True)),
                "alias": state.settings.get("alias"),
                "pinRequired": bool(state.settings.get("pin")),
                "uploadUrl": f"http://{self._local_ip()}:{state.web_port}/upload",
            })
        return self._send_json(404, {"message": "Not found"})

    def _handle_qrcode(self) -> None:
        """上传页的二维码（SVG），供手机扫码直达。"""
        state = self.state
        if not state.settings.get("web_upload", True):
            return self._send_json(403, {"message": "Web upload disabled"})

        host = self._query().get("host") or self._local_ip()
        port = state.web_port
        target = f"http://{host}:{port}/upload"

        from .qrcode import to_svg
        try:
            svg = to_svg(target, "M", scale=6, border=3)
        except ValueError as exc:
            return self._send_json(400, {"message": str(exc)})

        body = svg.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "image/svg+xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self._cors()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _local_ip(self) -> str:
        """取本机在局域网中的地址，用于拼二维码里的 URL。

        不能用「连接外部地址看出口」的做法：那可能选中 VPN/虚拟网卡
        （实测某些机器会返回 tun 地址 198.18.0.1），导致二维码指向错误网段。
        这里优先选用物理网卡的私有地址，与多播发现使用同一套接口筛选逻辑。
        """
        from .discovery import list_interfaces

        candidates = [addr for _name, addr in list_interfaces()]

        def score(addr: str) -> int:
            # 私有地址优先，其次链路本地，最后其它
            if addr.startswith("192.168.") or addr.startswith("10."):
                return 0
            if addr.startswith("172."):
                try:
                    second = int(addr.split(".")[1])
                    if 16 <= second <= 31:
                        return 0
                except (ValueError, IndexError):
                    pass
            if addr.startswith("169.254."):
                return 2
            # 198.18.0.0/15 是保留的基准测试网段，常被代理/VPN 软件占用，
            # 不可能是 NAS 的局域网地址，排到最后
            if addr.startswith("198.18.") or addr.startswith("198.19."):
                return 9
            return 1

        if candidates:
            return sorted(candidates, key=score)[0]

        # 退路：枚举本机地址，排除虚拟网段后取第一个私有地址
        import socket as _socket
        found: list[str] = []
        try:
            for info in _socket.getaddrinfo(_socket.gethostname(), None, _socket.AF_INET):
                found.append(info[4][0])
        except OSError:
            pass
        found += [a for a in self._fallback_probe_addrs()]
        found = [a for a in dict.fromkeys(found) if not a.startswith("127.")]
        if found:
            return sorted(found, key=score)[0]

        host = self.headers.get("Host", "")
        return host.split(":")[0] or "localhost"

    def _fallback_probe_addrs(self) -> list[str]:
        """通过 UDP connect 探测出口地址（可能不是局域网地址，仅作退路）。"""
        import socket as _socket
        out: list[str] = []
        for target in (("8.8.8.8", 80), ("223.5.5.5", 80)):
            try:
                s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
                try:
                    s.connect(target)
                    out.append(s.getsockname()[0])
                finally:
                    s.close()
            except OSError:
                continue
        return out

    def _serve_webui_file(self, name: str) -> None:
        """直接返回 webui 目录下的一个文件。"""
        target = (WEBUI_DIR / name).resolve()
        try:
            if not str(target).startswith(str(WEBUI_DIR.resolve())) or not target.is_file():
                return self._send_json(404, {"message": "Not found"})
        except OSError:
            return self._send_json(404, {"message": "Not found"})

        body = target.read_bytes()
        ctype = "text/html; charset=utf-8" if target.suffix == ".html" else "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self._cors()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

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
            # 收件目录先校验再用：目录不存在或不可写时明确报错，
            # 避免用户以为设置生效、收文件时才失败。
            if "download_dir" in body:
                err = state.settings.validate_download_dir(
                    str(body.get("download_dir") or "")
                )
                if err:
                    return self._send_json(400, {"message": err, "field": "download_dir"})
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
