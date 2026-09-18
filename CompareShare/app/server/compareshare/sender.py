"""LocalSend v2.2 发送端：向对端注册、协商上传、推送文件。

安全模型（与官方实现对齐）：
  * HTTPS 模式下，对端用自签证书；身份以「证书 DER 的 SHA-256」固定，而非 CA 校验
  * 不校验证书主机名（对端按 IP 访问，且官方刻意跳过主机名匹配）
  * 发现阶段不固定指纹（TOFU），握手后从证书读取，后续请求按指纹校验
"""

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import mimetypes
import os
import socket
import ssl
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .protocol import DeviceInfo
from .tls import cert_paths

log = logging.getLogger("compareshare.sender")

TIMEOUT = 30


class SendError(RuntimeError):
    pass


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """按证书指纹校验对端（不校验证书链与主机名）。"""

    def __init__(
        self,
        host: str,
        port: int,
        expected_fingerprint: str | None,
        context: ssl.SSLContext,
        timeout: float = TIMEOUT,
    ) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self.expected_fingerprint = (expected_fingerprint or "").upper()

    def connect(self) -> None:  # noqa: D102
        super().connect()
        if not self.expected_fingerprint:
            return
        der = self.sock.getpeercert(binary_form=True)
        if not der:
            raise SendError("无法获取对端证书")
        actual = hashlib.sha256(der).hexdigest().upper()
        if actual != self.expected_fingerprint:
            raise SendError(
                f"对端证书指纹不匹配：期望 {self.expected_fingerprint}，实际 {actual}"
            )


def build_client_context() -> ssl.SSLContext:
    """双向 TLS：客户端也出示自己的证书，但不校验证书链。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cert, key = cert_paths()
    if cert.is_file() and key.is_file():
        try:
            ctx.load_cert_chain(str(cert), str(key))
        except (OSError, ssl.SSLError) as exc:
            log.warning("加载本地客户端证书失败：%s", exc)
    return ctx


class PeerClient:
    """与单个对端通信。"""

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str,
        self_info: Callable[[], DeviceInfo],
        fingerprint: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol or "https"
        self.get_self_info = self_info
        self.fingerprint = fingerprint

    # ---- 传输层 ------------------------------------------------------

    def _connection(self) -> http.client.HTTPConnection:
        if self.protocol == "https":
            return PinnedHTTPSConnection(
                self.host, self.port, self.fingerprint, build_client_context()
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=TIMEOUT)

    def _request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = TIMEOUT,
    ) -> tuple[int, bytes]:
        conn = self._connection()
        try:
            conn.timeout = timeout
            hdrs = {"Content-Type": "application/json"} if body is not None else {}
            hdrs.update(headers or {})
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, data
        except (OSError, ssl.SSLError, SendError) as exc:
            raise SendError(f"连接 {self.host}:{self.port} 失败：{exc}") from exc
        finally:
            conn.close()

    # ---- 协议接口 ----------------------------------------------------

    def register(self) -> dict[str, Any]:
        payload = json.dumps(
            self.get_self_info().to_json(), ensure_ascii=False
        ).encode("utf-8")
        status, data = self._request("POST", "/api/localsend/v2/register", payload)
        if status != 200:
            raise SendError(f"register 返回 {status}")
        try:
            return json.loads(data)
        except ValueError:
            return {}

    def prepare_upload(
        self, files: dict[str, dict[str, Any]], pin: str | None
    ) -> dict[str, Any] | None:
        body = json.dumps(
            {"info": self.get_self_info().to_json(), "files": files},
            ensure_ascii=False,
        ).encode("utf-8")
        path = "/api/localsend/v2/prepare-upload"
        if pin:
            path += f"?pin={pin}"

        status, data = self._request("POST", path, body)
        if status == 204:
            return None
        if status == 401:
            raise SendError("需要 PIN 码或 PIN 码错误")
        if status == 403:
            raise SendError("对端拒绝了本次传输")
        if status == 409:
            raise SendError("对端正忙，请稍后重试")
        if status == 429:
            raise SendError("PIN 码尝试次数过多，请稍后再试")
        if status != 200:
            raise SendError(f"prepare-upload 返回 {status}")

        try:
            return json.loads(data)
        except ValueError as exc:
            raise SendError("prepare-upload 响应无法解析") from exc

    def upload_file(
        self,
        session_id: str,
        file_id: str,
        token: str,
        path: Path,
        progress: Callable[[int], None] | None = None,
    ) -> None:
        size = path.stat().st_size
        conn = self._connection()
        try:
            conn.timeout = 300
            query = (
                f"/api/localsend/v2/upload"
                f"?sessionId={session_id}&fileId={file_id}&token={token}"
            )
            conn.putrequest("POST", query)
            conn.putheader("Content-Type", "application/octet-stream")
            conn.putheader("Content-Length", str(size))
            conn.endheaders()

            sent = 0
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(512 * 1024)
                    if not chunk:
                        break
                    conn.send(chunk)
                    sent += len(chunk)
                    if progress:
                        progress(sent)

            resp = conn.getresponse()
            resp.read()
            if resp.status == 422:
                raise SendError("校验和不匹配，文件可能已损坏")
            if resp.status == 403:
                raise SendError("令牌无效或来源 IP 不匹配")
            if resp.status != 200:
                raise SendError(f"upload 返回 {resp.status}")
        except (OSError, ssl.SSLError) as exc:
            raise SendError(f"上传失败：{exc}") from exc
        finally:
            conn.close()

    def cancel(self, session_id: str) -> None:
        try:
            self._request(
                "POST", f"/api/localsend/v2/cancel?sessionId={session_id}"
            )
        except SendError:
            pass


def build_file_dtos(paths: list[str]) -> tuple[dict[str, dict[str, Any]], dict[str, Path]]:
    """把本地路径展开为协议所需的 FileDto 字典，并计算 SHA-256。"""
    dtos: dict[str, dict[str, Any]] = {}
    mapping: dict[str, Path] = {}

    expanded: list[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            for child in sorted(p.rglob("*")):
                if child.is_file():
                    expanded.append(child)
        elif p.is_file():
            expanded.append(p)
        else:
            raise SendError(f"文件不存在：{raw}")

    if not expanded:
        raise SendError("没有可发送的文件")

    for path in expanded:
        file_id = str(uuid.uuid4())
        try:
            stat = path.stat()
            size = stat.st_size
        except OSError as exc:
            raise SendError(f"无法读取 {path}：{exc}") from exc

        digest = _sha256_file(path)
        mime, _ = mimetypes.guess_type(path.name)
        metadata: dict[str, Any] = {}
        try:
            import datetime
            metadata["modified"] = (
                datetime.datetime.fromtimestamp(stat.st_mtime)
                .astimezone(datetime.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            )
        except (OSError, ValueError):
            pass

        dto: dict[str, Any] = {
            "id": file_id,
            "fileName": path.name,
            "size": size,
            "fileType": mime or "application/octet-stream",
            "sha256": digest,
        }
        if metadata:
            dto["metadata"] = metadata

        dtos[file_id] = dto
        mapping[file_id] = path

    return dtos, mapping


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def sha256_cert_fingerprint(host: str, port: int, timeout: float = 10.0) -> str | None:
    """从对端 TLS 握手读取证书指纹（用于 HTTP 发现后的身份固定）。"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    cert, key = cert_paths()
    if cert.is_file() and key.is_file():
        try:
            ctx.load_cert_chain(str(cert), str(key))
        except (OSError, ssl.SSLError):
            pass

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return None
                return hashlib.sha256(der).hexdigest().upper()
    except (OSError, ssl.SSLError) as exc:
        log.debug("读取 %s:%s 证书失败：%s", host, port, exc)
        return None
