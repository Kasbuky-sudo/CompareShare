"""LocalSend v2.2 接收端：register / prepare-upload / upload / cancel 等接口。

设计要点：
  * 上传走流式落盘，边写边算 SHA-256，绝不全量读入内存
  * 文件名一律清洗为单段名，并校验落盘路径仍在收件目录内（防穿越）
  * 同名文件自动改名 file (1).ext，绝不覆盖
  * 收到 size 之外的字节要截断，少于 size 视为失败
  * 一次只允许一个上传会话（协议规定 409）
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from pathlib import Path
from typing import Any

from .protocol import DeviceInfo, FileDto, Session, sanitize_filename

log = logging.getLogger("compareshare.receiver")

PIN_MAX_ATTEMPTS = 3
PIN_BLOCK_SECONDS = 60
# 对端中途断线时，会话不能永久占位（协议规定同一时刻只允许一个上传会话）
SESSION_TIMEOUT = 120.0


class ReceiveError(Exception):
    """带 HTTP 状态码的业务错误。"""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def unique_path(directory: Path, filename: str) -> Path:
    """在目录中为文件找一个不冲突的名字，形如 name (1).ext。"""
    candidate = directory / filename
    if not candidate.exists():
        return candidate

    stem, suffix = os.path.splitext(filename)
    for i in range(1, 10000):
        candidate = directory / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
    return directory / f"{stem} ({uuid.uuid4().hex[:8]}){suffix}"


class PinGuard:
    """按来源 IP 限制 PIN 尝试次数。"""

    def __init__(self) -> None:
        self._failures: dict[str, tuple[int, float]] = {}

    def check(self, ip: str, expected: str, provided: str | None) -> None:
        if not expected:
            return
        count, blocked_at = self._failures.get(ip, (0, 0.0))
        if blocked_at and time.time() - blocked_at < PIN_BLOCK_SECONDS:
            raise ReceiveError(429, "Too many requests")
        if blocked_at:
            self._failures.pop(ip, None)
            count = 0

        if provided != expected:
            count += 1
            if count >= PIN_MAX_ATTEMPTS:
                self._failures[ip] = (count, time.time())
                raise ReceiveError(429, "Too many requests")
            self._failures[ip] = (count, 0.0)
            raise ReceiveError(401, "PIN required or invalid")

        self._failures.pop(ip, None)


class Receiver:
    """上传会话管理与落盘。"""

    def __init__(self, get_download_dir, get_pin) -> None:
        self.get_download_dir = get_download_dir
        self.get_pin = get_pin
        self.pin_guard = PinGuard()
        self._session: Session | None = None
        self._lock = __import__("threading").RLock()
        self.history: list[dict[str, Any]] = []

    # ---- 会话 --------------------------------------------------------

    def current_session(self) -> Session | None:
        with self._lock:
            self._expire_stale()
            return self._session

    def _expire_stale(self) -> None:
        """清理长时间无进展的会话（调用方需持有锁）。"""
        session = self._session
        if session is None:
            return
        last = max([session.created, *(session.progress.values() or [session.created])])
        if time.time() - last > SESSION_TIMEOUT:
            log.info("会话 %s 超时，已释放", session.session_id)
            self._session = None

    def clear_session(self, session_id: str | None = None) -> bool:
        with self._lock:
            if self._session is None:
                return False
            if session_id and self._session.session_id != session_id:
                return False
            self._session = None
            return True

    def prepare_upload(self, body: dict[str, Any], remote_addr: str, pin: str | None) -> dict[str, Any] | None:
        """返回 {sessionId, files:{id:token}}；无需传输时返回 None。"""
        expected_pin = self.get_pin()
        self.pin_guard.check(remote_addr, expected_pin, pin)

        info_raw = body.get("info")
        files_raw = body.get("files")
        if not isinstance(info_raw, dict) or not isinstance(files_raw, dict):
            raise ReceiveError(400, "Invalid body")

        peer = DeviceInfo.from_json(info_raw)
        files: dict[str, FileDto] = {}
        for fid, fdata in files_raw.items():
            if not isinstance(fdata, dict):
                continue
            files[str(fid)] = FileDto.from_json(fdata)

        if not files:
            return None

        with self._lock:
            self._expire_stale()
            if self._session is not None and not self._session.is_complete():
                raise ReceiveError(409, "Blocked by another session")

            session = Session(
                session_id=str(uuid.uuid4()),
                peer=peer,
                files=files,
                tokens={fid: str(uuid.uuid4()) for fid in files},
                remote_addr=remote_addr,
                created=time.time(),
            )
            self._session = session
            log.info(
                "接收会话开始：来自 %s（%s），%d 个文件",
                peer.alias, remote_addr, len(files),
            )
            return {
                "sessionId": session.session_id,
                "files": dict(session.tokens),
            }

    # ---- 上传 --------------------------------------------------------

    def upload(
        self,
        session_id: str,
        file_id: str,
        token: str,
        body: Any,
        remote_addr: str,
        content_length: int | None,
        chunked: bool = False,
    ) -> None:
        with self._lock:
            session = self._session
        if session is None or session.session_id != session_id:
            raise ReceiveError(403, "Invalid token or IP")
        if session.remote_addr != remote_addr:
            raise ReceiveError(403, "Invalid token or IP")
        if session.tokens.get(file_id) != token:
            raise ReceiveError(403, "Invalid token or IP")

        fmeta = session.files.get(file_id)
        if fmeta is None:
            raise ReceiveError(400, "Missing parameters")

        directory = Path(self.get_download_dir())
        directory.mkdir(parents=True, exist_ok=True)

        safe_name = sanitize_filename(fmeta.file_name)
        target = unique_path(directory, safe_name)
        # 防穿越：最终路径必须仍在收件目录内
        try:
            if not str(target.resolve()).startswith(str(directory.resolve()) + os.sep):
                raise ReceiveError(400, "Missing parameters")
        except OSError:
            pass

        expected = fmeta.size
        digest = hashlib.sha256()
        written = 0
        # 临时名与目标名长度无关，避免长文件名加上后缀后超出文件系统上限
        tmp = directory / f".{uuid.uuid4().hex}.part"

        try:
            with open(tmp, "wb") as fh:
                if chunked:
                    # 客户端用 Transfer-Encoding: chunked 流式上传。
                    # BaseHTTPRequestHandler 不会自动解码分块格式，
                    # 直接按字节读会把分块长度标记写进文件，导致内容损坏
                    # （字节数看似正确，但校验和不匹配）。
                    written = _read_chunked(body, fh, digest, expected)
                else:
                    written = _read_sized(body, fh, digest, expected)
                fh.flush()
                os.fsync(fh.fileno())

            if written != expected:
                raise ReceiveError(500, "Receiver error")

            if fmeta.sha256 and digest.hexdigest().lower() != fmeta.sha256.lower():
                log.warning(
                    "校验和不匹配：%s（期望 %s，实际 %s，收到 %d 字节）",
                    fmeta.file_name, fmeta.sha256[:16], digest.hexdigest()[:16], written,
                )
                raise ReceiveError(422, "Checksum mismatch")

            # 保留对端给出的修改时间
            meta = fmeta.metadata or {}
            modified = meta.get("modified")
            if isinstance(modified, str):
                try:
                    ts = _parse_iso8601(modified)
                    if ts:
                        os.utime(tmp, (ts, ts))
                except (ValueError, OSError):
                    pass

            os.replace(tmp, target)
        except ReceiveError:
            _silent_unlink(tmp)
            raise
        except OSError as exc:
            _silent_unlink(tmp)
            log.exception("写入文件失败")
            raise ReceiveError(500, f"Receiver error: {exc}") from exc

        with self._lock:
            session.received[file_id] = written
            session.finished.add(file_id)
            session.progress[file_id] = time.time()
            complete = session.is_complete()

        log.info("已接收文件：%s（%d 字节）", target.name, written)

        if complete:
            self._record_history(session, directory)
            with self._lock:
                if self._session is session:
                    self._session = None

    def _record_history(self, session: Session, directory: Path) -> None:
        entry = {
            "time": time.time(),
            "alias": session.peer.alias,
            "remoteAddr": session.remote_addr,
            "count": len(session.finished),
            "bytes": sum(session.received.values()),
            "direction": "in",
            "dir": str(directory),
            "files": [
                session.files[fid].file_name
                for fid in session.finished
                if fid in session.files
            ][:50],
        }
        self.history.insert(0, entry)
        del self.history[200:]


def _silent_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _read_sized(body: Any, fh: Any, digest: Any, expected: int) -> int:
    """按 Content-Length 精确读取。

    两点必须注意：
    1. 按剩余字节数读：socket 上的 read(n) 会阻塞到凑满 n 字节，
       而对端发完就等响应，直接读会死锁。
    2. 对端声明的 size 可能大于实际发送量（异常客户端或中途断流），
       此时 read 会一直等下去。依赖 socket 超时兜底，返回已读字节数，
       由调用方判定体积不符。
    """
    written = 0
    remaining = expected
    while remaining > 0:
        try:
            chunk = body.read(min(512 * 1024, remaining))
        except (TimeoutError, OSError):
            # 对端未按声明长度发送，停止等待，交由体积校验判定失败
            break
        if not chunk:
            break
        fh.write(chunk)
        digest.update(chunk)
        written += len(chunk)
        remaining -= len(chunk)
    return written


def _read_chunked(body: Any, fh: Any, digest: Any, expected: int) -> int:
    """解碼 HTTP chunked 传输编码并写入文件。

    分块格式：<十六进制长度>[;扩展]CRLF<数据>CRLF … 以长度 0 的分块结束。
    不解码会把长度标记混进文件内容（字节数可能仍与 expected 相符），
    因此必须逐块解析后再落盘。
    """
    written = 0

    def read_line() -> bytes:
        line = body.readline(1024)
        if not line:
            raise ValueError("chunked body truncated")
        return line.rstrip(b"\r\n")

    while True:
        header = read_line()
        # 长度后可带扩展（;key=value），忽略之
        size_part = header.split(b";", 1)[0].strip()
        if not size_part:
            continue
        try:
            size = int(size_part, 16)
        except ValueError as exc:
            raise ValueError(f"invalid chunk size: {size_part[:20]!r}") from exc

        if size == 0:
            # 末尾可能还有 trailer，读到空行为止
            while True:
                trailer = body.readline(1024)
                if trailer in (b"", b"\r\n", b"\n"):
                    break
            break

        remaining = size
        while remaining > 0:
            piece = body.read(min(512 * 1024, remaining))
            if not piece:
                raise ValueError("chunked body truncated")
            # 超出声明大小则截断，避免写入多余数据
            if written + len(piece) > expected:
                piece = piece[: max(0, expected - written)]
            if piece:
                fh.write(piece)
                digest.update(piece)
                written += len(piece)
            remaining -= len(piece)

        read_line()  # 分块数据后的 CRLF

    return written


_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|z|[+-]\d{2}:?\d{2})?$"
)


def _parse_iso8601(value: str) -> float | None:
    """宽松解析 ISO 8601（官方客户端会带小数秒）。"""
    m = _ISO.match(value.strip())
    if not m:
        return None
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    frac = m.group(7) or ""
    micro = int((frac + "000000")[:6]) if frac else 0
    tz = m.group(8)
    import calendar
    base = calendar.timegm((year, month, day, hour, minute, second, 0, 0, 0))
    offset = 0
    if tz and tz not in ("Z", "z"):
        sign = 1 if tz[0] == "+" else -1
        tz = tz[1:].replace(":", "")
        offset = sign * (int(tz[:2]) * 3600 + int(tz[2:4]) * 60)
    return base - offset + micro / 1_000_000
