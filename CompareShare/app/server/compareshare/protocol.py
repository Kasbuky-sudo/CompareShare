"""LocalSend 协议 v2.2 —— 数据模型与线格式。

规格：https://github.com/localsend/protocol
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

PROTOCOL_VERSION = "2.2"
DEFAULT_PORT = 53317
MULTICAST_GROUP = "224.0.0.167"
MULTICAST_GROUP_V6 = "ff12::fd3a:e420"

# 文件名清洗：仅保留最后一段，替换非法字符，限制长度
_ILLEGAL = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def sanitize_filename(name: str, max_bytes: int = 255) -> str:
    """把对端传来的文件名收敛为安全的单段文件名。"""
    if not name:
        return "untitled"
    # 取最后一段，阻断路径穿越
    name = name.replace("\\", "/").split("/")[-1]
    name = _ILLEGAL.sub("_", name).strip()
    name = name.rstrip(". ")
    if not name:
        return "untitled"
    stem = name.split(".")[0].lower()
    if stem in _RESERVED:
        name = f"_{name}"
    return _truncate_bytes(name, max_bytes)


def _truncate_bytes(name: str, max_bytes: int) -> str:
    """按 UTF-8 字符边界截断，尽量保留扩展名。"""
    if len(name.encode("utf-8")) <= max_bytes:
        return name

    root, ext = os.path.splitext(name)
    ext_bytes = len(ext.encode("utf-8"))
    # 扩展名本身就超限或没有扩展名时，整体截断
    if not ext or ext_bytes >= max_bytes // 2:
        return _cut(name, max_bytes) or "untitled"

    budget = max_bytes - ext_bytes
    root = _cut(root, budget)
    return (root + ext) if root else _cut(name, max_bytes) or "untitled"


def _cut(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    # 回退到合法字符边界
    return encoded[:max_bytes].decode("utf-8", "ignore")


@dataclass
class FileDto:
    id: str
    file_name: str
    size: int
    file_type: str = "application/octet-stream"
    sha256: str | None = None
    preview: str | None = None
    metadata: dict[str, Any] | None = None

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "FileDto":
        meta = data.get("metadata")
        return cls(
            id=str(data.get("id", "")),
            file_name=str(data.get("fileName", "")),
            size=int(data.get("size", 0) or 0),
            file_type=str(data.get("fileType") or "application/octet-stream"),
            sha256=(data.get("sha256") or None),
            preview=(data.get("preview") or None),
            metadata=meta if isinstance(meta, dict) else None,
        )

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "fileName": self.file_name,
            "size": self.size,
            "fileType": self.file_type,
        }
        if self.sha256:
            out["sha256"] = self.sha256
        if self.preview:
            out["preview"] = self.preview
        if self.metadata:
            out["metadata"] = self.metadata
        return out


@dataclass
class DeviceInfo:
    """announce / register 共用的设备信息。"""

    alias: str
    version: str = PROTOCOL_VERSION
    device_model: str | None = None
    device_type: str | None = "server"
    fingerprint: str = ""
    port: int = DEFAULT_PORT
    protocol: str = "https"
    download: bool = True

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "DeviceInfo":
        return cls(
            alias=str(data.get("alias", "")),
            version=str(data.get("version", PROTOCOL_VERSION)),
            device_model=data.get("deviceModel"),
            device_type=data.get("deviceType"),
            fingerprint=str(data.get("fingerprint", "")),
            port=int(data.get("port", DEFAULT_PORT) or DEFAULT_PORT),
            protocol=str(data.get("protocol", "https")),
            download=bool(data.get("download", False)),
        )

    def to_json(self, announce: bool | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {
            "alias": self.alias,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "port": self.port,
            "protocol": self.protocol,
            "download": self.download,
        }
        if self.device_model:
            out["deviceModel"] = self.device_model
        if self.device_type:
            out["deviceType"] = self.device_type
        if announce is not None:
            out["announce"] = announce
        return out

    def to_register_response(self) -> dict[str, Any]:
        """register 响应不回 port / protocol（对端已从 URL 得知）。"""
        out: dict[str, Any] = {
            "alias": self.alias,
            "version": self.version,
            "fingerprint": self.fingerprint,
            "download": self.download,
        }
        if self.device_model:
            out["deviceModel"] = self.device_model
        if self.device_type:
            out["deviceType"] = self.device_type
        return out


@dataclass
class Peer:
    """已发现的局域网设备。"""

    info: DeviceInfo
    host: str
    last_seen: float
    source: str = "multicast"
    online: bool = True
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return self.info.fingerprint

    @property
    def alias(self) -> str:
        return self.info.alias

    def key(self) -> str:
        return self.fingerprint or f"{self.host}:{self.info.port}"

    def to_json(self) -> dict[str, Any]:
        return {
            "alias": self.info.alias,
            "host": self.host,
            "port": self.info.port,
            "protocol": self.info.protocol,
            "deviceModel": self.info.device_model,
            "deviceType": self.info.device_type,
            "fingerprint": self.info.fingerprint,
            "version": self.info.version,
            "download": self.info.download,
            "source": self.source,
            "online": self.online,
            "lastSeen": self.last_seen,
        }


@dataclass
class Session:
    """一次上传会话。"""

    session_id: str
    peer: DeviceInfo
    files: dict[str, FileDto]
    tokens: dict[str, str]
    remote_addr: str
    created: float
    received: dict[str, int] = field(default_factory=dict)
    finished: set[str] = field(default_factory=set)
    progress: dict[str, float] = field(default_factory=dict)

    def is_complete(self) -> bool:
        return len(self.finished) >= len(self.tokens)

    def to_json(self) -> dict[str, Any]:
        return {
            "sessionId": self.session_id,
            "alias": self.peer.alias,
            "remoteAddr": self.remote_addr,
            "created": self.created,
            "files": [
                {
                    **f.to_json(),
                    "received": self.received.get(fid, 0),
                    "finished": fid in self.finished,
                }
                for fid, f in self.files.items()
            ],
        }
