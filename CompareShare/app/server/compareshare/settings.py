"""运行时配置：读取/写入应用配置，并解析飞牛注入的目录变量。"""

from __future__ import annotations

import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "alias": "",
    "download_dir": "",
    "port": 53317,
    "web_port": 11011,
    "https": True,
    "pin": "",
    "auto_accept": True,
    "device_model": "fnOS NAS",
    "device_type": "server",
    "announce_interval": 30,
    "interfaces": [],
    "open_in_folder": False,
    # 浏览器上传页：手机不装应用也能传文件
    "web_upload": True,
}

_lock = threading.RLock()


def _env_path(name: str, fallback: str) -> Path:
    raw = os.environ.get(name, "").strip()
    return Path(raw) if raw else Path(fallback)


def config_dir() -> Path:
    p = _env_path("TRIM_PKGETC", str(Path.home() / ".compareshare" / "etc"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def var_dir() -> Path:
    p = _env_path("TRIM_PKGVAR", str(Path.home() / ".compareshare" / "var"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def app_dest() -> Path:
    p = _env_path("TRIM_APPDEST", str(Path(__file__).resolve().parent.parent))
    return p


def log_file() -> Path:
    return var_dir() / "server.log"


def tls_dir() -> Path:
    """证书放在配置目录而非数据目录。

    fingerprint 是本机在 LocalSend 网络里的身份，对端设备靠它记住本机；
    放在配置目录可以跨重装、升级保留，避免对端需要重新信任。
    """
    p = config_dir() / "tls"
    p.mkdir(parents=True, exist_ok=True)
    return p


def share_paths() -> list[str]:
    """飞牛通过 TRIM_DATA_SHARE_PATHS 暴露 config/resource 里声明的共享目录。"""
    raw = os.environ.get("TRIM_DATA_SHARE_PATHS", "")
    return [p for p in raw.split(":") if p]


def accessible_paths() -> list[str]:
    """飞牛已授权给本应用的目录（用户授权后由系统注入，最权威的来源）。"""
    raw = os.environ.get("TRIM_DATA_ACCESSIBLE_PATHS", "")
    return [p for p in raw.split(":") if p]


def system_version() -> str:
    """飞牛系统版本，例如 1.2.0604。"""
    return os.environ.get("TRIM_SYS_VERSION", "").strip()


def version_tuple(text: str) -> tuple[int, ...]:
    parts: list[int] = []
    for seg in (text or "").split("."):
        digits = "".join(c for c in seg if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def default_download_dir() -> str:
    """默认收件目录，优先用应用自己的共享目录。"""
    shares = share_paths()
    if shares:
        inbox = shares[0]
        # 共享目录可能以 appname 为根，inbox 子目录更合适
        candidate = os.path.join(inbox, "inbox") if not inbox.endswith("inbox") else inbox
        return candidate
    return str(var_dir() / "received")


def default_alias() -> str:
    try:
        host = os.uname().nodename
    except Exception:
        host = "CompareShare"
    return f"{host} (Compare Share)"


class Settings:
    """线程安全的应用配置。"""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (config_dir() / "config.json")
        self._data: dict[str, Any] = dict(DEFAULTS)
        self._dir_error: str | None = None
        self.load()

    def load(self) -> None:
        with _lock:
            data = dict(DEFAULTS)
            if self.path.is_file():
                try:
                    loaded = json.loads(self.path.read_text("utf-8"))
                    if isinstance(loaded, dict):
                        data.update(loaded)
                except (OSError, ValueError):
                    pass
            if not data.get("alias"):
                data["alias"] = default_alias()
            if not data.get("download_dir"):
                data["download_dir"] = default_download_dir()
            self._data = data
            self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """尝试创建收件目录。

        失败时记录原因而不是静默忽略：目录不存在或不可写时，
        收文件会失败，用户需要知道是配置问题而不是传到一半丢文件。
        """
        target = self._data.get("download_dir")
        if not target:
            self._dir_error = "未配置下载目录"
            return
        try:
            Path(target).mkdir(parents=True, exist_ok=True)
            self._dir_error = None
        except OSError as exc:
            self._dir_error = (
                f"无法创建或访问下载目录 {target}：{exc.strerror or exc}。"
                "请在设置中选择一个已授权且存在的目录。"
            )

    def save(self) -> None:
        with _lock:
            tmp = self.path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            tmp.replace(self.path)

    def get(self, key: str, default: Any = None) -> Any:
        with _lock:
            return self._data.get(key, DEFAULTS.get(key, default))

    def as_dict(self) -> dict[str, Any]:
        with _lock:
            return dict(self._data)

    def update(self, patch: dict[str, Any]) -> dict[str, Any]:
        allowed = set(DEFAULTS)
        with _lock:
            for key, value in patch.items():
                if key in allowed:
                    self._data[key] = value
            if not self._data.get("download_dir"):
                self._data["download_dir"] = default_download_dir()
            self._ensure_dirs()
            self.save()
            return dict(self._data)

    def validate_download_dir(self, target: str) -> str | None:
        """校验收件目录可用性，返回错误说明或 None。

        目录不存在且无法创建时直接报错：否则用户以为设置生效，
        实际收文件会在最后一步失败。
        """
        if not target:
            return "下载目录不能为空"
        if not target.startswith("/"):
            return "请填写以 / 开头的完整路径"
        path = Path(target)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return (
                f"目录不存在且无法创建（{exc.strerror or exc}）。"
                "请先在飞牛文件管理器中创建该目录，或在「飞牛目录授权」中选择已有目录。"
            )
        if not path.is_dir():
            return "该路径不是目录"
        if not os.access(path, os.W_OK):
            return (
                "应用当前身份没有该目录的写权限。"
                "请在「飞牛目录授权」中授权此目录后重试。"
            )
        try:
            probe = path / f".compareshare-write-test-{secrets.token_hex(4)}"
            probe.write_bytes(b"")
            probe.unlink()
        except OSError as exc:
            return f"目录不可写（{exc.strerror or exc}），请检查授权。"
        return None

    def dir_error(self) -> str | None:
        with _lock:
            return self._dir_error

    def ensure_pin(self, length: int = 6) -> str:
        """返回现有 PIN，没有则生成一个（用于「需要确认」模式）。"""
        with _lock:
            pin = str(self._data.get("pin") or "")
            if len(pin) == length and pin.isdigit():
                return pin
            pin = "".join(secrets.choice("0123456789") for _ in range(length))
            self._data["pin"] = pin
            self.save()
            return pin

    def clear_pin(self) -> None:
        self.update({"pin": ""})

    def download_dir(self) -> Path:
        with _lock:
            raw = self._data.get("download_dir") or default_download_dir()
        return Path(raw)

    def effective_https(self) -> bool:
        return bool(self.get("https", True))

    def effective_port(self) -> int:
        try:
            return int(self.get("port", 53317))
        except (TypeError, ValueError):
            return 53317
