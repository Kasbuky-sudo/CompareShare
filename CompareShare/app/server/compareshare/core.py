"""应用核心：聚合配置、发现、收发与会话状态。"""

from __future__ import annotations

import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from . import receiver as receiver_mod
from . import sender as sender_mod
from .discovery import DiscoveryService
from .fnos import FnosOpenApi, is_safe_path
from .protocol import (
    DEFAULT_PORT,
    PROTOCOL_VERSION,
    DeviceInfo,
    Peer,
    sanitize_filename,
)
from .settings import Settings, share_paths
from .tls import ensure_certificate, generate_random_fingerprint

log = logging.getLogger("compareshare.core")

APP_NAME = "CompareShare"
PEER_TTL = 300.0


class AppState:
    """进程内的全局状态。"""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()
        self.lock = threading.RLock()
        self.started_at = time.time()

        self.fingerprint = ""
        self._init_identity()

        self.receiver = receiver_mod.Receiver(
            get_download_dir=lambda: str(self.settings.download_dir()),
            get_pin=lambda: str(self.settings.get("pin") or ""),
        )
        self.peers: dict[str, Peer] = {}
        self._replied: dict[str, float] = {}
        self.fnos = FnosOpenApi(APP_NAME)

        self.discovery = DiscoveryService(
            port=self.port,
            get_self_info=self.self_info,
            on_peer=self._on_peer,
            interfaces=list(self.settings.get("interfaces") or []),
        )
        self.transfers: list[dict[str, Any]] = []
        self._transfer_lock = threading.Lock()

    # ---- 身份 --------------------------------------------------------

    def _init_identity(self) -> None:
        if self.settings.effective_https():
            try:
                self.fingerprint = ensure_certificate()
                return
            except RuntimeError as exc:
                log.error("证书不可用（%s），回退为 HTTP 模式", exc)
                self.settings.update({"https": False})
        self.fingerprint = generate_random_fingerprint()

    @property
    def port(self) -> int:
        return self.settings.effective_port()

    @property
    def web_port(self) -> int:
        try:
            return int(self.settings.get("web_port", 11011))
        except (TypeError, ValueError):
            return 11011

    def self_info(self) -> DeviceInfo:
        return DeviceInfo(
            alias=str(self.settings.get("alias") or "Compare Share"),
            version=PROTOCOL_VERSION,
            device_model=str(self.settings.get("device_model") or "fnOS NAS"),
            device_type=str(self.settings.get("device_type") or "server"),
            fingerprint=self.fingerprint,
            port=self.port,
            protocol="https" if self.settings.effective_https() else "http",
            download=True,
        )

    # ---- 设备表 ------------------------------------------------------

    def _on_peer(self, info: DeviceInfo, host: str, source: str) -> None:
        peer = Peer(info=info, host=host, last_seen=time.time(), source=source)
        key = peer.key()
        is_new = False
        with self.lock:
            existing = self.peers.get(key)
            if existing:
                existing.info = info
                existing.host = host
                existing.last_seen = time.time()
                existing.source = source
                existing.online = True
            else:
                # 同一 host:port 换了指纹，说明设备重装或换了证书身份，
                # 应替换旧条目而不是并存，避免列表里出现同一台设备的僵尸记录
                for old_key, old_peer in list(self.peers.items()):
                    if (old_peer.host == host and old_peer.info.port == info.port
                            and old_peer.fingerprint != info.fingerprint):
                        del self.peers[old_key]
                        log.info(
                            "设备 %s 指纹变化，替换旧记录（%s → %s）",
                            info.alias, old_peer.fingerprint[:12], info.fingerprint[:12],
                        )
                        break
                self.peers[key] = peer
                is_new = True

        if is_new:
            log.info("发现设备：%s @ %s:%s（%s）", info.alias, host, info.port, source)
            # 协议规定：收到广播后要用 HTTP register 回访，对方才会知道本机存在。
            # 无线网络下多播常被路由器过滤，这一步是双向发现的关键。
            if source == "multicast":
                self._reply_announce(info, host)

    def _reply_announce(self, info: DeviceInfo, host: str) -> None:
        if not info.port or not info.alias:
            return
        now = time.time()
        with self.lock:
            last = self._replied.get(host, 0.0)
            if now - last < 60.0:  # 同一台设备一分钟内只回访一次
                return
            self._replied[host] = now
            if len(self._replied) > 500:
                for key in list(self._replied)[:250]:
                    self._replied.pop(key, None)

        def _worker() -> None:
            from . import sender as sender_mod
            for proto in ("https", "http"):
                try:
                    client = sender_mod.PeerClient(
                        host=host,
                        port=info.port,
                        protocol=proto,
                        self_info=self.self_info,
                        fingerprint=info.fingerprint or None,
                    )
                    client.register()
                    log.debug("已回访 %s（%s://%s:%s）", info.alias, proto, host, info.port)
                    return
                except Exception:  # noqa: BLE001 - 回访失败不影响主流程
                    continue

        threading.Thread(target=_worker, daemon=True, name=f"reply-{host}").start()

    def note_peer(self, info: DeviceInfo, host: str, source: str = "register") -> None:
        self._on_peer(info, host, source)

    def prune_peers(self) -> None:
        now = time.time()
        with self.lock:
            for key, peer in list(self.peers.items()):
                if now - peer.last_seen > PEER_TTL:
                    peer.online = False
                    if now - peer.last_seen > PEER_TTL * 4:
                        del self.peers[key]

    def list_peers(self) -> list[dict[str, Any]]:
        self.prune_peers()
        with self.lock:
            items = sorted(self.peers.values(), key=lambda p: (-p.online, p.alias.lower()))
            return [p.to_json() for p in items]

    def get_peer(self, key: str) -> Peer | None:
        with self.lock:
            return self.peers.get(key)

    def remove_peer(self, key: str) -> bool:
        with self.lock:
            return self.peers.pop(key, None) is not None

    # ---- 主动发现 ----------------------------------------------------

    def scan_network(self, timeout: float = 1.0, workers: int = 64) -> dict[str, Any]:
        """主动扫描本网段，弥补多播在无线网络下常被过滤的问题。

        协议规定的 HTTP 发现方式：向候选地址 POST /api/localsend/v2/register，
        有响应即为 LocalSend 设备。
        """
        from .discovery import list_interfaces
        from . import sender as sender_mod

        targets: list[str] = []
        for _name, addr in list_interfaces(list(self.settings.get("interfaces") or [])):
            parts = addr.split(".")
            if len(parts) != 4:
                continue
            prefix = ".".join(parts[:3])
            for last in range(1, 255):
                candidate = f"{prefix}.{last}"
                if candidate != addr:
                    targets.append(candidate)

        targets = list(dict.fromkeys(targets))
        if not targets:
            return {"scanned": 0, "found": 0}

        found: list[str] = []
        lock = threading.Lock()

        def probe(host: str) -> None:
            for proto in ("https", "http"):
                try:
                    client = sender_mod.PeerClient(
                        host=host,
                        port=self.port,
                        protocol=proto,
                        self_info=self.self_info,
                        fingerprint=None,  # 首次接触不固定指纹
                    )
                    info_raw = client.register()
                    if not info_raw:
                        continue
                    info = DeviceInfo.from_json(info_raw)
                    if not info.alias or info.fingerprint == self.fingerprint:
                        continue
                    info.protocol = proto
                    self._on_peer(info, host, "scan")
                    with lock:
                        found.append(info.alias)
                    return
                except Exception:  # noqa: BLE001 - 探测失败是常态
                    continue

        with ThreadPoolExecutor(max_workers=workers) as pool:
            pool.map(probe, targets)

        log.info("网段扫描完成：探测 %d 个地址，发现 %d 台设备", len(targets), len(found))
        return {"scanned": len(targets), "found": len(found), "peers": found}

    # ---- 收发 --------------------------------------------------------

    def send_files(
        self,
        peer_key: str,
        paths: list[str],
        pin: str | None = None,
        progress_cb: Any = None,
    ) -> dict[str, Any]:
        peer = self.get_peer(peer_key)
        if peer is None:
            raise sender_mod.SendError("设备不存在或已离线")

        record: dict[str, Any] = {
            "time": time.time(),
            "direction": "out",
            "alias": peer.alias,
            "host": peer.host,
            "state": "preparing",
            "total": 0,
            "sent": 0,
            "files": [],
            "error": None,
        }
        with self._transfer_lock:
            self.transfers.insert(0, record)
            del self.transfers[200:]

        try:
            dtos, mapping = sender_mod.build_file_dtos(paths)
            record["files"] = [d["fileName"] for d in dtos.values()]
            record["total"] = sum(d["size"] for d in dtos.values())
            record["state"] = "connecting"

            client = sender_mod.PeerClient(
                host=peer.host,
                port=peer.info.port,
                protocol=peer.info.protocol,
                self_info=self.self_info,
                fingerprint=peer.fingerprint or None,
            )

            prepared = client.prepare_upload(dtos, pin)
            if prepared is None:
                record["state"] = "done"
                record["note"] = "对端无需接收"
                return record

            session_id = prepared.get("sessionId", "")
            tokens = prepared.get("files", {}) or {}
            record["state"] = "transferring"

            sent_total = 0
            for file_id, token in tokens.items():
                path = mapping.get(file_id)
                if path is None:
                    continue

                def _cb(done: int, _base: int = sent_total) -> None:
                    record["sent"] = _base + done
                    if progress_cb:
                        progress_cb(record)

                client.upload_file(session_id, file_id, token, path, _cb)
                sent_total += path.stat().st_size
                record["sent"] = sent_total

            record["state"] = "done"
            return record
        except sender_mod.SendError as exc:
            record["state"] = "failed"
            record["error"] = str(exc)
            raise
        except Exception as exc:  # noqa: BLE001 - 兜底，记录后上抛
            record["state"] = "failed"
            record["error"] = str(exc)
            raise

    # ---- 下载（对端拉取） --------------------------------------------

    def list_share_files(self) -> list[dict[str, Any]]:
        directory = self.settings.download_dir()
        out: list[dict[str, Any]] = []
        try:
            entries = sorted(
                directory.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True
            )
        except OSError:
            return out
        for item in entries:
            if not item.is_file() or item.name.endswith(".part"):
                continue
            try:
                stat = item.stat()
            except OSError:
                continue
            import mimetypes
            mime, _ = mimetypes.guess_type(item.name)
            out.append(
                {
                    "id": item.name,
                    "fileName": item.name,
                    "size": stat.st_size,
                    "fileType": mime or "application/octet-stream",
                    "modified": stat.st_mtime,
                }
            )
            if len(out) >= 500:
                break
        return out

    def resolve_share_file(self, file_id: str) -> Path | None:
        """把文件 id 安全地解析为收件目录内的路径。"""
        name = sanitize_filename(file_id)
        if name != file_id:
            return None  # 名字被清洗过，说明原始输入可疑
        directory = self.settings.download_dir().resolve()
        candidate = (directory / name).resolve()
        try:
            if candidate.parent != directory or not candidate.is_file():
                return None
        except OSError:
            return None
        return candidate

    # ---- 飞牛目录授权 ------------------------------------------------

    def authorized_paths(self, uid: int | None = None) -> dict[str, Any]:
        """回读官方授权目录。只认系统返回的结果，不采信前端传参。

        用户域与共享域分别查询：任一接口不可用（例如 scope 未生效）时，
        仍返回另一域的结果，而不是整体失败。
        """
        result: dict[str, Any] = {
            "available": self.fnos.available(),
            "user": [],
            "shared": [],
            "labels": {},
            "errors": [],
            "error": None,
        }
        if not self.fnos.available():
            result["error"] = "当前环境不支持飞牛开放接口"
            return result

        if uid is None:
            uid = int(os.environ.get("TRIM_RUN_UID") or os.environ.get("TRIM_UID") or 0)

        # 首选来源：飞牛在用户授权后注入的 TRIM_DATA_ACCESSIBLE_PATHS。
        # 这是系统直接下发的授权结果，比走开放接口查询更可靠、无权限依赖。
        from .settings import accessible_paths
        try:
            injected = [p for p in accessible_paths() if is_safe_path(p)]
        except Exception:  # noqa: BLE001
            injected = []
        result["injected"] = injected

        if injected:
            result["user"] = injected
            try:
                result["labels"] = self.fnos.convert_path(injected)
            except Exception:  # noqa: BLE001
                pass
            return result

        if uid:
            try:
                result["user"] = [
                    p for p in self.fnos.user_accessible_folders(uid) if is_safe_path(p)
                ]
            except Exception as exc:  # noqa: BLE001 - 单域失败不影响另一域
                log.warning("查询用户授权目录失败：%s", exc)
                result["errors"].append(f"用户目录：{exc}")

        try:
            result["shared"] = [
                p for p in self.fnos.shared_accessible_folders() if is_safe_path(p)
            ]
        except Exception as exc:  # noqa: BLE001
            log.warning("查询共享授权目录失败：%s", exc)
            result["errors"].append(f"共享目录：{exc}")

        all_paths = result["user"] + result["shared"]
        if all_paths:
            try:
                result["labels"] = self.fnos.convert_path(all_paths)
            except Exception as exc:  # noqa: BLE001 - 语义路径只是锦上添花
                log.debug("路径转换失败：%s", exc)

        if result["errors"] and not all_paths:
            # TRIM_API_TOKEN 仅部分 fnOS 版本注入；缺少它时主来源
            # （TRIM_DATA_ACCESSIBLE_PATHS）仍然可用，因此不算故障。
            only_token = all("TRIM_API_TOKEN" in e for e in result["errors"])
            if not only_token:
                result["error"] = "；".join(result["errors"])
            else:
                result["degraded"] = True
        return result
    def share_dirs(self) -> list[str]:
        return share_paths()

    # ---- 生命周期 ----------------------------------------------------

    def start(self) -> None:
        self.discovery.start()
        # 启动后做一次网段扫描，补上多播在无线网络下被过滤导致的设备遗漏
        def _initial_scan() -> None:
            time.sleep(3)
            try:
                self.scan_network()
            except Exception:  # noqa: BLE001
                log.exception("启动扫描失败")

        threading.Thread(target=_initial_scan, daemon=True, name="initial-scan").start()

    def stop(self) -> None:
        self.discovery.stop()

    def status(self) -> dict[str, Any]:
        session = self.receiver.current_session()
        download_dir = self.settings.download_dir()
        return {
            "alias": self.settings.get("alias"),
            "fingerprint": self.fingerprint,
            "protocol": "https" if self.settings.effective_https() else "http",
            "port": self.port,
            "webPort": self.web_port,
            "downloadDir": str(download_dir),
            "pinRequired": bool(self.settings.get("pin")),
            "pin": str(self.settings.get("pin") or ""),
            "autoAccept": bool(self.settings.get("auto_accept", True)),
            "uptime": time.time() - self.started_at,
            "peers": len(self.list_peers()),
            "session": session.to_json() if session else None,
            "version": PROTOCOL_VERSION,
            "sharePaths": self.share_dirs(),
        }
