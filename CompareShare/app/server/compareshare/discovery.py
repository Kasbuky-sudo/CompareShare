"""局域网设备发现：LocalSend 多播协议 + HTTP 子网扫描兜底。

要点（来自协议规格与官方实现）：
  * 多播组 224.0.0.167，端口 53317（UDP 与 TCP 同端口）
  * 每个接口一个独立 socket，用 IP_MULTICAST_IF 绑定出口，否则会从错误网卡发出
  * TTL 固定为 1，只在本网段传播；开启回环便于自测
  * 通过 fingerprint 过滤掉自己发出的广播
  * 必须排除 docker0 / veth* / br-* 等虚拟接口，否则广播会打到容器网络里
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import threading
import time
from typing import Callable

from .protocol import MULTICAST_GROUP, DeviceInfo

log = logging.getLogger("compareshare.discovery")

ANNOUNCE_DELAYS = (0.1, 0.5, 2.0)
_VIRTUAL_PREFIXES = ("docker", "veth", "br-", "virbr", "tun", "tap", "lo", "Meta")


def is_usable_interface(name: str) -> bool:
    """排除虚拟/容器接口，只保留真实物理网卡。"""
    if not name:
        return False
    for prefix in _VIRTUAL_PREFIXES:
        if name == prefix or name.startswith(prefix):
            return False
    return True


def list_interfaces(only: list[str] | None = None) -> list[tuple[str, str]]:
    """返回 [(接口名, IPv4 地址)]，仅包含已启用且有地址的真实网卡。"""
    results: list[tuple[str, str]] = []
    try:
        import fcntl  # type: ignore
    except ImportError:
        fcntl = None  # type: ignore

    try:
        names = socket.if_nameindex()
    except OSError:
        names = []

    for _idx, name in names:
        if only:
            if name not in only:
                continue
        elif not is_usable_interface(name):
            continue

        addr = _interface_ipv4(name)
        if addr:
            results.append((name, addr))
    return results


def _interface_ipv4(name: str) -> str | None:
    """用 ioctl 取网卡地址，避免依赖 psutil。"""
    try:
        import fcntl  # type: ignore
    except ImportError:
        return None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", name[:15].encode("utf-8"))
        res = fcntl.ioctl(s.fileno(), 0x8915, packed)  # SIOCGIFADDR
        return socket.inet_ntoa(res[20:24])
    except OSError:
        return None
    finally:
        s.close()


class DiscoveryService:
    """负责多播广播与监听，维护在线设备表。"""

    def __init__(
        self,
        port: int,
        get_self_info: Callable[[], DeviceInfo],
        on_peer: Callable[[DeviceInfo, str, str], None],
        interfaces: list[str] | None = None,
    ) -> None:
        self.port = port
        self.get_self_info = get_self_info
        self.on_peer = on_peer
        self.interfaces = interfaces or []

        self._sockets: list[tuple[socket.socket, str]] = []
        self._running = False
        self._threads: list[threading.Thread] = []
        self._send_lock = threading.Lock()

    # ---- 生命周期 ----------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._running = True

        ifaces = list_interfaces(self.interfaces)
        if not ifaces:
            log.warning("未找到可用网卡，多播发现不可用")
            self._running = False
            return

        for name, addr in ifaces:
            sock = self._make_socket(addr)
            if sock is None:
                continue
            self._sockets.append((sock, name))
            t = threading.Thread(
                target=self._listen_loop, args=(sock, name), daemon=True,
                name=f"discovery-rx-{name}",
            )
            t.start()
            self._threads.append(t)
            log.info("多播监听已启动：%s (%s)", name, addr)

        threading.Thread(target=self._announce_loop, daemon=True, name="announce").start()

    def stop(self) -> None:
        self._running = False
        for sock, _name in self._sockets:
            try:
                sock.close()
            except OSError:
                pass
        self._sockets.clear()

    # ---- socket 构造 -------------------------------------------------

    def _make_socket(self, addr: str) -> socket.socket | None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass

            # 必须绑定通配地址才能收到发往多播组的数据报
            sock.bind(("", self.port))

            mreq = struct.pack("4s4s", socket.inet_aton(MULTICAST_GROUP), socket.inet_aton(addr))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            # 固定出口网卡，否则会按路由表选路（x86 那台默认路由是 Meta 口）
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
            sock.settimeout(1.0)
            return sock
        except OSError as exc:
            log.warning("网卡 %s 多播 socket 创建失败：%s", addr, exc)
            return None

    # ---- 收发 --------------------------------------------------------

    def _listen_loop(self, sock: socket.socket, name: str) -> None:
        while self._running:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                msg = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(msg, dict):
                continue
            if not msg.get("announce", False):
                # 只处理主动广播，忽略应答
                if "announce" in msg and not msg["announce"]:
                    continue

            info = DeviceInfo.from_json(msg)
            me = self.get_self_info()
            if info.fingerprint and info.fingerprint == me.fingerprint:
                continue  # 自己发的
            if not info.alias:
                continue

            try:
                self.on_peer(info, addr[0], "multicast")
            except Exception:  # noqa: BLE001 - 回调异常不应中断监听
                log.exception("多播设备回调失败")

    def announce_now(self) -> None:
        self._announce_once()

    def _announce_loop(self) -> None:
        interval = 30.0
        while self._running:
            self._announce_once()
            # 分段等待，便于快速退出
            slept = 0.0
            while self._running and slept < interval:
                time.sleep(0.5)
                slept += 0.5

    def _announce_once(self) -> None:
        me = self.get_self_info()
        payload = json.dumps(me.to_json(announce=True), ensure_ascii=False).encode("utf-8")
        for delay in ANNOUNCE_DELAYS:
            if not self._running:
                return
            with self._send_lock:
                for sock, _name in self._sockets:
                    try:
                        sock.sendto(payload, (MULTICAST_GROUP, self.port))
                    except OSError:
                        pass
            if delay:
                time.sleep(delay)
