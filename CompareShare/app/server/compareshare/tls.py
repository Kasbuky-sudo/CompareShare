"""自签证书生成与指纹计算。

LocalSend 在 HTTPS 模式下用自签证书，设备身份即证书 DER 的 SHA-256（大写十六进制）。
官方实现刻意不做主机名校验（对端按 IP 访问），因此这里不写 SAN、CN 固定。

用 openssl 命令行生成，避免引入 cryptography 依赖；飞牛 fnOS 自带 openssl。
"""

from __future__ import annotations

import hashlib
import logging
import subprocess
from pathlib import Path

from .settings import tls_dir, var_dir

log = logging.getLogger("compareshare.tls")

CERT_NAME = "cert.pem"
KEY_NAME = "key.pem"


def cert_paths() -> tuple[Path, Path]:
    d = tls_dir()
    return d / CERT_NAME, d / KEY_NAME


def fingerprint_from_der(der: bytes) -> str:
    """证书指纹：SHA-256(DER) 大写十六进制，与官方实现一致。"""
    return hashlib.sha256(der).hexdigest().upper()


def _pem_to_der(pem_path: Path) -> bytes | None:
    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(pem_path), "-outform", "DER"],
            capture_output=True, check=True, timeout=30,
        )
        return out.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("读取证书失败：%s", exc)
        return None


def ensure_certificate() -> str:
    """确保存在自签证书，返回其指纹。已存在则直接复用。"""
    cert, key = cert_paths()

    if cert.is_file() and key.is_file():
        der = _pem_to_der(cert)
        if der:
            return fingerprint_from_der(der)
        log.warning("已有证书不可用，将重新生成")

    # 从旧位置（数据目录）迁移证书，保持设备身份不变
    _migrate_legacy_cert(cert, key)

    if cert.is_file() and key.is_file():
        der = _pem_to_der(cert)
        if der:
            return fingerprint_from_der(der)

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert),
        "-days", "3650",
        "-subj", "/CN=CompareShare",
    ]
    try:
        subprocess.run(cmd, capture_output=True, check=True, timeout=120)
    except FileNotFoundError as exc:
        raise RuntimeError("系统未安装 openssl，无法生成 TLS 证书") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"生成 TLS 证书失败：{exc.stderr.decode('utf-8', 'replace')[:200]}"
        ) from exc

    try:
        key.chmod(0o600)
    except OSError:
        pass

    der = _pem_to_der(cert)
    if not der:
        raise RuntimeError("生成后无法读取证书")
    fp = fingerprint_from_der(der)
    log.info("已生成自签证书，指纹 %s", fp)
    return fp


def _migrate_legacy_cert(cert: Path, key: Path) -> None:
    """把 1.0.0 放在数据目录的证书搬到配置目录，避免设备指纹变化。"""
    legacy_dir = var_dir() / "tls"
    legacy_cert = legacy_dir / CERT_NAME
    legacy_key = legacy_dir / KEY_NAME
    if not (legacy_cert.is_file() and legacy_key.is_file()):
        return
    if cert.exists() or key.exists():
        return
    try:
        import shutil
        shutil.copy2(legacy_cert, cert)
        shutil.copy2(legacy_key, key)
        key.chmod(0o600)
        log.info("已从旧位置迁移证书，保持设备指纹不变")
    except OSError as exc:
        log.warning("迁移旧证书失败：%s", exc)


def generate_random_fingerprint() -> str:
    """HTTP 模式下用随机字符串作为设备标识。"""
    import secrets
    return secrets.token_hex(32).upper()
