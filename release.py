#!/usr/bin/env python3
"""Compare Share 一条龙发布脚本。

用法：
    python release.py 1.2.1 "本次更新说明"

自动完成：
    1. 更新 manifest 的版本号与 changelog
    2. 构建 fpk
    3. 部署到 x86 与 arm 两台 NAS
    4. 提交并推送源码仓库
    5. 在 CompareShare 与 FnDepot 两个仓库创建 Release 并上传 fpk
    6. 更新 FnDepot 的 fnpack.json 索引与其根 README 的版本号
    7. 校验：从索引下载 fpk 并比对 sha256

依赖：Windows 凭据管理器中已保存的 GitHub 凭据（git:https://github.com）。
不写入任何凭据到磁盘。
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.abspath(__file__))
FNPACK = r"C:\Users\User\Desktop\FNOS\fnpack-test\fnpack.exe"
TRIM_CLI = r"C:\Users\User\.zcode\skills\trim-cli\scripts\trim-cli.cmd"
GIT = r"C:\Program Files\Git\cmd\git.exe"

CS_REPO = "Kasbuky-sudo/CompareShare"
FD_REPO = "Kasbuky-sudo/FnDepot"
FPK = "CompareShare.fpk"

NAS = [("x86", "192.168.31.87"), ("arm", "192.168.31.190")]

OWNER_URL = "https://github.com/Kasbuky-sudo"


# ---------------------------------------------------------------- 基础设施

def read_token() -> str:
    """从 Windows 凭据管理器读取 GitHub token（不落盘）。"""
    ps = r'''
$sig = @"
using System;
using System.Runtime.InteropServices;
public class CredRel {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern bool CredReadW(string target, int type, int flags, out IntPtr credential);
  [DllImport("advapi32.dll")]
  public static extern void CredFree(IntPtr cred);
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  public struct CREDENTIAL {
    public int Flags; public int Type; public IntPtr TargetName; public IntPtr Comment;
    public long LastWritten; public int CredentialBlobSize; public IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public IntPtr Attributes;
    public IntPtr TargetAlias; public IntPtr UserName;
  }
}
"@
Add-Type -TypeDefinition $sig
$p = [IntPtr]::Zero
if ([CredRel]::CredReadW("git:https://github.com", 1, 0, [ref]$p)) {
  $c = [System.Runtime.InteropServices.Marshal]::PtrToStructure($p, [type][CredRel+CREDENTIAL])
  [System.Runtime.InteropServices.Marshal]::PtrToStringUni($c.CredentialBlob, $c.CredentialBlobSize/2)
}
'''
    r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True, timeout=120)
    tok = (r.stdout or "").strip()
    if not tok:
        raise SystemExit("未能从凭据管理器取到 GitHub token")
    return tok


class GitHub:
    def __init__(self, token: str) -> None:
        self.h = {"User-Agent": "compare-share-release",
                  "Authorization": f"Bearer {token}",
                  "Accept": "application/vnd.github+json"}

    def api(self, method: str, path: str, payload=None, timeout: int = 300):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request("https://api.github.com" + path, data=data,
                                     method=method, headers=dict(self.h))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read()
                return r.status, (json.loads(body) if body else None)
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except Exception:
                return e.code, body[:400]

    def get_text(self, repo: str, path: str) -> tuple[str, str]:
        st, d = self.api("GET", f"/repos/{repo}/contents/{path}")
        if st != 200:
            raise SystemExit(f"读取 {repo}/{path} 失败：{st} {d}")
        return base64.b64decode(d["content"]).decode("utf-8"), d["sha"]

    def put_text(self, repo: str, path: str, text: str, sha: str, message: str) -> int:
        st, _ = self.api("PUT", f"/repos/{repo}/contents/{path}", {
            "message": message, "branch": "main", "sha": sha,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii")})
        return st

    def ensure_release(self, repo: str, tag: str, name: str, body: str):
        st, rel = self.api("GET", f"/repos/{repo}/releases/tags/{tag}")
        if st == 200:
            return rel
        st, rel = self.api("POST", f"/repos/{repo}/releases", {
            "tag_name": tag, "name": name, "body": body,
            "draft": False, "prerelease": False, "target_commitish": "main"})
        if st not in (200, 201):
            raise SystemExit(f"创建 Release 失败 {repo} {tag}：{st} {rel}")
        return rel

    def upload_asset(self, repo: str, rel: dict, path: str) -> dict:
        data = open(path, "rb").read()
        st, assets = self.api("GET", f"/repos/{repo}/releases/{rel['id']}/assets")
        if st == 200:
            for a in assets:
                if a["name"] == os.path.basename(path):
                    self.api("DELETE", f"/repos/{repo}/releases/assets/{a['id']}")
        url = rel["upload_url"].split("{")[0] + f"?name={os.path.basename(path)}"
        req = urllib.request.Request(url, data=data, method="POST", headers={
            "User-Agent": "compare-share-release",
            "Authorization": self.h["Authorization"],
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(data))})
        with urllib.request.urlopen(req, timeout=900) as r:
            return json.loads(r.read())


def run(cmd, cwd=REPO, timeout=600, check=False):
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       cwd=cwd, encoding="utf-8", errors="replace")
    if check and r.returncode != 0:
        raise SystemExit(f"命令失败：{' '.join(cmd)}\n{r.stdout}\n{r.stderr}")
    return r


# ---------------------------------------------------------------- 步骤

def step_bump(version: str, changelog: str) -> None:
    print(f"[1/8] 更新 manifest 版本号 → {version}")
    path = os.path.join(REPO, "CompareShare", "manifest")
    txt = open(path, encoding="utf-8").read()
    txt = re.sub(r"^version\s*=.*$", f"version               = {version}",
                 txt, flags=re.M)
    txt = re.sub(r"^changelog\s*=.*$", f"changelog             = {changelog}",
                 txt, flags=re.M)
    open(path, "w", encoding="utf-8", newline="\n").write(txt)


def step_build(version: str) -> tuple[bytes, str]:
    print("[2/8] 构建 fpk")
    for d in ("app/server/__pycache__", "app/server/compareshare/__pycache__"):
        shutil.rmtree(os.path.join(REPO, "CompareShare", *d.split("/")),
                      ignore_errors=True)
    r = run([FNPACK, "build", "-d", "CompareShare"], timeout=300)
    if r.returncode != 0:
        raise SystemExit(f"构建失败：{r.stdout}\n{r.stderr}")

    data = open(os.path.join(REPO, FPK), "rb").read()
    t = tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)))
    mf = t.extractfile("manifest").read().decode("utf-8")
    got = [l.split("=")[1].strip() for l in mf.splitlines()
           if l.startswith("version")][0]
    if got != version:
        raise SystemExit(f"包内版本号是 {got}，期望 {version}")
    sha = hashlib.sha256(data).hexdigest()
    print(f"      {len(data)} 字节  sha256 {sha[:16]}…")
    return data, sha


def step_deploy() -> None:
    print("[3/8] 部署到两台 NAS")
    for profile, host in NAS:
        base = [TRIM_CLI, "--profile", profile, "--host", host, "--port", "5666",
                "--scheme", "ws", "--allow-insecure-ws"]
        run(base + ["app", "uninstall", "CompareShare", "--yes"])
        time.sleep(6)
        r = run(base + ["app", "install-fpk", FPK, "--volume-id", "1", "--yes"])
        ok = "Started install task" in (r.stdout or "")
        print(f"      {profile}: {'已开始安装' if ok else '安装失败 ' + r.stdout[:80]}")


def step_git(version: str) -> None:
    print("[4/8] 提交并推送源码")
    for args in (["add", "--", "CompareShare", "README.md"],
                 ["commit", "-m", f"v{version}"],
                 ["push", "origin", "main"]):
        r = run([GIT] + args)
        print(f"      git {args[0]}: {'OK' if r.returncode == 0 else '跳过/失败'}")


def step_release(gh: GitHub, version: str, body: str) -> None:
    print("[5/8] 创建 Release 并上传 fpk")
    tag = f"CompareShare-v{version}"
    for repo in (CS_REPO, FD_REPO):
        rel = gh.ensure_release(repo, tag, f"Compare Share v{version}", body)
        a = gh.upload_asset(repo, rel, os.path.join(REPO, FPK))
        print(f"      {repo.split('/')[-1]}: {a['browser_download_url']}")


def step_index(gh: GitHub, version: str, data: bytes, sha: str,
               changelog: str) -> None:
    print("[6/8] 更新 FnDepot 索引")
    txt, fsha = gh.get_text(FD_REPO, "fnpack.json")
    doc = json.loads(txt)
    now = time.strftime("%Y-%m-%dT%H:%M:%S+08:00")
    tag = f"CompareShare-v{version}"
    doc["apps"]["CompareShare"]["releases"][version] = {
        "changelog": changelog,
        "updated_at": now,
        "packages": {"all": {
            "download_url": (f"https://github.com/{FD_REPO}/releases/download/"
                             f"{tag}/{FPK}"),
            "sha256": sha, "size": len(data), "updated_at": now}}}
    new = json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
    st = gh.put_text(FD_REPO, "fnpack.json", new, fsha,
                     f"Compare Share {version}")
    releases = list(doc["apps"]["CompareShare"]["releases"].keys())
    print(f"      fnpack.json: {st}  版本 {releases}")

    # 根 README 的版本号同步（避免手写不一致）
    txt, rsha = gh.get_text(FD_REPO, "README.md")
    new_readme = re.sub(r"(\| \[Compare Share\]\([^)]*\) \| )[^|]+(\s*\|)",
                        rf"\g<1>{version}\g<2>", txt, count=1)
    if new_readme != txt:
        st = gh.put_text(FD_REPO, "README.md", new_readme, rsha,
                         f"Compare Share 版本号 → {version}")
        print(f"      根 README 版本号: {st}")
    else:
        print("      根 README 无需改动")


# 面向用户的应用说明只需这些章节；其余（目录结构、从源码构建、实现要点）
# 属于开发者内容，不该出现在应用商店的详情页里。
USER_SECTIONS = ("功能", "安装", "浏览器上传", "目录授权", "许可", "端口", "链接")


def build_app_readme() -> str:
    """从本地 README 提取面向用户的章节，作为 FnDepot 应用说明。

    直接整篇搬运会把「目录结构」「从源码构建」等开发者内容带到应用详情页，
    因此按二级标题切分后只保留用户向章节。
    """
    src = os.path.join(REPO, "README.md")
    text = open(src, encoding="utf-8").read()

    parts = re.split(r"^(## .+)$", text, flags=re.M)
    head = parts[0].rstrip()
    body: list[str] = []

    for i in range(1, len(parts), 2):
        title = parts[i]
        content = parts[i + 1] if i + 1 < len(parts) else ""
        name = title.lstrip("#").strip()
        if any(name == s or name.startswith(s) for s in USER_SECTIONS):
            chunk = title + content.rstrip()
            if name.startswith("许可"):
                # 署名已在页面开头给出，此处只保留许可与免责说明
                chunk = title + "\n\n本项目基于 [Apache-2.0](LICENSE) 发布。\n" \
                                "本应用为独立实现，与 LocalSend 官方无隶属关系。"
            body.append(chunk)

    return head + "\n\n" + "\n\n".join(body) + "\n"


def step_app_readme(gh: GitHub) -> None:
    print("[7/8] 同步应用说明到 FnDepot")
    if not os.path.exists(os.path.join(REPO, "README.md")):
        print("      跳过（本地无 README）")
        return
    txt = build_app_readme()
    cur, sha = gh.get_text(FD_REPO, "CompareShare/README.md")
    if txt == cur:
        print("      已是最新")
        return
    st = gh.put_text(FD_REPO, "CompareShare/README.md", txt, sha,
                     "同步 Compare Share 应用说明")
    print(f"      CompareShare/README.md: {st} ({len(cur)} → {len(txt)} 字节)")


def step_verify(gh: GitHub, version: str, sha: str, size: int) -> None:
    print("[8/8] 校验：从索引下载并比对")
    txt, _ = gh.get_text(FD_REPO, "fnpack.json")
    pkg = json.loads(txt)["apps"]["CompareShare"]["releases"][version]["packages"]["all"]
    raw = urllib.request.urlopen(
        urllib.request.Request(pkg["download_url"],
                               headers={"User-Agent": "compare-share-release"}),
        timeout=300).read()
    ok_size = len(raw) == size
    ok_sha = hashlib.sha256(raw).hexdigest() == sha
    print(f"      索引 URL: {pkg['download_url']}")
    print(f"      大小一致: {ok_size}   哈希一致: {ok_sha}")
    if not (ok_size and ok_sha):
        raise SystemExit("校验未通过")


# ---------------------------------------------------------------- 入口

def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        print("示例：python release.py 1.2.1 \"修复若干问题\"")
        return 2

    version = sys.argv[1]
    changelog = sys.argv[2]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"版本号格式应为 x.y.z，收到 {version!r}")
        return 2

    print(f"=== Compare Share v{version} 发布 ===")
    print(f"说明：{changelog}")
    print()

    token = read_token()
    gh = GitHub(token)

    step_bump(version, changelog)
    data, sha = step_build(version)
    step_deploy()

    release_body = f"### Compare Share v{version}\n\n{changelog}\n"
    step_git(version)
    step_release(gh, version, release_body)
    step_index(gh, version, data, sha, changelog)
    step_app_readme(gh)
    step_verify(gh, version, sha, len(data))

    print()
    print(f"=== 发布完成 v{version} ===")
    print(f"  Release: https://github.com/{CS_REPO}/releases/tag/CompareShare-v{version}")
    print(f"  索引   : https://github.com/{FD_REPO}/blob/main/fnpack.json")
    print(f"  sha256 : {sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
