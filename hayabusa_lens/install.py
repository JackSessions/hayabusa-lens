"""Download the official Hayabusa release for this computer from GitHub (only when you ask). Nothing is bundled."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import tempfile
import urllib.request
import zipfile

API = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
HOME = os.path.join(os.path.expanduser("~"), ".hayabusa-lens")


class InstallError(Exception):
    pass


def platform_key(system: str | None = None, machine: str | None = None) -> str:
    """e.g. 'lin-x64', 'win-x64', 'mac-aarch64'."""
    s = (system or platform.system()).lower()
    m = (machine or platform.machine()).lower()
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "aarch64", "arm64": "aarch64", "i386": "x86", "i686": "x86", "x86": "x86"}.get(m)
    osn = {"linux": "lin", "darwin": "mac", "windows": "win"}.get(s)
    if not arch or not osn:
        raise InstallError(f"No official Hayabusa download for {s} / {m}. Download it by hand from https://github.com/Yamato-Security/hayabusa/releases")
    return f"{osn}-{arch}"


def pick_asset(assets: list[dict], key: str) -> dict:
    names = [a for a in assets if a["name"].endswith(".zip") and "live-response" not in a["name"] and "all-platforms" not in a["name"] and f"-{key}" in a["name"]]
    if not names:
        raise InstallError(f"This Hayabusa release has no download for {key}.")
    names.sort(key=lambda a: ("musl" not in a["name"], a["name"]))     # prefer the statically linked Linux build
    return names[0]


def safe_extract(zf: zipfile.ZipFile, dest: str) -> None:
    root = os.path.realpath(dest)
    for info in zf.infolist():
        target = os.path.realpath(os.path.join(dest, info.filename))
        if target != root and not target.startswith(root + os.sep):
            raise InstallError(f"Refusing to unpack an unsafe path from the archive: {info.filename}")
    zf.extractall(dest)


def install(dest_root: str | None = None, progress=None, api_url: str = API, opener=urllib.request.urlopen, system: str | None = None, machine: str | None = None) -> str:
    """Returns the path of the installed hayabusa program. progress(done_bytes, total_bytes, message) is optional."""
    say = progress or (lambda *a: None)
    headers = {"User-Agent": "hayabusa-lens", "Accept": "application/vnd.github+json"}
    say(0, 0, "looking up the latest Hayabusa release")
    try:
        with opener(urllib.request.Request(api_url, headers=headers), timeout=30) as r:
            release = json.load(r)
    except Exception as e:
        raise InstallError(f"Could not reach GitHub ({e}). Check your internet connection.") from e
    asset = pick_asset(release.get("assets", []), platform_key(system, machine))
    tag = release.get("tag_name", "latest")
    dest = os.path.join(dest_root or HOME, f"hayabusa-{tag.lstrip('v')}")
    os.makedirs(dest, exist_ok=True)
    fd, zpath = tempfile.mkstemp(suffix=".zip")
    os.close(fd)
    try:
        sha = hashlib.sha256()
        total = int(asset.get("size") or 0)
        done = 0
        say(0, total, f"downloading {asset['name']}")
        with opener(urllib.request.Request(asset["browser_download_url"], headers=headers), timeout=60) as r, open(zpath, "wb") as out:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
                sha.update(chunk)
                done += len(chunk)
                say(done, total, f"downloading {asset['name']}")
        expected = str(asset.get("digest") or "")
        if expected.startswith("sha256:") and expected[7:].lower() != sha.hexdigest():
            raise InstallError("The download does not match the checksum GitHub published for it. Not installing it.")
        say(done, total, "unpacking")
        with zipfile.ZipFile(zpath) as zf:
            safe_extract(zf, dest)
    except zipfile.BadZipFile as e:
        raise InstallError("The downloaded file was not a valid zip archive.") from e
    except OSError as e:
        raise InstallError(f"Could not download or unpack Hayabusa: {e}") from e
    finally:
        if os.path.exists(zpath):
            os.unlink(zpath)
    for dirpath, _, files in os.walk(dest):
        for f in files:
            base = f.lower().replace(".exe", "")
            if base.startswith("hayabusa") and not f.lower().endswith((".zip", ".md", ".txt", ".yml", ".yaml")) and os.path.dirname(os.path.join(dirpath, f)) == dest:
                p = os.path.join(dirpath, f)
                os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                say(done, total, "done")
                return p
    raise InstallError("Unpacked the archive but could not find the hayabusa program inside it.")
