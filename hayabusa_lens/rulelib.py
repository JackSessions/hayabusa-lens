"""The rule library: a folder (~/.hayabusa-lens/rules) that is always populated, online or offline.

  online   fetches the newest SigmaHQ release through the GitHub API (core / core+ / core++ / all / emerging threats)
  offline  reuses the last downloaded copy from the cache, else falls back to the small STARTER set shipped with Hayabusa Lens
  auto     tries online, then offline

Sigma rules belong to the SigmaHQ community (Detection Rule License 1.1). The starter rules are original, simplified examples."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
import urllib.request
import zipfile

from . import install as I
from . import rulesidx as RI

HOME = os.path.join(os.path.expanduser("~"), ".hayabusa-lens")
LIB = os.path.join(HOME, "rules")
CACHE = os.path.join(HOME, "rules-cache")
API = "https://api.github.com/repos/SigmaHQ/sigma/releases/latest"
SETS = {"core": "sigma_core.zip", "core+": "sigma_core+.zip", "core++": "sigma_core++.zip", "all": "sigma_all_rules.zip", "emerging": "sigma_emerging_threats_addon.zip"}
SET_HELP = {"core": "highest-quality rules, smallest (about 1.4 MB)", "core+": "core plus more coverage (about 2.5 MB)", "core++": "broadest curated set (about 2.7 MB)", "all": "every rule (about 3.2 MB)", "emerging": "emerging threats add-on (about 0.4 MB)"}


class RuleLibError(Exception):
    pass


def starter_dir() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "starter")


def ensure_starter(lib: str | None = None) -> int:
    """Copy the bundled starter rules into the library (idempotent). Returns how many rule files are there."""
    lib = lib or LIB
    dest = os.path.join(lib, "starter")
    os.makedirs(dest, exist_ok=True)
    n = 0
    src = starter_dir()
    if os.path.isdir(src):
        for f in sorted(os.listdir(src)):
            if f.endswith(".yml"):
                t = os.path.join(dest, f)
                if not os.path.exists(t):
                    shutil.copy(os.path.join(src, f), t)
                n += 1
    return n


def manifest(lib: str | None = None) -> dict:
    try:
        with open(os.path.join(lib or LIB, "manifest.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _write_manifest(lib: str, data: dict) -> None:
    os.makedirs(lib, exist_ok=True)
    with open(os.path.join(lib, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1)


def status(lib: str | None = None) -> dict:
    lib = lib or LIB
    ensure_starter(lib)
    ix = RI.RuleIndex([lib])
    m = manifest(lib)
    return {"dir": lib, "count": len(ix.entries), "source": m.get("source", "starter set (offline)"), "set": m.get("set", ""), "tag": m.get("tag", ""), "updated": m.get("updated", ""),
            "cached": sorted(os.listdir(CACHE)) if os.path.isdir(CACHE) else [], "sets": SET_HELP}


def _extract(zpath: str, lib: str, label: str) -> str:
    dest = os.path.join(lib, label)
    tmp = dest + ".new"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp)
    try:
        with zipfile.ZipFile(zpath) as zf:
            I.safe_extract(zf, tmp)
    except zipfile.BadZipFile as e:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuleLibError("The rules archive was not a valid zip file.") from e
    for old in os.listdir(lib):                       # replace earlier downloads, keep starter/ and the manifest
        if old.startswith("sigma-") and os.path.join(lib, old) != tmp:
            shutil.rmtree(os.path.join(lib, old), ignore_errors=True)
    os.replace(tmp, dest)
    return dest


def update_online(rule_set: str = "core", lib: str | None = None, cache: str | None = None, progress=None, api_url: str = API, opener=urllib.request.urlopen) -> dict:
    lib, cache = lib or LIB, cache or CACHE
    if rule_set not in SETS:
        raise RuleLibError(f"Unknown rule set '{rule_set}'. Choose one of: {', '.join(SETS)}.")
    say = progress or (lambda *a: None)
    headers = {"User-Agent": "hayabusa-lens", "Accept": "application/vnd.github+json"}
    say(0, 0, "asking GitHub for the newest SigmaHQ release")
    try:
        with opener(urllib.request.Request(api_url, headers=headers), timeout=30) as r:
            release = json.load(r)
    except Exception as e:
        raise RuleLibError(f"Could not reach GitHub ({e}).") from e
    asset = next((a for a in release.get("assets", []) if a["name"] == SETS[rule_set]), None)
    if not asset:
        raise RuleLibError(f"The newest SigmaHQ release has no '{rule_set}' archive.")
    tag = release.get("tag_name", "latest")
    os.makedirs(cache, exist_ok=True)
    zpath = os.path.join(cache, f"{rule_set}-{tag}.zip")
    fd, tmp = tempfile.mkstemp(suffix=".zip", dir=cache)
    os.close(fd)
    try:
        sha, done, total = hashlib.sha256(), 0, int(asset.get("size") or 0)
        say(0, total, f"downloading {asset['name']}")
        with opener(urllib.request.Request(asset["browser_download_url"], headers=headers), timeout=60) as r, open(tmp, "wb") as out:
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
            raise RuleLibError("The download does not match the checksum GitHub published for it. Not using it.")
        os.replace(tmp, zpath)
    except OSError as e:
        raise RuleLibError(f"Could not download the rules: {e}") from e
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    for old in os.listdir(cache):                      # keep only the newest cached archive per set
        if old.startswith(rule_set + "-") and old != os.path.basename(zpath):
            os.unlink(os.path.join(cache, old))
    say(done, total, "unpacking")
    _extract(zpath, lib, f"sigma-{tag}-{rule_set}")
    m = {"source": f"SigmaHQ {tag} ({rule_set})", "set": rule_set, "tag": tag, "updated": time.strftime("%Y-%m-%d %H:%M"), "mode": "online"}
    _write_manifest(lib, m)
    ensure_starter(lib)
    return m


def use_offline(rule_set: str = "core", lib: str | None = None, cache: str | None = None) -> dict:
    """Populate from the cache if a previous download exists, else make sure the starter rules are in place."""
    lib, cache = lib or LIB, cache or CACHE
    n = ensure_starter(lib)
    if os.path.isdir(cache):
        zips = sorted(f for f in os.listdir(cache) if f.endswith(".zip") and (f.startswith(rule_set + "-") or not any(g.startswith(rule_set + "-") for g in os.listdir(cache))))
        if zips:
            z = zips[-1]
            label = "sigma-" + z[:-4].split("-", 1)[1] + "-" + z.split("-", 1)[0]
            _extract(os.path.join(cache, z), lib, label)
            m = {"source": f"cached SigmaHQ download ({z[:-4]})", "set": z.split("-", 1)[0], "tag": z[:-4].split("-", 1)[1], "updated": time.strftime("%Y-%m-%d %H:%M"), "mode": "offline-cache"}
            _write_manifest(lib, m)
            return m
    m = {"source": f"starter set ({n} example rules, offline)", "set": "starter", "tag": "", "updated": time.strftime("%Y-%m-%d %H:%M"), "mode": "offline-starter"}
    _write_manifest(lib, m)
    return m


def update(rule_set: str = "core", mode: str = "auto", progress=None, **kw) -> dict:
    """mode: 'online' (fail if offline), 'offline', or 'auto' (online, then cache, then starter)."""
    if mode == "offline":
        return use_offline(rule_set, kw.get("lib"), kw.get("cache"))
    try:
        return update_online(rule_set, progress=progress, **kw)
    except RuleLibError as e:
        if mode == "online":
            raise
        m = use_offline(rule_set, kw.get("lib"), kw.get("cache"))
        m["note"] = f"Offline ({e}). Using: {m['source']}."
        return m
