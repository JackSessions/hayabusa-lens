"""Chainsaw (WithSecure) as a second detection engine. Chainsaw is a separate program (GPL-3.0) that you install yourself;
Hayabusa Lens runs it as a subprocess, reads the JSON it writes and shows the results in the same dashboard."""
from __future__ import annotations

import glob
import os
import re
import subprocess
import tempfile

from . import install as I
from . import runner as R


def _triple() -> str | None:
    try:
        return I.chainsaw_triple()
    except I.InstallError:
        return None


def _is_chainsaw(path: str) -> bool:
    name = os.path.basename(path).lower().replace(".exe", "")
    return os.path.isfile(path) and os.access(path, os.X_OK) and re.fullmatch(r"chainsaw[-\w.+]*", name) is not None


def _pick(folder: str) -> str | None:
    """Several platform builds can sit in one folder: prefer the one for this computer."""
    t = _triple()
    hits = sorted(glob.glob(os.path.join(folder, "chainsaw*")))
    exact = [h for h in hits if t and os.path.basename(h).startswith(f"chainsaw_{t}") and _is_chainsaw(h)]
    return (exact or [h for h in hits if _is_chainsaw(h) and "_" not in os.path.basename(h)] or [None])[0]


def find_chainsaw(explicit: str | None = None) -> str | None:
    for cand in (explicit, os.environ.get("CHAINSAW_PATH")):
        if cand:
            if os.path.isdir(cand):
                for sub in (cand, os.path.join(cand, "chainsaw")):
                    hit = _pick(sub)
                    if hit:
                        return os.path.abspath(hit)
            elif os.path.isfile(cand):
                return os.path.abspath(cand)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        for exe in ("chainsaw", "chainsaw.exe"):
            p = os.path.join(d, exe)
            if d and os.path.isfile(p) and os.access(p, os.X_OK):
                return os.path.abspath(p)
    home = os.path.expanduser("~")
    for pattern in (f"{home}/.hayabusa-lens/chainsaw-*/chainsaw", f"{home}/.hayabusa-lens/chainsaw-*", f"{home}/chainsaw*/chainsaw", f"{home}/chainsaw*", f"{home}/Downloads/chainsaw*/chainsaw", f"{home}/Downloads/chainsaw*"):
        for folder in sorted(glob.glob(pattern), reverse=True):
            if os.path.isdir(folder):
                hit = _pick(folder)
                if hit:
                    return os.path.abspath(hit)
    return None


def probe(path: str) -> dict:
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=30, errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        raise R.HayabusaError(f"Could not run Chainsaw: {e}") from e
    m = re.search(r"chainsaw\s+([\d.]+)", out.stdout + out.stderr, re.I)
    base = os.path.dirname(path)
    sigma = next((d for d in (os.path.join(base, "sigma"),) if os.path.isdir(d)), "")
    rules = os.path.join(base, "rules") if os.path.isdir(os.path.join(base, "rules")) else ""
    mapping = next((m_ for m_ in (os.path.join(base, "mappings", "sigma-event-logs-all.yml"),) if os.path.isfile(m_)), "")
    return {"path": path, "version": m.group(1) if m else "unknown", "sigma": sigma, "rules": rules, "mapping": mapping, "ready": bool(sigma and mapping)}


def build_command(info: dict, target: str, out_file: str) -> list[str]:
    if not info.get("ready"):
        raise R.HayabusaError("Chainsaw needs its sigma/ and mappings/ folders next to the program. Use 'Download it for me' to get the complete package.")
    if not os.path.isabs(target) or not os.path.exists(target):
        raise R.HayabusaError(f"Path not found: {target}")
    cmd = [info["path"], "hunt", target, "-s", info["sigma"], "--mapping", info["mapping"]]
    if info.get("rules"):
        cmd += ["-r", info["rules"]]
    return cmd + ["--jsonl", "--skip-errors", "-q", "-o", out_file]


def scan(info: dict, target: str, log: list[str]) -> str:
    fd, out = tempfile.mkstemp(prefix="hayabusa-lens-", suffix=".jsonl")
    os.close(fd)
    os.unlink(out)
    code = R.run(build_command(info, target, out), os.path.dirname(info["path"]), log)
    if not os.path.exists(out):
        if code == 0:
            with open(out, "w") as f:                     # clean run with no detections
                f.write("")
            return out
        raise R.HayabusaError("Chainsaw produced no results (" + (" | ".join(log[-3:]) or f"exit code {code}") + ")")
    return out
