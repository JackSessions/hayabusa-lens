"""Finding and running the Hayabusa program. Hayabusa is a separate program (AGPL-3.0) that you install yourself;
Hayabusa Lens only calls it as a subprocess and reads the file it writes."""
from __future__ import annotations

import glob
import os
import re
import subprocess
import tempfile
import threading

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
EXE = "hayabusa.exe" if os.name == "nt" else "hayabusa"


class HayabusaError(Exception):
    pass


def _is_binary(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK) and re.fullmatch(r"hayabusa[-\w.]*", os.path.basename(path).replace(".exe", ""), re.I) is not None


def find_hayabusa(explicit: str | None = None) -> str | None:
    """--hayabusa PATH, $HAYABUSA_PATH, the PATH, then the usual download folders."""
    for cand in (explicit, os.environ.get("HAYABUSA_PATH")):
        if cand:
            if os.path.isdir(cand):
                hits = sorted(glob.glob(os.path.join(cand, "hayabusa*")))
                cand = next((h for h in hits if _is_binary(h)), None) or ""
            if cand and os.path.isfile(cand):
                return os.path.abspath(cand)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        p = os.path.join(d, EXE)
        if d and os.path.isfile(p) and os.access(p, os.X_OK):
            return os.path.abspath(p)
    home = os.path.expanduser("~")
    for pattern in (f"{home}/.hayabusa-lens/*/hayabusa*", f"{home}/hayabusa*/hayabusa*", f"{home}/Downloads/hayabusa*/hayabusa*", f"{home}/Tools/hayabusa*/hayabusa*", "/opt/hayabusa*/hayabusa*", os.path.join(os.getcwd(), "hayabusa*", "hayabusa*"), os.path.join(os.getcwd(), "hayabusa*")):
        for p in sorted(glob.glob(pattern), reverse=True):
            if _is_binary(p):
                return os.path.abspath(p)
    return None


def probe(path: str) -> dict:
    """Run `hayabusa help` and work out which command style this version uses."""
    try:
        out = subprocess.run([path, "help"], cwd=os.path.dirname(path), capture_output=True, text=True, timeout=30, errors="replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        raise HayabusaError(f"Could not run Hayabusa: {e}") from e
    text = ANSI.sub("", out.stdout + out.stderr)
    m = re.search(r"Hayabusa v([\d.]+)(?: - ([^\n]+))?", text)
    style = "dfir" if "dfir-timeline" in text else "legacy" if "json-timeline" in text else None
    return {"path": path, "version": m.group(1) if m else "unknown", "release": (m.group(2) if m else "") or "", "style": style,
            "rules": os.path.isdir(os.path.join(os.path.dirname(path), "rules"))}


def build_command(info: dict, target: str, out_file: str, min_level: str = "informational", noisy: bool = False) -> list[str]:
    if info["style"] is None:
        raise HayabusaError("This Hayabusa version has no timeline command Hayabusa Lens understands. Try Hayabusa 2.x or newer.")
    if not os.path.isabs(target) or not os.path.exists(target):
        raise HayabusaError(f"Path not found: {target}")
    flag = "-d" if os.path.isdir(target) else "-f"
    cmd = [info["path"]]
    if info["style"] == "dfir":
        cmd += ["dfir-timeline", flag, target, "-t", "jsonl"]
    else:
        cmd += ["json-timeline", flag, target, "-L"]
    cmd += ["-o", out_file, "-w", "-q", "-N", "-C", "-K", "-p", "verbose", "-O"]
    if min_level in ("low", "medium", "high", "critical"):
        cmd += ["-m", min_level]
    if noisy:
        cmd += ["-n"]
    return cmd


def run(cmd: list[str], cwd: str, log: list[str], cancel: threading.Event | None = None) -> int:
    """Run Hayabusa, keeping the last few readable lines of its output in `log`."""
    proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace", bufsize=1)
    buf = ""
    assert proc.stdout is not None
    while True:
        ch = proc.stdout.read(1)
        if not ch:
            break
        if ch in "\r\n":
            line = ANSI.sub("", buf).strip()
            if line:
                log.append(line)
                del log[:-12]
            buf = ""
        else:
            buf += ch
        if cancel is not None and cancel.is_set():
            proc.kill()
            break
    return proc.wait()


def scan(info: dict, target: str, min_level: str, noisy: bool, log: list[str]) -> str:
    """Run a scan and return the path of the JSONL file (the caller deletes it)."""
    fd, out = tempfile.mkstemp(prefix="hayabusa-lens-", suffix=".jsonl")
    os.close(fd)
    os.unlink(out)                       # Hayabusa creates it; -C lets it overwrite, but start clean
    code = run(build_command(info, target, out, min_level, noisy), os.path.dirname(info["path"]), log)
    if not os.path.exists(out):
        tail = " | ".join(log[-3:]) or f"exit code {code}"
        raise HayabusaError(f"Hayabusa produced no results ({tail})")
    return out


def update_rules(info: dict, log: list[str]) -> int:
    return run([info["path"], "update-rules"], os.path.dirname(info["path"]), log)
