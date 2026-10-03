"""Hayabusa's summary commands (logon summary, event ID / computer / log-file metrics), shown as tables in the interface."""
from __future__ import annotations

import csv
import os
import re
import tempfile

from . import runner as R

MAX_ROWS = 5000

TOOLS = {
    "logon-summary": {"label": "Logon summary", "desc": "Successful and failed logons by account, logon type and source (events 4624 / 4625).", "files": [("successful", "Successful logons"), ("failed", "Failed logons")], "prefix": True},
    "eid-metrics": {"label": "Event ID metrics", "desc": "How many events of each ID and channel the logs contain: a quick map of what happened.", "files": [("", "Event IDs")], "prefix": False},
    "computer-metrics": {"label": "Computer metrics", "desc": "Which computers appear in the logs and how many events each produced.", "files": [("", "Computers")], "prefix": False},
    "log-metrics": {"label": "Log file metrics", "desc": "For each .evtx file: computers, event counts, first and last timestamps, channels and size.", "files": [("", "Log files")], "prefix": False},
}


def available(help_text: str) -> list[str]:
    found = [t for t in TOOLS if t in help_text]
    if re.search(r"^\s+search\s", help_text, re.M):
        found.append("search")
    return found


def build_command(info: dict, tool: str, target: str, out: str) -> list[str]:
    if tool not in TOOLS:
        raise R.HayabusaError(f"Unknown tool: {tool}")
    if tool not in info.get("tools", []):
        raise R.HayabusaError(f"This Hayabusa version does not have '{tool}'. Update Hayabusa and try again.")
    if not os.path.isabs(target) or not os.path.exists(target):
        raise R.HayabusaError(f"Path not found: {target}")
    return [info["path"], tool, "-d" if os.path.isdir(target) else "-f", target, "-o", out, "-C", "-K", "-q"]


def read_csv(path: str) -> dict:
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        rows = list(csv.reader(fh))
    if not rows:
        return {"header": [], "rows": [], "total": 0}
    return {"header": rows[0], "rows": rows[1:MAX_ROWS + 1], "total": len(rows) - 1}


def run_tool(info: dict, tool: str, target: str, log: list[str]) -> list[dict]:
    spec = TOOLS[tool]
    tmp = tempfile.mkdtemp(prefix="hayabusa-lens-")
    base = os.path.join(tmp, "out")
    try:
        cmd = build_command(info, tool, target, base if spec["prefix"] else base + ".csv")
        code = R.run(cmd, os.path.dirname(info["path"]), log)
        tables = []
        for suffix, title in spec["files"]:
            p = f"{base}-{suffix}.csv" if spec["prefix"] else base + ".csv"
            if os.path.exists(p):
                t = read_csv(p)
                t["title"] = title
                tables.append(t)
        if not tables:
            raise R.HayabusaError("Hayabusa produced no output (" + (" | ".join(log[-2:]) or f"exit code {code}") + ")")
        return tables
    finally:
        for f in os.listdir(tmp):
            os.unlink(os.path.join(tmp, f))
        os.rmdir(tmp)


def search_command(info: dict, target: str, out: str, keywords: list[str], regex: str = "", and_logic: bool = False, ignore_case: bool = True) -> list[str]:
    """`hayabusa search`: finds ANY event (not only detections) by keyword(s) or a regular expression."""
    if "search" not in info.get("tools", []):
        raise R.HayabusaError("This Hayabusa version has no 'search' command. Update Hayabusa and try again.")
    if not os.path.isabs(target) or not os.path.exists(target):
        raise R.HayabusaError(f"Path not found: {target}")
    keywords = [k.strip() for k in keywords if k.strip()][:20]
    if not keywords and not regex.strip():
        raise R.HayabusaError("Type at least one keyword (or a regular expression) to search for.")
    cmd = [info["path"], "search", "-d" if os.path.isdir(target) else "-f", target]
    if regex.strip():
        rx = regex.strip()[:300]
        cmd += ["-r", rx if (not ignore_case or rx.startswith("(?i)")) else "(?i)" + rx]     # -r cannot be combined with -i
    else:
        for k in keywords:
            cmd += ["-k", k[:200]]
        if and_logic and len(keywords) > 1:
            cmd += ["-a"]
    if ignore_case and not regex.strip():
        cmd += ["-i"]
    return cmd + ["-o", out, "-C", "-K", "-q"]


def run_search(info: dict, target: str, keywords: list[str], regex: str, and_logic: bool, ignore_case: bool, log: list[str]) -> list[dict]:
    tmp = tempfile.mkdtemp(prefix="hayabusa-lens-")
    out = os.path.join(tmp, "search.csv")
    try:
        code = R.run(search_command(info, target, out, keywords, regex, and_logic, ignore_case), os.path.dirname(info["path"]), log)
        if not os.path.exists(out):
            if code == 0:
                return [{"title": "Matching events", "header": ["Result"], "rows": [["No events matched."]], "total": 0}]
            raise R.HayabusaError("Hayabusa search failed (" + (" | ".join(log[-2:]) or f"exit code {code}") + ")")
        t = read_csv(out)
        if t["total"] == 0:
            return [{"title": "Matching events", "header": ["Result"], "rows": [["No events matched."]], "total": 0}]
        t["title"] = "Matching events"
        return [t]
    finally:
        for f in os.listdir(tmp):
            os.unlink(os.path.join(tmp, f))
        os.rmdir(tmp)
