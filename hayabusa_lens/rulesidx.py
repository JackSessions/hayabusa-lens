"""An index of the Sigma / Hayabusa rule files on this computer, for the rule viewer. Reads files only; never writes."""
from __future__ import annotations

import os
import re
import threading

MAX_FILES = 40000
MAX_BYTES = 300_000
TAC = {"initial_access": "Initial Access", "execution": "Execution", "persistence": "Persistence", "privilege_escalation": "Privilege Escalation", "defense_evasion": "Defense Evasion",
       "stealth": "Stealth", "credential_access": "Credential Access", "discovery": "Discovery", "lateral_movement": "Lateral Movement", "collection": "Collection",
       "command_and_control": "Command and Control", "exfiltration": "Exfiltration", "impact": "Impact", "reconnaissance": "Reconnaissance", "resource_development": "Resource Development"}


def parse_meta(text: str) -> dict:
    def top(key):
        m = re.search(rf"^{key}:\s*(.+?)\s*$", text, re.M)
        return m.group(1).strip("'\"") if m else ""
    tags = []
    m = re.search(r"^tags:\s*\n((?:\s+-\s*.+\n?)+)", text, re.M)
    if m:
        tags = [t.strip().strip("'\"") for t in re.findall(r"-\s*(.+)", m.group(1))]
    return {"title": top("title"), "id": top("id"), "level": top("level"), "status": top("status"), "tags": tags}


def mitre_from_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    tech, tac = [], []
    for t in tags:
        t = t.lower().replace("attack.", "")
        if re.fullmatch(r"t\d{4}(\.\d{3})?", t):
            tech.append(t.upper())
        elif t in TAC:
            tac.append(TAC[t])
    return tech, tac


class RuleIndex:
    def __init__(self, dirs: list[str]):
        self.dirs = [d for d in dirs if d and os.path.isdir(d)]
        self.entries: dict[str, dict] = {}
        self.by_id: dict[str, str] = {}
        self.by_title: dict[str, str] = {}
        self.by_file: dict[str, list[str]] = {}
        n = 0
        for root in self.dirs:
            for dirpath, _, files in os.walk(root):
                for f in files:
                    if not f.lower().endswith((".yml", ".yaml")) or n >= MAX_FILES:
                        continue
                    p = os.path.join(dirpath, f)
                    try:
                        if os.path.getsize(p) > MAX_BYTES:
                            continue
                        with open(p, "r", encoding="utf-8", errors="replace") as fh:
                            text = fh.read()
                    except OSError:
                        continue
                    meta = parse_meta(text)
                    if not meta["title"]:
                        continue
                    n += 1
                    meta["path"], meta["file"] = p, f
                    meta["blob"] = (meta["title"] + " " + meta["id"] + " " + f + " " + " ".join(meta["tags"])).lower()
                    self.entries[p] = meta
                    if meta["id"]:
                        self.by_id.setdefault(meta["id"].lower(), p)
                    self.by_title.setdefault(meta["title"].lower(), p)
                    self.by_file.setdefault(f.lower(), []).append(p)

    def find(self, rule_id: str = "", rule_file: str = "", title: str = "") -> dict | None:
        p = (self.by_id.get(rule_id.lower()) if rule_id else None) or (self.by_file.get(rule_file.lower(), [None])[0] if rule_file else None) or (self.by_title.get(title.lower()) if title else None)
        return self.entries.get(p) if p else None

    def search(self, q: str, limit: int = 60) -> list[dict]:
        words = q.lower().split()
        hits = [e for e in self.entries.values() if all(w in e["blob"] for w in words)] if words else list(self.entries.values())
        hits.sort(key=lambda e: (e["title"].lower().find(words[0]) if words and words[0] in e["title"].lower() else 999, e["title"].lower()))
        out = [{k: e[k] for k in ("path", "title", "id", "level", "tags", "file", "status")} for e in hits[:limit]]
        for o in out:
            o["folder"] = os.path.basename(os.path.dirname(o["path"]))
        return out

    def read(self, path: str) -> str | None:
        if path not in self.entries:                 # only files we indexed are ever served
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()


_CACHE: dict[tuple, RuleIndex] = {}
_LOCK = threading.Lock()


def get_index(dirs: list[str]) -> RuleIndex:
    key = tuple(sorted(d for d in dirs if d))
    with _LOCK:
        if key not in _CACHE:
            _CACHE.clear()
            _CACHE[key] = RuleIndex(list(key))
        return _CACHE[key]


def invalidate() -> None:
    with _LOCK:
        _CACHE.clear()
