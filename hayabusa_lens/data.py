"""Loading, normalising and querying Hayabusa timelines (JSONL, JSON or CSV)."""
from __future__ import annotations

import csv
import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone

LEVEL_NAMES = ["informational", "low", "medium", "high", "critical"]
LEVEL_ALIASES = {"info": 0, "informational": 0, "low": 1, "med": 2, "medium": 2, "high": 3, "crit": 4, "critical": 4}
TACTICS = {
    "Recon": "Reconnaissance", "ResDev": "Resource Development", "InitAccess": "Initial Access", "Exec": "Execution", "Persis": "Persistence",
    "PrivEsc": "Privilege Escalation", "Stealth": "Stealth", "Evas": "Defense Evasion", "CredAccess": "Credential Access", "Disc": "Discovery",
    "LatMov": "Lateral Movement", "Collect": "Collection", "C2": "Command and Control", "Exfil": "Exfiltration", "Impact": "Impact",
}
_TS = re.compile(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(\.\d+)?\s*(Z|[+-]\d\d:?\d\d)?$")


class LoadError(Exception):
    pass


def norm_level(value) -> int:
    return LEVEL_ALIASES.get(str(value).strip().lower(), 0)


def parse_ts(text) -> float | None:
    """Milliseconds since the epoch (UTC), or None when the text is not a recognisable timestamp."""
    m = _TS.match(str(text or "").strip())
    if not m:
        return None
    date, clock, frac, zone = m.groups()
    tz = timezone.utc
    if zone and zone != "Z":
        sign = 1 if zone[0] == "+" else -1
        digits = zone[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    dt = datetime.strptime(f"{date} {clock}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=tz)
    return dt.timestamp() * 1000 + (float("0" + frac) * 1000 if frac else 0)


def iso(ms: float) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _as_list(v) -> list[str]:
    if v is None or v == "":
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x)]
    return [p.strip() for p in re.split(r"\s*[¦|]\s*", str(v)) if p.strip()]


def _flat(v) -> str:
    if isinstance(v, dict):
        return " ¦ ".join(f"{k}: {x}" for k, x in v.items())
    return "" if v is None else str(v)


def _val(x):
    if isinstance(x, dict):
        return x.get("#text", "")
    return x


def chainsaw_dict(c: dict) -> dict:
    """Chainsaw's JSON detection -> the shape Hayabusa Lens works with."""
    docs = c.get("documents")
    doc = c.get("document") or (docs[0] if docs else {}) or {}
    data = doc.get("data") or {}
    ev = data.get("Event", data) if isinstance(data, dict) else {}
    sysd = ev.get("System", {}) if isinstance(ev, dict) else {}
    payload = ev.get("EventData") or ev.get("UserData") or {} if isinstance(ev, dict) else {}
    if isinstance(payload, dict):
        payload = {k: v for k, v in payload.items() if not str(k).endswith("_attributes")}
        if len(payload) == 1 and isinstance(next(iter(payload.values())), dict):
            payload = {k: v for k, v in next(iter(payload.values())).items()}
    ts = c.get("timestamp") or ((sysd.get("TimeCreated_attributes") or {}).get("SystemTime"))
    other = [x for x in (c.get("group"), c.get("status")) if x]
    extra = {"Authors": ", ".join(c.get("authors") or []), "Detected by": "Chainsaw"}
    if docs:
        extra["Matching events"] = len(docs)
    return {"Timestamp": ts, "RuleTitle": c.get("name"), "Level": c.get("level"), "Computer": sysd.get("Computer"), "Channel": sysd.get("Channel"),
            "EventID": _val(sysd.get("EventID")), "RecordID": _val(sysd.get("EventRecordID")), "MitreTactics": [], "MitreTags": [], "OtherTags": other,
            "Details": payload, "ExtraFieldInfo": extra, "RuleFile": "", "RuleID": "", "EvtxFile": doc.get("path", "")}


def make_row(i: int, d: dict) -> dict | None:
    if "document" in d or "documents" in d:
        d = chainsaw_dict(d)
    ts = parse_ts(d.get("Timestamp") or d.get("timestamp"))
    if ts is None:
        return None
    tags = _as_list(d.get("MitreTags"))
    row = {
        "i": i, "ts": ts, "title": str(d.get("RuleTitle") or "(no title)"), "lvl": norm_level(d.get("Level")), "comp": str(d.get("Computer") or ""),
        "chan": str(d.get("Channel") or ""), "eid": str(d.get("EventID") or ""), "rid": str(d.get("RecordID") or ""),
        "tactics": [TACTICS.get(t, t) for t in _as_list(d.get("MitreTactics"))], "tags": tags, "other": _as_list(d.get("OtherTags")),
        "rulefile": str(d.get("RuleFile") or ""), "ruleid": str(d.get("RuleID") or ""), "evtx": str(d.get("EvtxFile") or ""),
        "details": d.get("Details"), "extra": d.get("ExtraFieldInfo"),
    }
    row["dtext"] = _flat(row["details"])
    row["blob"] = " ".join([row["title"], row["comp"], row["chan"], row["eid"], row["dtext"], _flat(row["extra"]), " ".join(row["tags"]), " ".join(row["tactics"])]).lower()
    return row


class Dataset:
    def __init__(self, rows: list[dict], source: str = "", skipped: int = 0):
        self.rows = sorted(rows, key=lambda r: r["ts"])
        for n, r in enumerate(self.rows):
            r["i"] = n
        self.source, self.skipped = source, skipped
        self._cache: dict = {}

    # ---- loading
    @classmethod
    def from_dicts(cls, dicts, source: str = "") -> "Dataset":
        rows, skipped = [], 0
        for n, d in enumerate(dicts):
            r = make_row(n, d) if isinstance(d, dict) else None
            if r:
                rows.append(r)
            else:
                skipped += 1
        return cls(rows, source, skipped)

    @classmethod
    def load(cls, path: str) -> "Dataset":
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                head = fh.read(1)
                fh.seek(0)
                if head == "[":
                    return cls.from_dicts(json.load(fh), path)
                if head == "{":
                    return cls.from_dicts((json.loads(line) for line in fh if line.strip()), path)
                return cls.from_dicts(csv.DictReader(fh), path)
        except (json.JSONDecodeError, csv.Error) as e:
            raise LoadError(f"Could not read this as Hayabusa output (JSON, JSONL or CSV): {e}") from e
        except UnicodeError as e:
            raise LoadError(f"Could not read this file as text: {e}") from e

    # ---- querying
    def _match(self, r: dict, f: dict, skip: tuple = ()) -> bool:
        if "levels" not in skip and f.get("levels") is not None and r["lvl"] not in f["levels"]:
            return False
        if "time" not in skip:
            if f.get("frm") is not None and r["ts"] < f["frm"]:
                return False
            if f.get("to") is not None and r["ts"] > f["to"]:
                return False
        if "q" not in skip and f.get("q") and not all(w in r["blob"] for w in f["q"].lower().split()):
            return False
        if "computer" not in skip and f.get("computer") and r["comp"] != f["computer"]:
            return False
        if "rule" not in skip and f.get("rule") and r["title"] != f["rule"]:
            return False
        if "tactic" not in skip and f.get("tactic") and f["tactic"] not in r["tactics"]:
            return False
        if "tag" not in skip and f.get("tag") and f["tag"] not in r["tags"]:
            return False
        if "eid" not in skip and f.get("eid") and r["eid"] != f["eid"]:
            return False
        if "chan" not in skip and f.get("chan") and r["chan"] != f["chan"]:
            return False
        return True

    def select(self, f: dict, skip: tuple = ()) -> list[dict]:
        return [r for r in self.rows if self._match(r, f, skip)]

    def facets(self, f: dict, top: int = 12) -> dict:
        rows = self.select(f, skip=("computer", "rule", "tactic", "tag", "eid", "chan"))
        rules = Counter((r["title"], r["lvl"]) for r in rows)
        def top_of(counter: Counter, n=top):
            return [{"name": k, "count": v} for k, v in counter.most_common(n)]
        return {
            "rules": [{"name": t, "lvl": l, "count": c} for (t, l), c in rules.most_common(top)],
            "computers": top_of(Counter(r["comp"] for r in rows)),
            "tactics": top_of(Counter(t for r in rows for t in r["tactics"])),
            "tags": top_of(Counter(t for r in rows for t in r["tags"])),
            "eids": top_of(Counter(r["eid"] for r in rows)),
            "channels": top_of(Counter(r["chan"] for r in rows)),
        }

    def counts(self, f: dict) -> list[int]:
        out = [0] * 5
        for r in self.select(f, skip=("levels",)):
            out[r["lvl"]] += 1
        return out

    def timeline(self, f: dict, buckets: int = 96) -> dict:
        rows = self.select(f, skip=("time",))
        if not rows:
            return {"start": 0, "step": 1, "buckets": []}
        lo, hi = rows[0]["ts"], rows[-1]["ts"]
        step = max(1000.0, (hi - lo) / buckets + 1)
        n = int((hi - lo) // step) + 1
        data = [[0] * 5 for _ in range(n)]
        for r in rows:
            data[int((r["ts"] - lo) // step)][r["lvl"]] += 1
        return {"start": lo, "step": step, "buckets": data}

    def summary(self) -> dict:
        lv = Counter(r["lvl"] for r in self.rows)
        return {"total": len(self.rows), "skipped": self.skipped, "levels": [lv.get(i, 0) for i in range(5)], "source": self.source,
                "first": iso(self.rows[0]["ts"]) if self.rows else "", "last": iso(self.rows[-1]["ts"]) if self.rows else "",
                "computers": len({r["comp"] for r in self.rows}), "files": len({r["evtx"] for r in self.rows if r["evtx"]})}


def compact(r: dict) -> dict:
    """The row as the table shows it."""
    return {"i": r["i"], "t": iso(r["ts"]), "lvl": r["lvl"], "title": r["title"], "comp": r["comp"], "chan": r["chan"], "eid": r["eid"], "d": r["dtext"][:200], "tactics": r["tactics"]}


def full(r: dict) -> dict:
    keep = ("i", "title", "comp", "chan", "eid", "rid", "tactics", "tags", "other", "rulefile", "ruleid", "evtx", "details", "extra")
    out = {k: r[k] for k in keep}
    out.update(t=iso(r["ts"]), level=LEVEL_NAMES[r["lvl"]])
    return out


def mitre_url(tag: str) -> str | None:
    m = re.fullmatch(r"[Tt](\d{4})(?:\.(\d{3}))?", tag.replace("attack.", ""))
    if not m:
        return None
    return f"https://attack.mitre.org/techniques/T{m.group(1)}/" + (f"{m.group(2)}/" if m.group(2) else "")
