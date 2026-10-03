"""Compare two loaded scans: what is new, what is gone, what stayed."""
from __future__ import annotations

from collections import Counter

from . import data as D


def key(r: dict, mode: str = "rule") -> tuple:
    """mode 'rule': the same rule firing on the same event. mode 'event': the same event flagged by anything (useful across engines)."""
    base = (r["comp"].lower(), r["eid"], r["rid"], int(r["ts"] // 1000))
    return base if mode == "event" else (r["title"],) + base


def _by_key(rows: list[dict], mode: str) -> dict:
    out: dict = {}
    for r in rows:
        k = key(r, mode)
        if k not in out or r["lvl"] > out[k]["lvl"]:
            out[k] = r                       # keep the most severe detection for an event
    return out


def compare(a: D.Dataset, b: D.Dataset, mode: str = "rule") -> dict:
    ka, kb = _by_key(a.rows, mode), _by_key(b.rows, mode)
    new = [kb[k] for k in kb if k not in ka]
    gone = [ka[k] for k in ka if k not in kb]
    same = sum(1 for k in kb if k in ka)

    def by_level(rows):
        c = Counter(r["lvl"] for r in rows)
        return [c.get(i, 0) for i in range(5)]

    def top(rows, field, n=12):
        return [{"name": k, "count": v} for k, v in Counter(r[field] for r in rows).most_common(n)]
    rules_a, rules_b = {r["title"] for r in a.rows}, {r["title"] for r in b.rows}
    return {
        "mode": mode, "a": a.summary(), "b": b.summary(),
        "counts": {"new": len(new), "gone": len(gone), "same": same},
        "new_levels": by_level(new), "gone_levels": by_level(gone),
        "new_rules": top(new, "title"), "gone_rules": top(gone, "title"),
        "new_computers": top(new, "comp"), "gone_computers": top(gone, "comp"),
        "rules_only_in_b": sorted(rules_b - rules_a)[:30], "rules_only_in_a": sorted(rules_a - rules_b)[:30],
        "_new": new, "_gone": gone,
    }
