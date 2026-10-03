"""Turn alerts into a map of the computers, accounts and addresses involved.

Nodes   host (the computer that logged the event), user (account named in the event), ip (address named in the event)
Edges   two things that appear in the same alert. A user connected to several hosts, or one address touching several
        hosts, is how lateral movement and scanning show up.
Only what the events actually say is drawn: this is a map of evidence, not a scan of the network."""
from __future__ import annotations

import ipaddress
import re

IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IP6 = re.compile(r"(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}(?![0-9a-f:])", re.I)
USER_KEYS = re.compile(r"(?:^|[a-z])(?:user|username|acct|account|accountname|logonuser)$|^(?:tgt|src|target|subject)(?:user|acct|account)(?:name)?$", re.I)
HOST_KEYS = re.compile(r"workstation|src ?comp|source ?host|srchost|target ?comp|dest ?host|remote ?host", re.I)
NOT_IP_KEYS = re.compile(r"version|product|company|description|hash|guid|signature|copyright|original|ver$", re.I)    # 2.5.0.0 in FileVersion is not an address
SKIP_USERS = {"", "-", "n/a", "none", "null", "anonymous logon", "system", "local service", "network service", "window manager", "font driver host"}
MAX_NODES = 160
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def _ip_kind(s: str) -> str | None:
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local:
        return None
    if a.version == 4 and a.packed[1:] == b"\xff\xff\xff":                        # x.255.255.255 broadcast
        return None
    if a.version == 4 and any(a in n for n in DOC_NETS):        # documentation ranges stand in for "the internet" in demo data
        return "external"
    return "external" if a.is_global else "internal"


def _user(v: str) -> str | None:
    u = v.strip().split("\\")[-1].split("@")[0].strip()
    if re.fullmatch(r"0x[0-9a-f]+|S-1-[\d-]+|\d+|[0-9a-f]{8}-[0-9a-f-]{27}", u, re.I):          # logon IDs, SIDs, GUIDs are not accounts
        return None
    if u.lower() in SKIP_USERS or len(u) > 40 or u.endswith("$") or u.startswith("DWM-") or u.startswith("UMFD-") or " " in u and len(u) > 24:
        return None
    return u


def _short(h: str) -> str:
    """PC01.example.corp and PC01 are the same computer."""
    return h if IP.fullmatch(h) or ":" in h else h.split(".")[0].upper()


def entities(r: dict) -> dict:
    """The accounts, computers and addresses one alert names (used for sharing events with useful fields)."""
    users, hosts, ips = [], [], []
    comp = (r.get("comp") or "").strip()
    if comp and comp != "-":
        hosts.append(_short(comp))
    for k, v in {**(r.get("details") or {}), **(r.get("extra") or {})}.items():
        if not isinstance(v, (str, int, float)):
            continue
        sv = str(v)
        if USER_KEYS.search(k) and _user(sv):
            users.append(_user(sv))
        if HOST_KEYS.search(k) and sv.strip() not in ("", "-") and not IP.fullmatch(sv.strip()):
            hosts.append(_short(sv.strip()))
        ips += [m for m in ([] if NOT_IP_KEYS.search(k) else IP.findall(sv) + IP6.findall(sv)) if _ip_kind(m)]
    uniq = lambda xs: list(dict.fromkeys(xs))
    return {"users": uniq(users), "hosts": uniq(hosts), "ips": uniq(ips)}


def build(rows: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def node(kind: str, name: str, row: dict, sub: str = "") -> str:
        nid = f"{kind}:{name.lower()}"
        n = nodes.get(nid)
        if n is None:
            n = nodes[nid] = {"id": nid, "type": kind, "name": name, "sub": sub, "alerts": 0, "max": 0, "levels": [0] * 5, "titles": {}, "tactics": {}, "first": row["ts"], "last": row["ts"]}
        n["alerts"] += 1
        n["max"] = max(n["max"], row["lvl"])
        n["levels"][row["lvl"]] += 1
        n["titles"][row["title"]] = n["titles"].get(row["title"], 0) + 1
        for t in row.get("tactics") or []:
            n["tactics"][t] = n["tactics"].get(t, 0) + 1
        n["first"], n["last"] = min(n["first"], row["ts"]), max(n["last"], row["ts"])
        return nid

    for r in rows:
        members = []
        comp = (r.get("comp") or "").strip()
        if comp and comp != "-":
            members.append(node("host", _short(comp), r))
        fields = {**(r.get("details") or {}), **(r.get("extra") or {})}
        for k, v in fields.items():
            if not isinstance(v, (str, int, float)):
                continue
            sv = str(v)
            if USER_KEYS.search(k):
                u = _user(sv)
                if u:
                    members.append(node("user", u, r))
            if HOST_KEYS.search(k) and sv.strip() not in ("", "-") and not IP.fullmatch(sv.strip()):
                members.append(node("host", _short(sv.strip()), r))
            for m in ([] if NOT_IP_KEYS.search(k) else IP.findall(sv) + IP6.findall(sv)):
                kind = _ip_kind(m)
                if kind:
                    members.append(node("ip", m, r, kind))
        members = list(dict.fromkeys(members))
        for i, a in enumerate(members):
            for b in members[i + 1:]:
                key = tuple(sorted((a, b)))
                e = edges.setdefault(key, {"a": key[0], "b": key[1], "w": 0, "max": 0})
                e["w"] += 1
                e["max"] = max(e["max"], r["lvl"])
    keep = sorted(nodes.values(), key=lambda n: (-n["max"], -n["alerts"]))[:MAX_NODES]
    ids = {n["id"] for n in keep}
    es = [e for e in edges.values() if e["a"] in ids and e["b"] in ids]
    deg: dict[str, int] = {}
    for e in es:
        deg[e["a"]] = deg.get(e["a"], 0) + 1
        deg[e["b"]] = deg.get(e["b"], 0) + 1
    for n in keep:
        n["titles"] = sorted(n["titles"].items(), key=lambda t: -t[1])[:8]
        n["tactics"] = sorted(n["tactics"].items(), key=lambda t: -t[1])[:6]
        n["degree"] = deg.get(n["id"], 0)
    # leads worth a look
    leads = []
    hosts_of: dict[str, set] = {}
    for e in es:
        for x, y in ((e["a"], e["b"]), (e["b"], e["a"])):
            if x.split(":")[0] in ("user", "ip") and y.startswith("host:"):
                hosts_of.setdefault(x, set()).add(y)
    byid = {n["id"]: n for n in keep}
    for x, hs in sorted(hosts_of.items(), key=lambda kv: -len(kv[1])):
        if len(hs) >= 2:
            n = byid[x]
            leads.append({"node": x, "text": f"{'Account' if n['type'] == 'user' else 'Address'} {n['name']} appears in alerts on {len(hs)} computers"
                          + (" (external address)" if n.get("sub") == "external" else "") + ": possible lateral movement or scanning."})
        if len(leads) >= 6:
            break
    return {"nodes": keep, "edges": es, "leads": leads, "total_nodes": len(nodes), "truncated": len(nodes) > MAX_NODES}
