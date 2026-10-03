"""Share findings with other tools. Off by default; nothing is sent unless the user presses the button and confirms.

Hayabusa Lens is not a SIEM and keeps no database. This module only turns what is on screen into formats that free SIEMs
and log pipelines already read, and can push them to a destination the user types in:

  file     newline-delimited JSON (ECS-style) that Wazuh, Elastic Agent, Filebeat, Vector or Promtail can tail
  syslog   RFC 5424 over UDP or TCP, carrying CEF (ArcSight/most SIEMs) or the JSON event (Wazuh, Graylog, Security Onion)
  elastic  POST to {url}/_bulk (Elasticsearch, OpenSearch)
  splunk   POST to the HTTP Event Collector
  webhook  POST the JSON events to any URL

Credentials are used for the one request and never stored or logged."""
from __future__ import annotations

import calendar
import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from . import netmap as NM

LEVELS = ["informational", "low", "medium", "high", "critical"]
SEVERITY = [5, 25, 47, 73, 99]                 # ECS event.severity, 0-100
CEF_SEV = [1, 3, 5, 8, 10]
MAX_EVENTS = 100_000
BATCH = 500
SHARE_DIR = os.path.join(os.path.expanduser("~"), ".hayabusa-lens", "share")


class ShareError(Exception):
    pass


def _iso(ms: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ms / 1000)) + f".{int(ms % 1000):03d}Z"


# ---------- event shapes ----------

def ecs_event(r: dict) -> dict:
    ent = NM.entities(r)
    tags = list(r.get("tags") or [])
    ev = {
        "@timestamp": _iso(r["ts"]),
        "event": {"kind": "alert", "category": ["intrusion_detection"], "severity": SEVERITY[r["lvl"]], "code": str(r.get("eid", "")), "dataset": "hayabusa-lens.alert",
                  "module": "hayabusa-lens", "provider": r.get("chan", "")},
        "message": f"{r['title']} on {r.get('comp', '')}".strip(),
        "rule": {"name": r["title"], "id": r.get("ruleid", ""), "ruleset": r.get("rulefile", "")},
        "host": {"name": ent["hosts"][0] if ent["hosts"] else r.get("comp", "")},
        "labels": {"level": LEVELS[r["lvl"]]},
        "hayabusa_lens": {"version": __version__, "details": r.get("details") or {}, "extra": r.get("extra") or {}, "source_log": r.get("evtx", "")},
    }
    if ent["users"]:
        ev["user"] = {"name": ent["users"][0]}
    if ent["ips"]:
        ev["source"] = {"ip": ent["ips"][0]}
        ev["related"] = {"ip": ent["ips"], "user": ent["users"], "hosts": ent["hosts"]}
    elif ent["users"] or len(ent["hosts"]) > 1:
        ev["related"] = {"user": ent["users"], "hosts": ent["hosts"]}
    if tags or r.get("tactics"):
        ev["threat"] = {"framework": "MITRE ATT&CK", "technique": {"id": [t for t in tags]}, "tactic": {"name": list(r.get("tactics") or [])}}
    return ev


def audit_events(analysis: dict) -> list[dict]:
    """The AI audit trail as events: one per question put to the model."""
    out = []
    for e in analysis.get("audit", []):
        out.append({"@timestamp": _iso(e["t"] * 1000), "event": {"kind": "event", "category": ["process"], "action": "ai_investigation_step", "severity": SEVERITY[0], "dataset": "hayabusa-lens.ai_audit", "module": "hayabusa-lens", "duration": e["ms"] * 1_000_000},
                    "message": f"AI step {e['n']}: {e['question']} -> {e.get('action') or 'no action'} {e.get('args', '')}".strip(), "rule": {"name": "AI investigation audit trail", "id": "hl-ai-audit"},
                    "labels": {"level": LEVELS[0], "ai": e.get("ai", "")},
                    "hayabusa_lens": {"version": __version__, "step": e["n"], "kind": e["kind"], "tool": e.get("action", ""), "args": e.get("args", ""), "answer_excerpt": e.get("answer", "")[:500], "result_excerpt": e.get("result", "")[:500], "source_log": analysis.get("label", "")}})
    return out


def _cef_esc(v, header: bool) -> str:
    v = str(v).replace("\\", "\\\\")
    v = v.replace("|", "\\|") if header else v.replace("=", "\\=")
    return v.replace("\r", " ").replace("\n", " ")


def cef(ev: dict) -> str:
    """ArcSight Common Event Format, understood by nearly every SIEM."""
    lvl = LEVELS.index(ev["labels"]["level"])
    ext = {"rt": int(calendar.timegm(time.strptime(ev["@timestamp"][:19], "%Y-%m-%dT%H:%M:%S")) * 1000),
           "dhost": ev.get("host", {}).get("name", ""), "msg": ev["message"], "cs1Label": "level", "cs1": ev["labels"]["level"], "cs2Label": "ruleFile", "cs2": ev["rule"].get("ruleset", "")}
    if ev.get("source", {}).get("ip"):
        ext["src"] = ev["source"]["ip"]
    if ev.get("user", {}).get("name"):
        ext["suser"] = ev["user"]["name"]
    if ev.get("threat"):
        ext["cs3Label"] = "attack"
        ext["cs3"] = ",".join(ev["threat"]["technique"]["id"])
    head = "|".join(_cef_esc(x, True) for x in ("CEF:0", "Jack Sessions", "Hayabusa Lens", __version__, ev["rule"].get("id") or ev["rule"]["name"], ev["rule"]["name"], CEF_SEV[lvl]))
    return head + "|" + " ".join(f"{k}={_cef_esc(v, False)}" for k, v in ext.items() if v not in ("", 0))


def select(rows: list[dict], min_level: int) -> list[dict]:
    chosen = [r for r in rows if r["lvl"] >= min_level]
    if len(chosen) > MAX_EVENTS:
        raise ShareError(f"{len(chosen):,} events is more than the {MAX_EVENTS:,} limit. Raise the minimum level first.")
    return sorted(chosen, key=lambda r: r["ts"])


# ---------- destinations ----------

def check_url(url: str) -> urllib.parse.ParseResult:
    u = urllib.parse.urlparse(url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ShareError("The address must start with http:// or https://")
    try:
        ip = ipaddress.ip_address(u.hostname)
    except ValueError:
        ip = None
    if ip and ip.is_link_local:
        raise ShareError("That address is not allowed (link-local).")
    private = u.hostname in ("localhost",) or (ip is not None and (ip.is_private or ip.is_loopback))
    if u.scheme == "http" and not private:
        raise ShareError("Refusing to send over plain http to a public address. Use https://, or a server on your own network.")
    return u


def write_file(events: list[dict], path: str = "") -> str:
    path = os.path.abspath(os.path.expanduser(path)) if path else os.path.join(SHARE_DIR, "alerts.ndjson")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    return path


def send_syslog(events: list[dict], host: str, port: int = 514, proto: str = "udp", fmt: str = "cef") -> int:
    if proto not in ("udp", "tcp") or not 0 < port < 65536 or not host.strip():
        raise ShareError("Give a host, a port (1-65535) and udp or tcp.")
    me = socket.gethostname().split(".")[0] or "-"
    lines = []
    for e in events:
        body = cef(e) if fmt == "cef" else json.dumps(e, ensure_ascii=False)
        pri = 8 * 4 + (3 if e["event"]["severity"] >= 73 else 4 if e["event"]["severity"] >= 47 else 6)       # facility auth(4), severity error/warning/info
        lines.append(f"<{pri}>1 {e['@timestamp']} {me} hayabusa-lens - - - {body}")
    try:
        if proto == "udp":
            with socket.socket(socket.AF_INET if ":" not in host else socket.AF_INET6, socket.SOCK_DGRAM) as s:
                for ln in lines:
                    s.sendto(ln.encode("utf-8")[:8000], (host, port))
        else:
            with socket.create_connection((host, port), timeout=10) as s:
                s.sendall(("\n".join(lines) + "\n").encode("utf-8"))
    except OSError as e:
        raise ShareError(f"Could not reach {host}:{port} ({e.strerror or type(e).__name__}).") from None
    return len(lines)


def post(events: list[dict], kind: str, url: str, auth: str = "", index: str = "hayabusa-lens", opener=urllib.request.urlopen) -> int:
    """kind: elastic | splunk | webhook. `auth` is the full Authorization header value, e.g. 'ApiKey abc', 'Basic abc', 'Splunk <token>'."""
    u = check_url(url)
    base = url.strip().rstrip("/")
    sent = 0
    for i in range(0, len(events), BATCH):
        chunk = events[i:i + BATCH]
        if kind == "elastic":
            target = base if base.endswith("/_bulk") else base + "/_bulk"
            body = "".join(json.dumps({"create": {"_index": index}}) + "\n" + json.dumps(e, ensure_ascii=False) + "\n" for e in chunk)
            ctype = "application/x-ndjson"
        elif kind == "splunk":
            target = base if "/services/collector" in base else base + "/services/collector/event"
            body = "".join(json.dumps({"time": time.time(), "sourcetype": "hayabusa-lens", "host": e.get("host", {}).get("name", ""), "event": e}, ensure_ascii=False) for e in chunk)
            ctype = "application/json"
        elif kind == "webhook":
            target, body, ctype = base, json.dumps(chunk, ensure_ascii=False), "application/json"
        else:
            raise ShareError("Unknown destination type.")
        headers = {"Content-Type": ctype, "User-Agent": "hayabusa-lens"}
        if auth.strip():
            headers["Authorization"] = auth.strip()
        try:
            with opener(urllib.request.Request(target, data=body.encode("utf-8"), headers=headers, method="POST"), timeout=30) as r:
                resp = r.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            hint = {401: "credentials rejected", 403: "not allowed", 404: "wrong path or index"}.get(e.code, "the server refused it")
            raise ShareError(f"HTTP {e.code}: {hint}.") from None
        except (urllib.error.URLError, OSError) as e:
            raise ShareError(f"Could not reach {u.hostname} ({type(e).__name__}).") from None
        if kind == "elastic":
            try:
                if json.loads(resp).get("errors"):
                    raise ShareError("Elasticsearch accepted the request but rejected some events. Check the index name and permissions.")
            except ValueError:
                pass
        sent += len(chunk)
    return sent
