"""Local web server for Hayabusa Lens. Standard library only; listens on 127.0.0.1 with a one-time token."""
from __future__ import annotations

import csv
import html
import io
import json
import os
import secrets
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __author__, __url__, __version__
from . import data as D
from . import install as I
from . import runner as R
from .page import PAGE

MAX_BODY = 8192
JOBS: dict[str, dict] = {}
LOCK = threading.Lock()
STATE = {"hayabusa": None}          # explicit --hayabusa path, set by the CLI


def hayabusa_info() -> dict:
    path = R.find_hayabusa(STATE["hayabusa"])
    if not path:
        return {"found": False}
    try:
        return {"found": True, **R.probe(path)}
    except R.HayabusaError as e:
        return {"found": False, "path": path, "error": str(e)}


def _new_job() -> tuple[str, dict]:
    jid = secrets.token_hex(6)
    job = {"state": "running", "phase": "starting", "log": [], "t0": time.time()}
    with LOCK:
        JOBS[jid] = job
        for old in list(JOBS)[:-8]:                 # keep memory bounded: only recent results stay loaded
            JOBS.pop(old, None)
    return jid, job


def _run_scan(job: dict, target: str, min_level: str, noisy: bool) -> None:
    out = None
    try:
        info = hayabusa_info()
        if not info.get("found"):
            raise R.HayabusaError("Hayabusa was not found. Install it, then start Hayabusa Lens with --hayabusa /path/to/hayabusa.")
        job["phase"] = f"Hayabusa {info['version']} is scanning"
        out = R.scan(info, target, min_level, noisy, job["log"])
        job["phase"] = "reading results"
        job["dataset"] = D.Dataset.load(out)
        job["dataset"].source = target
        job["state"] = "done"
    except (R.HayabusaError, D.LoadError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {e}")
    finally:
        if out and os.path.exists(out):
            os.unlink(out)


def _run_open(job: dict, path: str) -> None:
    try:
        job["phase"] = "reading results"
        job["dataset"] = D.Dataset.load(path)
        job["state"] = "done"
    except FileNotFoundError:
        job.update(state="error", error=f"File not found: {path}")
    except (D.LoadError, OSError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {e}")


def parse_filters(q: dict) -> dict:
    def one(k): return (q.get(k) or [""])[0]
    def num(k):
        try:
            return float(one(k)) if one(k) != "" else None
        except ValueError:
            return None
    lv = one("levels")
    levels = {int(x) for x in lv.split(",") if x.strip().isdigit() and 0 <= int(x) <= 4} if lv != "" else None
    return {"levels": levels, "q": one("q").strip()[:200], "computer": one("computer"), "rule": one("rule"), "tactic": one("tactic"), "tag": one("tag"),
            "eid": one("eid"), "chan": one("chan"), "frm": num("frm"), "to": num("to")}


def export_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["Timestamp(UTC)", "Level", "RuleTitle", "Computer", "Channel", "EventID", "RecordID", "MitreTactics", "MitreTags", "Details", "RuleFile", "EvtxFile"])
    for r in rows:
        w.writerow([D.iso(r["ts"]), D.LEVEL_NAMES[r["lvl"]], r["title"], r["comp"], r["chan"], r["eid"], r["rid"], " ¦ ".join(r["tactics"]), " ¦ ".join(r["tags"]), r["dtext"], r["rulefile"], r["evtx"]])
    return buf.getvalue()


def export_html(ds: D.Dataset, rows: list[dict], f: dict) -> str:
    e = html.escape
    colours = ["#6b7f8c", "#38d6ff", "#ffb02e", "#ff7a2e", "#ff2d6f"]
    cnt = [0] * 5
    for r in rows:
        cnt[r["lvl"]] += 1
    tiles = "".join(f'<div class="t" style="--c:{colours[i]}"><b>{cnt[i]}</b><span>{D.LEVEL_NAMES[i]}</span></div>' for i in (4, 3, 2, 1, 0))
    body = "".join(
        f'<tr><td>{D.iso(r["ts"])}</td><td><span class="c" style="--c:{colours[r["lvl"]]}">{D.LEVEL_NAMES[r["lvl"]]}</span></td><td>{e(r["title"])}</td><td>{e(r["comp"])}</td><td>{e(r["eid"])}</td><td class="d">{e(r["dtext"][:240])}</td></tr>'
        for r in rows[:1000])
    more = f"<p class='m'>Showing the first 1000 of {len(rows)} events. Export CSV for all of them.</p>" if len(rows) > 1000 else ""
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Hayabusa Lens report</title><style>
:root{{color-scheme:dark}}body{{margin:0;background:#07090c;color:#d7e3ea;font:14px/1.5 system-ui,sans-serif}}main{{max-width:72rem;margin:0 auto;padding:2rem 1rem}}
h1{{font:800 1.6rem ui-monospace,monospace;background:linear-gradient(90deg,#ff5f6d,#ffb02e,#ffe14a,#4af0a2,#38d6ff,#e04aff);-webkit-background-clip:text;background-clip:text;color:transparent;display:inline-block;margin:0}}
.m{{color:#7fa7b5;font:12px ui-monospace,monospace}}.tiles{{display:flex;gap:.6rem;margin:1rem 0}}.t{{flex:1;border:1px solid var(--c);border-radius:8px;padding:.5rem;text-align:center}}.t b{{display:block;font-size:1.5rem;color:var(--c)}}.t span{{color:#7fa7b5;font-size:.75rem;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:.4rem;border-bottom:1px solid #1c252d;vertical-align:top}}th{{font:11px ui-monospace,monospace;color:#7fa7b5;text-transform:uppercase}}.c{{border:1px solid var(--c);color:var(--c);border-radius:999px;padding:0 .5rem;font:11px ui-monospace,monospace;text-transform:uppercase}}.d{{color:#9fb6bf;font:12px ui-monospace,monospace;word-break:break-all}}
</style><main><h1>Hayabusa Lens</h1><div class="m">v{__version__} | source: {e(ds.source or "demo")} | {len(rows)} events{' (filtered)' if any(v not in (None, '') for k, v in f.items() if k != 'levels') or f.get('levels') is not None else ''}</div>
<div class="tiles">{tiles}</div><table><tr><th>Time (UTC)</th><th>Level</th><th>Rule</th><th>Computer</th><th>EID</th><th>Details</th></tr>{body}</table>{more}
<p class="m">Created by <a style="color:#38d6ff" href="{__url__}">Jack Sessions</a> | unofficial front end for <a style="color:#38d6ff" href="https://github.com/Yamato-Security/hayabusa">Hayabusa</a> by Yamato Security | MIT licence</p></main></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "HayabusaLens"
    token = ""

    def log_message(self, *a) -> None:
        pass

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "").rsplit(":", 1)[0] in ("127.0.0.1", "localhost")

    def _token_ok(self, q: dict) -> bool:
        given = self.headers.get("X-HL-Token") or (q.get("token") or [""])[0]
        return secrets.compare_digest(given.encode(), self.token.encode())

    def _send(self, code: int, body: bytes, ctype: str = "application/json", extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; img-src 'self' data:")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _guard(self, q: dict) -> bool:
        if not self._host_ok():
            self._json(403, {"error": "bad host header"})
            return False
        if not self._token_ok(q):
            self._json(403, {"error": "missing or wrong token"})
            return False
        return True

    def _dataset(self, q: dict):
        job = JOBS.get((q.get("job") or [""])[0])
        if not job or job.get("state") != "done":
            self._json(404, {"error": "no finished scan"})
            return None
        return job["dataset"]

    def do_GET(self) -> None:
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        if not self._guard(q):
            return
        p = u.path
        if p == "/":
            self._send(200, PAGE.replace("__VERSION__", __version__).replace("__URL__", __url__).encode(), "text/html; charset=utf-8")
        elif p == "/api/hayabusa":
            self._json(200, hayabusa_info())
        elif p == "/api/status":
            job = JOBS.get((q.get("job") or [""])[0])
            if not job:
                return self._json(404, {"error": "unknown job"})
            out = {"state": job["state"], "progress": job.get("progress", 0), "phase": job.get("phase", ""), "log": job["log"][-6:], "error": job.get("error", ""), "elapsed": round(time.time() - job["t0"], 1)}
            if job["state"] == "done":
                out["summary"] = job["dataset"].summary()
            self._json(200, out)
        elif p == "/api/query":
            self._query(q)
        elif p == "/api/event":
            ds = self._dataset(q)
            if ds:
                try:
                    r = ds.rows[int((q.get("i") or ["-1"])[0])]
                except (ValueError, IndexError):
                    return self._json(404, {"error": "no such event"})
                ev = D.full(r)
                ev["links"] = {t: D.mitre_url(t) for t in r["tags"] if D.mitre_url(t)}
                self._json(200, ev)
        elif p == "/api/export":
            self._export(q)
        elif p == "/api/ls":
            self._ls((q.get("path") or [""])[0])
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        u = urllib.parse.urlparse(self.path)
        if not self._guard(urllib.parse.parse_qs(u.query)):
            return
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY or u.path not in ("/api/scan", "/api/open", "/api/demo", "/api/update-rules", "/api/install"):
            return self._json(404, {"error": "bad request"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._json(400, {"error": "bad JSON"})
        jid, job = _new_job()
        if u.path == "/api/demo":
            job["dataset"] = D.Dataset.from_dicts(D.demo_dicts(), "DEMO DATA (fictional)")
            job["state"] = "done"
        elif u.path == "/api/install":
            def inst():
                def prog(done, total, msg):
                    job["phase"] = msg.capitalize() + (f" ({done / 1048576:.0f} of {total / 1048576:.0f} MB)" if total and msg.startswith("down") else "")
                    job["progress"] = round(done / total, 3) if total else 0
                try:
                    path = I.install(progress=prog)
                    job.update(state="done", phase="installed: " + path)
                    job["dataset"] = D.Dataset([], "installed")
                except I.InstallError as e:
                    job.update(state="error", error=str(e))
                except Exception as e:
                    job.update(state="error", error=f"Unexpected error: {e}")
            threading.Thread(target=inst, daemon=True).start()
        elif u.path == "/api/update-rules":
            def upd():
                info = hayabusa_info()
                if not info.get("found"):
                    return job.update(state="error", error="Hayabusa was not found.")
                job["phase"] = "updating rules (needs internet)"
                code = R.update_rules(info, job["log"])
                job.update(state="error" if code else "done", error="update-rules failed: " + " | ".join(job["log"][-2:]) if code else "")
                job["dataset"] = D.Dataset([], "rules updated")
            threading.Thread(target=upd, daemon=True).start()
        else:
            path = str(body.get("path", "")).strip().strip('"')
            if not path:
                return self._json(400, {"error": "choose a file or folder first"})
            path = os.path.abspath(os.path.expanduser(path))
            if u.path == "/api/open":
                threading.Thread(target=_run_open, args=(job, path), daemon=True).start()
            else:
                lvl = str(body.get("minLevel", "informational"))
                threading.Thread(target=_run_scan, args=(job, path, lvl, bool(body.get("noisy"))), daemon=True).start()
        self._json(200, {"job": jid})

    def _query(self, q: dict) -> None:
        ds = self._dataset(q)
        if not ds:
            return
        f = parse_filters(q)
        rows = ds.select(f)
        sort = (q.get("sort") or ["time"])[0]
        rows = sorted(rows, key=lambda r: (-r["lvl"], r["ts"])) if sort == "level" else (rows[::-1] if sort == "-time" else rows)
        try:
            off, lim = max(0, int((q.get("offset") or ["0"])[0])), min(500, max(1, int((q.get("limit") or ["100"])[0])))
        except ValueError:
            off, lim = 0, 100
        self._json(200, {"total": len(rows), "rows": [D.compact(r) for r in rows[off:off + lim]], "facets": ds.facets(f), "counts": ds.counts(f), "timeline": ds.timeline(f), "summary": ds.summary()})

    def _export(self, q: dict) -> None:
        ds = self._dataset(q)
        if not ds:
            return
        f = parse_filters(q)
        rows = ds.select(f)
        fmt = (q.get("fmt") or ["csv"])[0]
        stamp = time.strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, ctype, name = json.dumps([D.full(r) for r in rows], ensure_ascii=False, indent=1).encode(), "application/json", f"hayabusa-lens-{stamp}.json"
        elif fmt == "html":
            body, ctype, name = export_html(ds, rows, f).encode(), "text/html; charset=utf-8", f"hayabusa-lens-{stamp}.html"
        else:
            body, ctype, name = export_csv(rows).encode(), "text/csv; charset=utf-8", f"hayabusa-lens-{stamp}.csv"
        self._send(200, body, ctype, {"Content-Disposition": f'attachment; filename="{name}"'})

    def _ls(self, path: str) -> None:
        path = os.path.abspath(os.path.expanduser(path or "~"))
        try:
            entries = []
            with os.scandir(path) as it:
                for e in it:
                    try:
                        d = e.is_dir()
                        entries.append({"name": e.name, "dir": d, "size": 0 if d else e.stat().st_size})
                    except OSError:
                        continue
            entries.sort(key=lambda x: (not x["dir"], x["name"].lower()))
            self._json(200, {"path": path, "parent": os.path.dirname(path), "entries": entries[:2000], "sep": os.sep})
        except OSError as e:
            self._json(200, {"path": path, "parent": os.path.dirname(path), "entries": [], "error": str(e.strerror or e), "sep": os.sep})


def make_server(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    token = secrets.token_urlsafe(18)
    return ThreadingHTTPServer(("127.0.0.1", port), type("Bound", (Handler,), {"token": token})), token


def serve(port: int = 0, open_browser: bool = True, path: str | None = None, demo: bool = False) -> int:
    httpd, token = make_server(port)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?token={token}"
    if demo:
        url += "&demo=1"
    elif path:
        url += "&path=" + urllib.parse.quote(os.path.abspath(path))
    print(f"Hayabusa Lens {__version__} by {__author__}\n  {url}\nListening on this computer only. Press Ctrl+C to stop.", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
    return 0
