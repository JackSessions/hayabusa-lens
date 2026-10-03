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
from . import chainsaw as CS
from . import attackchain as AC
from . import compare as CP
from . import investigate as INV
from . import install as I
from . import llm as LLM
from . import netmap as NM
from . import rulelib as RL
from . import rulesidx as RI
from . import runner as R
from . import samples as SM
from . import share as SH
from . import tools as TL
from . import vectorchain as VC
from .page import PAGE

MAX_BODY = 8192
MAX_UPLOAD = 40 << 20                  # a pasted or dropped agent trace
JOBS: dict[str, dict] = {}
LOCK = threading.Lock()
STATE = {"hayabusa": None, "chainsaw": None}          # explicit --hayabusa / --chainsaw paths, set by the CLI
TRACES: dict = {}
COMPARES: dict = {}


def hayabusa_info() -> dict:
    path = R.find_hayabusa(STATE["hayabusa"])
    if not path:
        return {"found": False}
    try:
        return {"found": True, **R.probe(path)}
    except R.HayabusaError as e:
        return {"found": False, "path": path, "error": str(e)}


def chainsaw_info() -> dict:
    path = CS.find_chainsaw(STATE["chainsaw"])
    if not path:
        return {"found": False}
    try:
        return {"found": True, **CS.probe(path)}
    except R.HayabusaError as e:
        return {"found": False, "path": path, "error": str(e)}


def rule_index() -> RI.RuleIndex:
    dirs = []
    hb, cs = hayabusa_info(), chainsaw_info()
    if hb.get("found"):
        dirs.append(os.path.join(os.path.dirname(hb["path"]), "rules"))
    if cs.get("found"):
        dirs += [cs.get("sigma", ""), cs.get("rules", "")]
    RL.ensure_starter()                                  # the library is never empty, even offline
    dirs.append(RL.LIB)
    return RI.get_index(dirs)


def resolve_ai(spec, kind: str = "chat") -> dict:
    """Turn what the page sent into a ready provider choice, enforcing consent for anything online."""
    spec = spec if isinstance(spec, dict) else {}
    prov, model = str(spec.get("provider", "")), str(spec.get("model", "")).strip()
    if prov in ("", "none"):
        raise LLM.LLMError("Choose an AI helper first.")
    if prov == "auto":
        rec = LLM.status()["recommend"]["explain"]
        if not rec:
            raise LLM.LLMError("No AI helper is set up yet. Install Ollama, log in to Claude Code, or add an API key in the AI box.")
        prov, model = rec["provider"], model or rec["model"]
    base = str(spec.get("base", ""))
    if prov == "ollama" and not model:
        loc = LLM.status()["local"]
        names = loc["chat_models"] if kind == "chat" else loc["embed_models"]
        model = names[0] if names else ""
    if prov not in LLM.PROVIDERS and prov != "claude-code":
        raise LLM.LLMError("Unknown AI helper.")
    if spec.get("consent") is not True and not LLM.is_local(prov, base) and prov != "ollama":
        raise LLM.LLMError("Tick the box to confirm the text may be sent to that online service, or choose a local model.")
    return {"provider": prov, "key": str(spec.get("key", "")), "base": base, "model": model}


def _run_investigate(job: dict, src: dict, body: dict) -> None:
    try:
        c = resolve_ai(body.get("ai"))
        ds = src["dataset"]
        steps_n = min(12, max(3, int(body.get("steps") or INV.DEFAULT_STEPS)))

        def ask(prompt: str) -> str:
            return LLM.chat(c["provider"], prompt, c["key"], c["base"], c["model"], max_tokens=700)

        def progress(turn: int, total: int, msg: str) -> None:
            job["phase"] = f"Step {turn} of {total}: {msg}"
            job["progress"] = round(turn / total, 3)
            job["log"].append(f"{turn}. {msg}")

        job["phase"] = "Starting the investigation"
        job["audit"] = []
        ai_label = c["provider"] + (" · " + c["model"] if c["model"] else "")

        def on_audit(e: dict) -> None:
            e["ai"] = ai_label

        res = INV.investigate(ds.rows, ask, str(body.get("focus", "")), steps_n, progress, job["audit"], on_audit)
        for e in job["audit"]:
            e.setdefault("ai", ai_label)
        emb = body.get("embed") if isinstance(body.get("embed"), dict) else {}
        if str(emb.get("provider", "local")) == "local":
            vecs, mode = None, "local"
        else:
            e = resolve_ai(emb, "embed")
            job["phase"] = "Placing the steps in 3D"
            vecs, mode = VC.from_dense(LLM.embed(e["provider"], [s["text"] for s in res["steps"]], e["key"], e["base"], e["model"])), f"{e['provider']} vectors"
        an = VC.analyze(res["steps"], vecs, mode)
        an["audit"] = job["audit"]
        tid = secrets.token_hex(6)
        if len(TRACES) > 8:
            TRACES.pop(next(iter(TRACES)))
        TRACES[tid] = an
        label = "AI investigation of " + str(src.get("label") or ds.source or "results")
        job["agent"] = dict(an, id=tid, label=label, report=res["report"], investigated=True, ai=ai_label, truncated=False)
        an["label"], an["report"], an["ai"] = label, res["report"], ai_label
        job["state"] = "done"
    except (LLM.LLMError, VC.TraceError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {type(e).__name__}: {e}")


def enrich(ds: D.Dataset) -> None:
    """Chainsaw does not report ATT&CK tags or rule files: fill them in from the Sigma rules on disk."""
    ix = rule_index()
    for r in ds.rows:
        e = ix.find(title=r["title"])
        if not e:
            continue
        tech, tac = RI.mitre_from_tags(e["tags"])
        r["ruleid"], r["rulefile"] = e["id"], e["file"]
        r["tags"], r["tactics"] = tech, tac
        r["blob"] += " " + " ".join(tech + tac).lower()


def _new_job() -> tuple[str, dict]:
    jid = secrets.token_hex(6)
    job = {"state": "running", "phase": "starting", "log": [], "t0": time.time()}
    with LOCK:
        JOBS[jid] = job
        for old in list(JOBS)[:-8]:                 # keep memory bounded: only recent results stay loaded
            JOBS.pop(old, None)
    return jid, job


def _run_scan(job: dict, target: str, min_level: str, noisy: bool, json_input: bool = False, engine: str = "hayabusa") -> None:
    out = None
    try:
        if engine == "chainsaw":
            return _run_chainsaw(job, target, min_level)
        info = hayabusa_info()
        if not info.get("found"):
            raise R.HayabusaError("Hayabusa was not found. Install it, then start Hayabusa Lens with --hayabusa /path/to/hayabusa.")
        job["phase"] = f"Hayabusa {info['version']} is scanning"
        out = R.scan(info, target, min_level, noisy, job["log"], json_input)
        job["phase"] = "reading results"
        job["dataset"] = D.Dataset.load(out)
        job["dataset"].source = target
        job["label"] = "Hayabusa: " + os.path.basename(target.rstrip("/\\"))
        job["state"] = "done"
    except (R.HayabusaError, D.LoadError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {e}")
    finally:
        if out and os.path.exists(out):
            os.unlink(out)


def _run_chainsaw(job: dict, target: str, min_level: str) -> None:
    out = None
    try:
        info = chainsaw_info()
        if not info.get("found"):
            raise R.HayabusaError("Chainsaw was not found. Press 'Download it for me' next to Chainsaw first, or start with --chainsaw PATH.")
        job["phase"] = f"Chainsaw {info['version']} is hunting with Sigma rules"
        out = CS.scan(info, target, job["log"])
        job["phase"] = "reading results"
        ds = D.Dataset.load(out) if os.path.getsize(out) else D.Dataset([], target)
        floor = max(0, D.LEVEL_NAMES.index(min_level)) if min_level in D.LEVEL_NAMES else 0
        if floor:
            ds = D.Dataset([r for r in ds.rows if r["lvl"] >= floor], target, ds.skipped)
        enrich(ds)
        ds.source = target
        job["dataset"], job["label"] = ds, "Chainsaw: " + os.path.basename(target.rstrip("/\\")) 
        job["state"] = "done"
    except (R.HayabusaError, D.LoadError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {e}")
    finally:
        if out and os.path.exists(out):
            os.unlink(out)


def _run_samples(job: dict) -> None:
    try:
        info = hayabusa_info()
        if not info.get("found"):
            raise R.HayabusaError("Hayabusa is needed to scan the sample logs. Press 'Download it for me' at the top first.")
        def prog(done, total, name):
            job["phase"] = f"Downloading sample logs ({done} of {total})"
            job["progress"] = round(done / max(total, 1), 3)
        folder = SM.download(progress=prog)
        job["progress"] = 0
        job["phase"] = f"Hayabusa {info['version']} is scanning the sample logs"
        out = R.scan(info, folder, "informational", False, job["log"])
        try:
            job["phase"] = "reading results"
            job["dataset"] = D.Dataset.load(out)
            job["dataset"].source = "real sample logs (Hayabusa sample-evtx collection)"
            job["label"] = "Hayabusa: real sample logs"
        finally:
            os.unlink(out)
        job["state"] = "done"
    except (R.HayabusaError, D.LoadError, SM.SamplesError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {e}")


def _run_tool(job: dict, tool: str, path: str) -> None:
    try:
        info = hayabusa_info()
        if not info.get("found"):
            raise R.HayabusaError("Hayabusa was not found. Press 'Download it for me' at the top first.")
        job["phase"] = f"Hayabusa {info['version']}: {TL.TOOLS.get(tool, {}).get('label', tool)}"
        job["tables"] = TL.run_tool(info, tool, path, job["log"])
        job["state"] = "done"
    except (R.HayabusaError, OSError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {e}")


def _run_search(job: dict, path: str, body: dict) -> None:
    try:
        info = hayabusa_info()
        if not info.get("found"):
            raise R.HayabusaError("Hayabusa was not found. Press 'Download it for me' at the top first.")
        job["phase"] = f"Hayabusa {info['version']} is searching every event"
        kws = [k for k in str(body.get("keywords", "")).split(",")]
        job["tables"] = TL.run_search(info, path, kws, str(body.get("regex", "")), bool(body.get("all")), bool(body.get("ignoreCase", True)), job["log"])
        job["state"] = "done"
    except (R.HayabusaError, OSError) as e:
        job.update(state="error", error=str(e))
    except Exception as e:
        job.update(state="error", error=f"Unexpected error: {e}")


def _run_open(job: dict, path: str) -> None:
    try:
        job["phase"] = "reading results"
        job["dataset"] = D.Dataset.load(path)
        job["label"] = "Opened: " + os.path.basename(path)
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
            self._json(200, {**hayabusa_info(), "chainsaw": chainsaw_info(), "samples_mb": round(SM.total_mb(), 1), "tool_info": {k: {"label": v["label"], "desc": v["desc"]} for k, v in TL.TOOLS.items()}})
        elif p == "/api/status":
            job = JOBS.get((q.get("job") or [""])[0])
            if not job:
                return self._json(404, {"error": "unknown job"})
            out = {"state": job["state"], "progress": job.get("progress", 0), "phase": job.get("phase", ""), "log": job["log"][-6:], "error": job.get("error", ""), "elapsed": round(time.time() - job["t0"], 1)}
            if job.get("notice"):
                out["notice"] = job["notice"]
            if "audit" in job:
                out["audit"] = [{k: v for k, v in e.items() if k != "prompt"} for e in job["audit"]]
            if job["state"] == "done" and "agent" in job:
                out["agent"] = dict(job["agent"], audit=[{k: v for k, v in e.items() if k != "prompt"} for e in job["agent"].get("audit", [])])
            elif job["state"] == "done" and "tables" in job:
                out["tables"] = job["tables"]
            elif job["state"] == "done":
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
        elif p == "/api/rule":
            self._rule(q)
        elif p == "/api/rules":
            self._rules(q)
        elif p == "/api/rulelib":
            self._json(200, RL.status())
        elif p == "/api/netmap":
            ds = self._dataset(q)
            if ds is not None:
                self._json(200, NM.build(ds.rows))
        elif p == "/api/audit":
            self._audit(q)
        elif p == "/api/audit/download":
            self._audit_download(q)
        elif p == "/api/llm/activity":
            self._json(200, {"events": LLM.activity(float((q.get("since") or ["0"])[0] or 0))[-14:], "now": time.time()})
        elif p == "/api/chain":
            ds = self._dataset(q)
            if ds is not None:
                self._json(200, {"stages": AC.stages(ds.rows, 1), "paths": AC.paths(ds.rows, 1), "total": len(ds.rows)})
        elif p == "/api/localai":
            self._json(200, LLM.local_status())
        elif p == "/api/llm":
            self._json(200, LLM.status())
        elif p == "/api/share/download":
            self._share_download(q)
        elif p == "/api/rulefile":
            self._rulefile(q)
        elif p == "/api/jobs":
            self._jobs()
        elif p == "/api/compare":
            self._compare(q)
        elif p == "/api/ls":
            self._ls((q.get("path") or [""])[0])
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        u = urllib.parse.urlparse(self.path)
        if not self._guard(urllib.parse.parse_qs(u.query)):
            return
        n = int(self.headers.get("Content-Length") or 0)
        if n > (MAX_BODY) or u.path not in ("/api/scan", "/api/open", "/api/demo", "/api/update-rules", "/api/rulelib", "/api/localai", "/api/llm/test", "/api/llm/key", "/api/investigate", "/api/explain/evtx", "/api/share", "/api/install", "/api/samples", "/api/tool", "/api/search"):
            return self._json(404, {"error": "bad request"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._json(400, {"error": "bad JSON"})
        if u.path == "/api/llm/test":
            return self._llm_test(body)
        if u.path == "/api/llm/key":
            try:
                LLM.set_key(str(body.get("provider", "")), str(body.get("key", "")))
                return self._json(200, {"ok": True, "keys": LLM.status()["keys"]})
            except LLM.LLMError as e:
                return self._json(400, {"error": str(e)})
        if u.path == "/api/explain/evtx":
            return self._explain_evtx(body)
        if u.path == "/api/share":
            return self._share(body)
        jid, job = _new_job()
        if u.path == "/api/demo":
            job["dataset"] = D.Dataset.from_dicts(D.demo_dicts(), "Demo data")
            job["label"] = "Demo data"
            job["state"] = "done"
        elif u.path == "/api/investigate":
            ident = str(body.get("job", ""))
            src = JOBS.get(ident)
            if not src or src.get("state") != "done" or "dataset" not in src or not src["dataset"].rows:
                JOBS.pop(jid, None)
                return self._json(400, {"error": "Load some results first (scan logs, open results, or try the demo)."})
            threading.Thread(target=_run_investigate, args=(job, src, body), daemon=True).start()
        elif u.path == "/api/search":
            path = os.path.abspath(os.path.expanduser(str(body.get("path", "")).strip().strip('"')))
            threading.Thread(target=_run_search, args=(job, path, body), daemon=True).start()
        elif u.path == "/api/tool":
            path = os.path.abspath(os.path.expanduser(str(body.get("path", "")).strip().strip('"')))
            threading.Thread(target=_run_tool, args=(job, str(body.get("tool", "")), path), daemon=True).start()
        elif u.path == "/api/samples":
            threading.Thread(target=_run_samples, args=(job,), daemon=True).start()
        elif u.path == "/api/install":
            def inst():
                def prog(done, total, msg):
                    job["phase"] = msg.capitalize() + (f" ({done / 1048576:.0f} of {total / 1048576:.0f} MB)" if total and msg.startswith("down") else "")
                    job["progress"] = round(done / total, 3) if total else 0
                try:
                    path = (I.install_chainsaw if body.get("engine") == "chainsaw" else I.install)(progress=prog)
                    job.update(state="done", phase="installed: " + path)
                    job["dataset"] = D.Dataset([], "installed")
                except I.InstallError as e:
                    job.update(state="error", error=str(e))
                except Exception as e:
                    job.update(state="error", error=f"Unexpected error: {e}")
            threading.Thread(target=inst, daemon=True).start()
        elif u.path == "/api/localai":
            def local_ai():
                def prog(done, total, msg):
                    job["phase"] = msg.capitalize() + (f" ({done / 1048576:.0f} of {total / 1048576:.0f} MB)" if total else "")
                    job["progress"] = round(done / total, 3) if total else 0
                try:
                    if body.get("action") == "pull":
                        LLM.start_ollama(job["log"])
                        LLM.pull_model(str(body.get("model", "")), prog)
                        job["notice"] = f"Model {body.get('model')} is ready. Choose Ollama in Connections."
                    else:
                        LLM.start_ollama(job["log"])
                        job["notice"] = "Ollama is running."
                    job.update(state="done")
                    job["dataset"] = D.Dataset([], "localai")
                except LLM.LLMError as e:
                    job.update(state="error", error=str(e))
                except Exception as e:
                    job.update(state="error", error=f"Unexpected error: {e}")
            threading.Thread(target=local_ai, daemon=True).start()
        elif u.path == "/api/rulelib":
            def get_rules():
                def prog(done, total, msg):
                    job["phase"] = msg.capitalize() + (f" ({done / 1048576:.1f} of {total / 1048576:.1f} MB)" if total and msg.startswith("down") else "")
                    job["progress"] = round(done / total, 3) if total else 0
                try:
                    m = RL.update(str(body.get("set", "core")), str(body.get("mode", "auto")), progress=prog)
                    RI.invalidate()
                    job.update(state="done", phase=m.get("note") or ("rules ready: " + m["source"]), notice=m.get("note") or ("Rules ready: " + m["source"]))
                    job["dataset"] = D.Dataset([], "rules")
                except RL.RuleLibError as e:
                    job.update(state="error", error=str(e))
                except Exception as e:
                    job.update(state="error", error=f"Unexpected error: {e}")
            threading.Thread(target=get_rules, daemon=True).start()
        elif u.path == "/api/update-rules":
            def upd():
                info = hayabusa_info()
                if not info.get("found"):
                    return job.update(state="error", error="Hayabusa was not found.")
                job["phase"] = "updating rules (needs internet)"
                before = rule_index().summary()["unique"]
                code = R.update_rules(info, job["log"])
                RI.invalidate()
                after = rule_index().summary()["unique"]
                if code:
                    return job.update(state="error", error="Updating the rules failed: " + " | ".join(job["log"][-2:]))
                job["notice"] = f"Rules updated. {after:,} unique rules on this computer" + (f" ({after - before:+,} since before)." if after != before else " (already up to date).")
                job["dataset"] = D.Dataset([], "rules updated")
                job["state"] = "done"
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
                threading.Thread(target=_run_scan, args=(job, path, lvl, bool(body.get("noisy")), bool(body.get("jsonInput")), str(body.get("engine", "hayabusa"))), daemon=True).start()
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

    def _rule(self, q: dict) -> None:
        ds = self._dataset(q)
        if not ds:
            return
        try:
            r = ds.rows[int((q.get("i") or ["-1"])[0])]
        except (ValueError, IndexError):
            return self._json(404, {"error": "no such event"})
        ix = rule_index()
        e = ix.find(r["ruleid"], r["rulefile"], r["title"])
        if not e:
            return self._json(200, {"found": False, "title": r["title"], "note": "The rule file for this detection was not found on this computer (the rules folder may be missing or a different version)."})
        self._json(200, self._rule_payload(ix, e))

    @staticmethod
    def _rule_payload(ix, e: dict) -> dict:
        tech, tac = RI.mitre_from_tags(e["tags"])
        return {"found": True, "path": e["path"], "file": e["file"], "title": e["title"], "id": e["id"], "level": e["level"], "status": e["status"], "tags": e["tags"],
                "techniques": {t: D.mitre_url(t) for t in tech}, "tactics": tac, "text": ix.read(e["path"])}

    def _rules(self, q: dict) -> None:
        ix = rule_index()
        res = ix.search((q.get("q") or [""])[0][:100], 80)
        self._json(200, {"total": ix.summary()["unique"], "summary": ix.summary(), "rules": res})

    def _rulefile(self, q: dict) -> None:
        ix = rule_index()
        path = (q.get("path") or [""])[0]
        e = ix.entries.get(path)
        self._json(200, self._rule_payload(ix, e)) if e else self._json(404, {"error": "unknown rule"})

    def _jobs(self) -> None:
        out = []
        for jid, job in list(JOBS.items()):
            ds = job.get("dataset")
            if job.get("state") == "done" and ds is not None and ds.rows:
                out.append({"job": jid, "label": job.get("label") or ds.source or "results", "total": len(ds.rows), "when": time.strftime("%H:%M", time.localtime(job["t0"])), "levels": ds.summary()["levels"]})
        self._json(200, {"jobs": out})

    def _explain_evtx(self, body: dict) -> None:
        """One-shot plain-English attack chain for the loaded results (or one computer/account/address)."""
        try:
            src = JOBS.get(str(body.get("job", "")))
            if not src or src.get("state") != "done" or "dataset" not in src or not src["dataset"].rows:
                raise LLM.LLMError("Load some results first.")
            c = resolve_ai(body.get("ai"))
            focus = str(body.get("focus", ""))
            text = LLM.chat(c["provider"], AC.explain_prompt(src["dataset"].rows, focus), c["key"], c["base"], c["model"], max_tokens=700)
            self._json(200, {"text": text, "ai": c["provider"] + (" · " + c["model"] if c["model"] else "")})
        except LLM.LLMError as e:
            self._json(400, {"error": str(e)})

    def _llm_test(self, body: dict) -> None:
        prov = str(body.get("provider", ""))
        try:
            if prov not in LLM.PROVIDERS and prov != "claude-code":
                raise LLM.LLMError("Choose a service to test.")
            if body.get("consent") is not True and not LLM.is_local(prov, str(body.get("base", ""))):
                raise LLM.LLMError("Tick the box to confirm a tiny test message ('reply pong') may be sent to that service.")
            self._json(200, LLM.test(prov, "embed" if body.get("kind") == "embed" else "chat", str(body.get("key", "")), str(body.get("base", "")), str(body.get("model", ""))))
        except LLM.LLMError as e:
            self._json(200, {"ok": False, "error": str(e)})

    def _share_events(self, src: str, ident: str, min_level: int) -> tuple[list[dict], str]:
        if src == "audit":
            t = TRACES.get(ident)
            if not t:
                raise SH.ShareError("That AI investigation is no longer loaded. Run it again.")
            return SH.audit_events(t), "audit"
        job = JOBS.get(ident)
        if not job or job.get("state") != "done" or "dataset" not in job:
            raise SH.ShareError("Those results are no longer loaded. Run the scan again or open the file.")
        return [SH.ecs_event(r) for r in SH.select(job["dataset"].rows, min_level)], "alerts"

    def _share(self, body: dict) -> None:
        try:
            try:
                lvl = min(4, max(0, int(body.get("minLevel", 2))))
            except (TypeError, ValueError):
                lvl = 2
            events, kind = self._share_events(str(body.get("source", "alerts")), str(body.get("job") or body.get("id") or ""), lvl)
            dest = body.get("dest") if isinstance(body.get("dest"), dict) else {}
            out = {"count": len(events), "sample": events[:2], "kind": kind}
            if body.get("action") != "send":
                return self._json(200, out)
            if body.get("confirm") is not True:
                raise SH.ShareError("Tick the box to confirm you want to send these events.")
            if not events:
                raise SH.ShareError("Nothing to send at that minimum level.")
            t = str(dest.get("type", ""))
            if t == "file":
                out.update(sent=len(events), path=SH.write_file(events, str(dest.get("path", ""))), message="Appended to the file. Point your SIEM agent at it.")
            elif t == "syslog":
                out.update(sent=SH.send_syslog(events, str(dest.get("host", "")).strip(), int(dest.get("port") or 514), str(dest.get("proto", "udp")), str(dest.get("fmt", "cef"))))
            elif t in ("elastic", "splunk", "webhook"):
                out["sent"] = SH.post(events, t, str(dest.get("url", "")), str(dest.get("auth", "")), str(dest.get("index") or "hayabusa-lens"))
            else:
                raise SH.ShareError("Choose where to send them.")
            out.setdefault("message", f"Sent {out['sent']:,} event(s).")
            self._json(200, out)
        except SH.ShareError as e:
            self._json(400, {"error": str(e)})
        except (ValueError, OSError) as e:
            self._json(400, {"error": f"Could not do that: {e}"})

    def _share_download(self, q: dict) -> None:
        try:
            events, kind = self._share_events((q.get("source") or ["alerts"])[0], (q.get("job") or q.get("id") or [""])[0], int((q.get("minLevel") or ["2"])[0]))
        except (SH.ShareError, ValueError) as e:
            return self._json(400, {"error": str(e)})
        if (q.get("fmt") or ["ndjson"])[0] == "cef":
            data, name, ctype = "\n".join(SH.cef(e) for e in events) + "\n", f"hayabusa-lens-{kind}.cef", "text/plain; charset=utf-8"
        else:
            data, name, ctype = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events), f"hayabusa-lens-{kind}.ndjson", "application/x-ndjson"
        self._send(200, data.encode("utf-8"), ctype, {"Content-Disposition": f'attachment; filename="{name}"'})

    def _audit_for(self, q: dict) -> dict | None:
        ident = (q.get("id") or q.get("job") or [""])[0]
        t = TRACES.get(ident)
        if t:
            return {"audit": t.get("audit", []), "label": t.get("label", ""), "report": t.get("report", ""), "ai": t.get("ai", "")}
        j = JOBS.get(ident)
        if j and "audit" in j:
            return {"audit": list(j["audit"]), "label": "AI investigation (running)", "report": "", "ai": ""}
        return None

    def _audit(self, q: dict) -> None:
        a = self._audit_for(q)
        self._json(200, a) if a else self._json(404, {"error": "No AI investigation with that id."})

    def _audit_download(self, q: dict) -> None:
        a = self._audit_for(q)
        if not a:
            return self._json(404, {"error": "No AI investigation with that id."})
        if (q.get("fmt") or ["md"])[0] == "json":
            return self._send(200, json.dumps(a, indent=1, ensure_ascii=False).encode("utf-8"), "application/json", {"Content-Disposition": 'attachment; filename="hayabusa-lens-ai-audit.json"'})
        lines = [f"# AI investigation audit trail", "", f"- Source: {a['label']}", f"- AI helper: {a['ai'] or 'unknown'}", f"- Made by Hayabusa Lens {__version__} on {time.strftime('%Y-%m-%d %H:%M:%S')}", "- Every question put to the AI and every answer that came back is listed below, with the tool it chose and what that tool returned.", ""]
        for e in a["audit"]:
            lines += [f"## {e['n']}. {e['question']}", f"*{time.strftime('%H:%M:%S', time.localtime(e['t']))} · {e['ms'] / 1000:.1f} s · {e.get('ai', '')}*", "",
                      "**Question sent to the AI**", "", "```", e.get("prompt", "(not stored)"), "```", "", "**AI answered**", "", "```", e.get("answer", ""), "```", ""]
            if e.get("action"):
                lines += [f"**Tool chosen:** `{e['action']} {e.get('args', '')}`", "", "**Tool returned**", "", "```", e.get("result", ""), "```", ""]
        if a["report"]:
            lines += ["## Final report", "", a["report"], ""]
        self._send(200, "\n".join(lines).encode("utf-8"), "text/markdown; charset=utf-8", {"Content-Disposition": 'attachment; filename="hayabusa-lens-ai-audit.md"'})

    def _compare(self, q: dict) -> None:
        ja, jb = JOBS.get((q.get("a") or [""])[0]), JOBS.get((q.get("b") or [""])[0])
        if not ja or not jb or "dataset" not in ja or "dataset" not in jb:
            return self._json(404, {"error": "Both results must still be loaded. Run the scans again or open the files."})
        mode = "event" if (q.get("mode") or [""])[0] == "event" else "rule"
        key = ((q.get("a") or [""])[0], (q.get("b") or [""])[0], mode)
        if key not in COMPARES:
            COMPARES.clear()
            COMPARES[key] = CP.compare(ja["dataset"], jb["dataset"], mode)
        c = COMPARES[key]
        which = (q.get("which") or ["new"])[0]
        rows = c["_gone"] if which == "gone" else c["_new"]
        rows = sorted(rows, key=lambda r: (-r["lvl"], r["ts"]))
        if (q.get("fmt") or [""])[0] == "csv":
            return self._send(200, export_csv(rows).encode(), "text/csv; charset=utf-8", {"Content-Disposition": f'attachment; filename="hayabusa-lens-{which}.csv"'})
        try:
            off, lim = max(0, int((q.get("offset") or ["0"])[0])), min(500, max(1, int((q.get("limit") or ["100"])[0])))
        except ValueError:
            off, lim = 0, 100
        out = {k: v for k, v in c.items() if not k.startswith("_")}
        out.update(which=which, total=len(rows), rows=[D.compact(r) for r in rows[off:off + lim]])
        self._json(200, out)

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


def serve(port: int = 0, open_browser: bool = True, path: str | None = None, demo: bool = False, samples: bool = False, ai_start: bool = True) -> int:
    httpd, token = make_server(port)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/?token={token}"
    if samples:
        url += "&samples=1"
    elif demo:
        url += "&demo=1"
    elif path:
        url += "&path=" + urllib.parse.quote(os.path.abspath(path))
    print(f"Hayabusa Lens {__version__} by {__author__}\n  {url}\nListening on this computer only. Press Ctrl+C to stop.", flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    if ai_start:
        threading.Thread(target=LLM.autostart, daemon=True).start()          # bring a local model up so the AI buttons are ready
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
        LLM.stop_started()
    return 0
