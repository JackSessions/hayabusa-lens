"""Vector chain analysis for LLM / agent traces.

Every step of an agent run (prompt, tool call, tool result, reply) becomes a vector. The vectors are squeezed to 3D
(PCA) so the run can be drawn as a chain of points. Big jumps between neighbouring steps, and steps that sit far away
from the task the agent was given, are scored and flagged: that is what a prompt injection or a hijacked agent looks like.

Two ways to make the vectors:
  local   hashed word and word-pair TF-IDF. Offline, no keys, nothing leaves this computer. It measures shared WORDS,
          not meaning, so a tool result that uses new vocabulary can look like a jump. Treat flags as leads, not verdicts.
  api     real embeddings from an OpenAI-compatible service (see llm.py), which capture meaning much better.

The risk score also uses a short list of well-known injection phrases. It is a heuristic, not a detector."""
from __future__ import annotations

import json
import math
import re
import zlib

MAX_STEPS = 3000
MAX_TEXT = 4000
EMBED_CHARS = 1500
DIM = 1 << 14

KINDS = ("system", "user", "assistant", "tool_call", "tool_result", "other")

INJECTION = [
    (r"ignore (?:all |any )?(?:the )?(?:previous|prior|above|earlier) (?:instructions|prompts?|rules)", "tells the model to ignore its instructions"),
    (r"disregard (?:all |any )?(?:the )?(?:previous|prior|above|earlier|your)", "tells the model to disregard earlier context"),
    (r"you are now (?:a |an |in )", "tries to reassign the model's role"),
    (r"(?:new|updated|revised) (?:system )?instructions?\s*[:\-]", "injects new instructions"),
    (r"(?:reveal|print|show|repeat|leak) (?:your |the )?(?:system|hidden|initial) (?:prompt|instructions|message)", "asks for the system prompt"),
    (r"do not (?:tell|inform|mention (?:this )?to) the user", "asks to hide actions from the user"),
    (r"without (?:telling|informing|notifying) the user", "asks to hide actions from the user"),
    (r"(?:send|email|post|upload|forward|exfiltrate)\b[^.\n]{0,80}\b(?:id_rsa|\.ssh|password|passwd|secret|api[_ -]?key|token|credentials|\.env)", "moves secrets to somewhere else"),
    (r"(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:ba|z)?sh", "pipes a download into a shell"),
    (r"base64\s+(?:-d|--decode)|powershell[^\n]{0,40}-enc", "decodes and runs hidden payloads"),
    (r"<\s*(?:system|im_start|\|im_start\|)\s*>|\[\s*(?:system|inst)\s*\]", "fake system or chat markers inside data"),
]
_INJ = [(re.compile(p, re.I), why) for p, why in INJECTION]
_WORD = re.compile(r"[a-z0-9_\.\-/\\@:]{2,}|[^\W\d_]{2,}", re.I)


SENSITIVE = ("id_rsa", ".ssh", ".env", "/etc/passwd", "/etc/shadow", "credentials", "api_key", "api-key", "private key", "secret", "password", "aws_access")


class TraceError(Exception):
    pass


# ---------- reading traces ----------

def _flat(x, limit=MAX_TEXT) -> str:
    """Turn any message content (string, list of blocks, dict) into plain text."""
    if x is None:
        return ""
    if isinstance(x, str):
        return x
    if isinstance(x, list):
        return "\n".join(t for t in (_flat(i, limit) for i in x) if t)[:limit]
    if isinstance(x, dict):
        for k in ("text", "content", "output", "result", "message", "value"):
            if k in x and x[k] not in (None, ""):
                return _flat(x[k], limit)
        return json.dumps(x, ensure_ascii=False)[:limit]
    return str(x)


def _steps_from_record(rec: dict) -> list[tuple[str, str, str]]:
    """One JSON record can hold several steps (a Claude message with text + tool_use blocks). Returns (kind, label, text)."""
    if isinstance(rec.get("payload"), dict):                       # Codex-style {"type":"response_item","payload":{...}}
        rec = rec["payload"]
    rtype = str(rec.get("type", "")).lower()
    if rtype == "function_call":
        return [("tool_call", "tool: " + str(rec.get("name", "?")), f"{rec.get('name', '')} {_flat(rec.get('arguments'))}")]
    if rtype == "function_call_output":
        return [("tool_result", "result", _flat(rec.get("output")))]
    role = str(rec.get("role") or rec.get("type") or rec.get("speaker") or rec.get("kind") or "").lower()
    out: list[tuple[str, str, str]] = []
    content = rec.get("content", rec.get("message", rec.get("text")))
    if isinstance(rec.get("message"), dict):                       # Claude Code style {"type":"assistant","message":{...}}
        role = str(rec["message"].get("role") or role).lower()
        content = rec["message"].get("content")
    if isinstance(content, list):
        for b in content:
            if not isinstance(b, dict):
                t = _flat(b)
                if t:
                    out.append((_role_kind(role), role or "text", t))
                continue
            bt = str(b.get("type", "")).lower()
            if bt == "tool_use":
                out.append(("tool_call", "tool: " + str(b.get("name", "?")), f"{b.get('name', '')} {_flat(b.get('input'))}"))
            elif bt == "tool_result":
                out.append(("tool_result", "result", _flat(b.get("content"))))
            elif bt in ("text", "input_text", "output_text"):
                out.append((_role_kind(role), role or "text", _flat(b.get("text"))))
            elif bt in ("thinking", "redacted_thinking"):
                out.append(("assistant", "thinking", _flat(b.get("thinking"))))
            else:
                out.append((_role_kind(role), role or bt or "other", _flat(b)))
    else:
        text = _flat(content)
        calls = rec.get("tool_calls") or ([rec["function_call"]] if rec.get("function_call") else [])
        if role in ("tool", "function") or rec.get("tool_call_id"):
            out.append(("tool_result", "result", text))
        elif text or not calls:
            if rec.get("tool_name") or rec.get("tool"):                      # flat custom format
                out.append(("tool_call", "tool: " + str(rec.get("tool_name") or rec.get("tool")), f"{rec.get('tool_name') or rec.get('tool')} {_flat(rec.get('args') or rec.get('arguments') or rec.get('input'))} {text}".strip()))
            else:
                out.append((_role_kind(role), role or "step", text))
        for c in calls:
            fn = c.get("function", c) if isinstance(c, dict) else {}
            out.append(("tool_call", "tool: " + str(fn.get("name", "?")), f"{fn.get('name', '')} {_flat(fn.get('arguments'))}"))
    for key, kind in (("output", "tool_result"), ("observation", "tool_result"), ("action", "tool_call"), ("thought", "assistant")):
        if key in rec and key not in ("content", "message", "text") and not out:
            out.append((kind, key, _flat(rec[key])))
    return [(k, l, t) for k, l, t in out if t and t.strip()]


def _role_kind(role: str) -> str:
    if "system" in role or "developer" in role:
        return "system"
    if role in ("user", "human") or "prompt" in role:
        return "user"
    if role in ("assistant", "ai", "model", "agent", "bot"):
        return "assistant"
    if "tool_result" in role or role in ("tool", "function", "observation", "result"):
        return "tool_result"
    if "tool" in role or role in ("action", "call"):
        return "tool_call"
    return "other"


def find_traces(limit: int = 25) -> list[dict]:
    """Agent logs already on this computer (Claude Code, Codex, or anything saved in ~/.hayabusa-lens/traces)."""
    import glob
    import os
    home = os.path.expanduser("~")
    spots = [("Claude Code", os.path.join(home, ".claude", "projects", "*", "*.jsonl")),
             ("Codex", os.path.join(home, ".codex", "sessions", "**", "*.jsonl")),
             ("Saved", os.path.join(home, ".hayabusa-lens", "traces", "*.jsonl"))]
    found = []
    for tool, pat in spots:
        for f in glob.glob(pat, recursive=True):
            try:
                st = os.stat(f)
            except OSError:
                continue
            if st.st_size < 200:
                continue
            proj = os.path.basename(os.path.dirname(f)).strip("-").replace("-", "/") if tool == "Claude Code" else ""
            found.append({"path": f, "tool": tool, "name": os.path.basename(f), "project": proj, "size": st.st_size, "mtime": int(st.st_mtime)})
    return sorted(found, key=lambda x: -x["mtime"])[:limit]


def parse_trace(text: str) -> list[dict]:
    text = text.strip().lstrip("﻿")
    if not text:
        raise TraceError("The trace is empty.")
    records: list = []
    if text.startswith("["):
        try:
            records = json.loads(text)
        except ValueError as e:
            raise TraceError(f"That looks like a JSON array but it is not valid JSON ({e}).") from e
    else:
        bad = 0
        for ln in text.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except ValueError:
                bad += 1
        if not records:
            raise TraceError("Could not read any JSON lines. Expected one JSON object per line (JSONL), or a JSON array.")
    if isinstance(records, dict):
        records = records.get("messages") or records.get("steps") or records.get("trace") or [records]
    steps: list[dict] = []
    for rec in records:
        if isinstance(rec, str):
            parts = [("other", "step", rec)]
        elif isinstance(rec, dict):
            parts = _steps_from_record(rec)
        else:
            continue
        for kind, label, body in parts:
            steps.append({"i": len(steps), "kind": kind, "label": label, "text": body[:MAX_TEXT]})
            if len(steps) >= MAX_STEPS:
                return steps
    if len(steps) < 2:
        raise TraceError("Found fewer than 2 readable steps. Each line needs a role/type and some content (prompt, tool call or output).")
    return steps


# ---------- vectors ----------

_STOP = frozenset("the a an and or of to in on for with is are was were be been it this that as at by from you your i we our will can not do does did have has had if then so but into out up my me they them their its".split())


def _tokens(text: str) -> list[str]:
    w = [t.lower() for t in _WORD.findall(text)]
    w = [t for t in w if t not in _STOP]
    return w + [a + " " + b for a, b in zip(w, w[1:])]


def embed_local(texts: list[str]) -> list[dict]:
    """Hashed TF-IDF. Returns sparse unit vectors as {index: weight}."""
    tfs, df = [], {}
    for t in texts:
        t = t[:EMBED_CHARS]
        tf: dict[int, float] = {}
        for tok in _tokens(t):
            h = zlib.crc32(tok.encode("utf-8", "ignore"))
            idx, sign = h % DIM, 1.0 if (h >> 31) & 1 else -1.0
            tf[idx] = tf.get(idx, 0.0) + sign
        tfs.append(tf)
        for k in tf:
            df[k] = df.get(k, 0) + 1
    n = len(texts)
    out = []
    for tf in tfs:
        v = {k: (1 + math.log(abs(c))) * math.copysign(1, c) * (math.log((1 + n) / (1 + df[k])) + 1) for k, c in tf.items() if c}
        out.append(_unit(v))
    return out


def from_dense(rows: list[list[float]]) -> list[dict]:
    return [_unit({j: x for j, x in enumerate(r) if x}) for r in rows]


def _unit(v: dict) -> dict:
    n = math.sqrt(sum(x * x for x in v.values())) or 1.0
    return {k: x / n for k, x in v.items()}


def cos(a: dict, b: dict) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(x * b.get(k, 0.0) for k, x in a.items())


def _centroid(vs: list[dict]) -> dict:
    c: dict = {}
    for v in vs:
        for k, x in v.items():
            c[k] = c.get(k, 0.0) + x
    return _unit(c) if c else {}


# ---------- 3D layout (PCA by power iteration on sparse, centred data) ----------

def pca3(vs: list[dict], iters: int = 25) -> list[list[float]]:
    n = len(vs)
    if n == 0:
        return []
    mean: dict[int, float] = {}
    for v in vs:
        for k, x in v.items():
            mean[k] = mean.get(k, 0.0) + x / n
    keys = sorted({k for v in vs for k in v})
    comps: list[dict] = []
    seed = 12345

    def matvec(w: dict) -> list[float]:               # (X - 1 m^T) w
        mw = sum(mean.get(k, 0.0) * x for k, x in w.items())
        return [sum(x * w.get(k, 0.0) for k, x in v.items()) - mw for v in vs]

    def rmatvec(u: list[float]) -> dict:               # (X - 1 m^T)^T u
        su, out = sum(u), {}
        for ui, v in zip(u, vs):
            if ui:
                for k, x in v.items():
                    out[k] = out.get(k, 0.0) + x * ui
        for k in keys:
            out[k] = out.get(k, 0.0) - mean.get(k, 0.0) * su
        return out

    for _ in range(3):
        w = {}
        for k in keys:
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
            w[k] = (seed / 0x7FFFFFFF) - 0.5
        for _i in range(iters):
            w = rmatvec(matvec(w))
            for c in comps:                             # deflate against earlier components
                d = sum(w.get(k, 0.0) * x for k, x in c.items())
                for k, x in c.items():
                    w[k] = w.get(k, 0.0) - d * x
            nr = math.sqrt(sum(x * x for x in w.values()))
            if nr < 1e-12:
                break
            w = {k: x / nr for k, x in w.items()}
        comps.append(w)
    cols = [matvec(c) for c in comps]
    pts = [[cols[d][i] for d in range(3)] for i in range(n)]
    for d in range(3):                                  # scale each axis to [-1, 1]
        m = max((abs(p[d]) for p in pts), default=0) or 1.0
        for p in pts:
            p[d] /= m
    return pts


# ---------- scoring ----------

def _robust_z(vals: list[float]) -> list[float]:
    s = sorted(vals)
    med = s[len(s) // 2]
    mad = sorted(abs(x - med) for x in vals)[len(vals) // 2] or 1e-6
    return [0.6745 * (x - med) / mad for x in vals]


def injection_hits(text: str) -> list[str]:
    return sorted({why for rx, why in _INJ if rx.search(text)})


def analyze(steps: list[dict], vectors: list[dict] | None = None, mode: str = "local") -> dict:
    texts = [s["text"] for s in steps]
    vs = vectors if vectors is not None else embed_local(texts)
    n = len(steps)
    first_user = next((i for i, s in enumerate(steps) if s["kind"] == "user"), 0)
    goal = vs[first_user]
    jump = [0.0] + [max(0.0, 1 - cos(vs[i], vs[i - 1])) for i in range(1, n)]
    drift = [max(0.0, 1 - cos(vs[i], goal)) for i in range(n)]
    recent = [0.0] + [max(0.0, 1 - max(cos(vs[i], vs[j]) for j in range(max(0, i - 4), i))) for i in range(1, n)]
    zj, zr = _robust_z(jump), _robust_z(recent)
    pts = pca3(vs)
    goal_text = steps[first_user]["text"].lower()
    tainted = {i for i, s in enumerate(steps) if s["kind"] == "tool_result" and injection_hits(s["text"])}
    out = []
    for i, s in enumerate(steps):
        hits = injection_hits(s["text"]) if s["kind"] in ("tool_result", "other") else []   # injections arrive in data, not in the agent's own words
        why = []
        risk = 0.0
        if i and zj[i] > 2.5 and zr[i] > 1.5:
            risk += min(2.0, 0.4 * zj[i])
            why.append(f"big jump from the previous step (robust z {zj[i]:.1f})")
        if i and drift[i] > 0.97 and zr[i] > 1.0 and s["kind"] in ("assistant", "tool_call"):
            risk += 0.6
            why.append("far from the task the agent was given")
        if hits:
            risk += 1.5 + 0.5 * len(hits)
            why += hits
        if s["kind"] in ("assistant", "tool_call") and i and any(k in tainted for k in range(max(0, i - 4), i)):
            risk += 1.2 if s["kind"] == "assistant" else 1.6
            why.append("acts soon after a tool result that contained injection phrases")
        sens = [t for t in SENSITIVE if t in s["text"].lower() and t not in goal_text]
        if sens and s["kind"] in ("tool_call", "assistant"):
            risk += 1.2
            why.append("touches secrets the task never mentioned (" + ", ".join(sens[:3]) + ")")
        lvl = 4 if risk >= 3.5 else 3 if risk >= 2.5 else 2 if risk >= 1.5 else 1 if risk >= 0.6 else 0
        out.append({"i": i, "kind": s["kind"], "label": s["label"], "text": s["text"], "x": pts[i][0], "y": pts[i][1], "z": pts[i][2],
                    "jump": round(jump[i], 3), "drift": round(drift[i], 3), "risk": round(risk, 2), "lvl": lvl, "why": why})
    flagged = [s for s in out if s["lvl"] >= 2]
    return {"mode": mode, "n": n, "goal": first_user, "flagged": len(flagged), "steps": out,
            "note": "Local mode compares shared words, not meaning. Flags are leads to review, not verdicts." if mode == "local" else f"Vectors: {mode}. Flags are leads to review, not verdicts."}
