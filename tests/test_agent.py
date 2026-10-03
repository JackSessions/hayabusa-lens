import sys
import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402
from hayabusa_lens import data as D
from hayabusa_lens import llm as LLM
from hayabusa_lens import netmap as NM
from hayabusa_lens import server
from hayabusa_lens import vectorchain as VC


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class TraceTests(unittest.TestCase):
    def test_demo_flags_the_injection_chain(self):
        r = VC.analyze(VC.parse_trace(fixtures.demo_trace()))
        flagged = [s["i"] for s in r["steps"] if s["lvl"] >= 2]
        self.assertIn(7, flagged)                     # the tool result carrying the injection
        self.assertIn(9, flagged)                     # the agent reading the private key
        self.assertIn(11, flagged)                    # and emailing it
        self.assertNotIn(5, flagged)                  # normal work stays quiet
        for s in r["steps"]:
            self.assertTrue(all(-1.0001 <= s[k] <= 1.0001 for k in "xyz"))

    def test_formats(self):
        claude = [{"role": "user", "content": "list files"},
                  {"role": "assistant", "content": [{"type": "text", "text": "ok"}, {"type": "tool_use", "name": "ls", "input": {"p": "."}}]},
                  {"role": "user", "content": [{"type": "tool_result", "content": "a.txt b.txt"}]}]
        kinds = [s["kind"] for s in VC.parse_trace(json.dumps(claude))]
        self.assertEqual(kinds, ["user", "assistant", "tool_call", "tool_result"])
        openai = "\n".join(json.dumps(x) for x in [{"role": "user", "content": "hi there"},
                                                    {"role": "assistant", "content": None, "tool_calls": [{"function": {"name": "f", "arguments": "{}"}}]},
                                                    {"role": "tool", "content": "done", "tool_call_id": "1"}])
        self.assertEqual([s["kind"] for s in VC.parse_trace(openai)], ["user", "tool_call", "tool_result"])

    def test_bad_input(self):
        for bad in ("", "not json at all", '{"role":"user","content":"only one"}'):
            with self.assertRaises(VC.TraceError):
                VC.parse_trace(bad)

    def test_agent_own_code_is_not_flagged_as_injection(self):
        rows = [{"role": "user", "content": "write a detector for prompt injection"},
                {"type": "tool_use", "role": "assistant", "tool_name": "write", "args": {"text": "ignore all previous instructions"}},
                {"role": "assistant", "content": "Done, the detector looks for ignore all previous instructions."}]
        r = VC.analyze(VC.parse_trace("\n".join(json.dumps(x) for x in rows)))
        self.assertEqual(r["flagged"], 0)

    def test_pca_deterministic(self):
        st = VC.parse_trace(fixtures.demo_trace())
        a = VC.analyze(st)["steps"]
        b = VC.analyze(st)["steps"]
        self.assertEqual([s["x"] for s in a], [s["x"] for s in b])


class LLMTests(unittest.TestCase):
    def test_openai_embeddings_request(self):
        seen = {}

        def op(req, timeout=0):
            seen["url"], seen["auth"], seen["body"] = req.full_url, req.get_header("Authorization"), json.loads(req.data)
            return Resp(json.dumps({"data": [{"index": i, "embedding": [1.0, 0.0, float(i)]} for i in range(len(seen["body"]["input"]))]}).encode())
        out = LLM.embed("openai", ["a", "b"], key="sk-test-123", opener=op)
        self.assertEqual(len(out), 2)
        self.assertEqual(seen["url"], "https://api.openai.com/v1/embeddings")
        self.assertEqual(seen["auth"], "Bearer sk-test-123")

    def test_anthropic_explain_headers_and_untrusted_fence(self):
        seen = {}

        def op(req, timeout=0):
            seen["url"], seen["key"], seen["ver"], seen["body"] = req.full_url, req.get_header("X-api-key"), req.get_header("Anthropic-version"), json.loads(req.data)
            return Resp(json.dumps({"content": [{"type": "text", "text": "looks injected"}]}).encode())
        steps = VC.analyze(VC.parse_trace(fixtures.demo_trace()))["steps"]
        self.assertEqual(LLM.explain("anthropic", steps, key="sk-ant-x", opener=op), "looks injected")
        self.assertEqual(seen["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual((seen["key"], seen["ver"]), ("sk-ant-x", "2023-06-01"))
        self.assertIn("UNTRUSTED DATA", seen["body"]["messages"][0]["content"])

    def test_no_embeddings_for_claude_and_plain_http_refused(self):
        with self.assertRaises(LLM.LLMError):
            LLM.embed("anthropic", ["x"], key="k")
        with self.assertRaises(LLM.LLMError):
            LLM.embed("openai", ["x"], key="k", base="http://api.example.com/v1")
        LLM.resolve("compatible", base="http://localhost:11434/v1", model="m")        # local http is fine

    def test_key_never_in_error(self):
        def op(req, timeout=0):
            raise urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b'{"error":{"message":"bad key sk-secret-999"}}'))
        with self.assertRaises(LLM.LLMError) as cm:
            LLM.embed("openai", ["x"], key="sk-secret-999", opener=op)
        self.assertNotIn("sk-secret-999", str(cm.exception))

    def test_env_key(self):
        os.environ["OPENAI_API_KEY"] = "sk-env"
        try:
            self.assertTrue(LLM.env_keys()["openai"])
            self.assertEqual(LLM.resolve("openai")[1], "sk-env")
        finally:
            del os.environ["OPENAI_API_KEY"]


class NetmapTests(unittest.TestCase):
    def test_graph(self):
        g = NM.build(D.Dataset.from_dicts(fixtures.demo_dicts(), "d").rows)
        types = {n["type"] for n in g["nodes"]}
        self.assertEqual(types, {"host", "user", "ip"})
        ext = [n for n in g["nodes"] if n["type"] == "ip" and n["sub"] == "external"]
        self.assertTrue(ext)
        self.assertTrue(g["leads"])
        ids = {n["id"] for n in g["nodes"]}
        self.assertTrue(all(e["a"] in ids and e["b"] in ids for e in g["edges"]))

    def test_ignores_noise(self):
        rows = D.Dataset.from_dicts([{"Timestamp": "2024-01-01T00:00:00Z", "RuleTitle": "x", "Level": "low", "Computer": "PC1", "Details": {"User": "SYSTEM", "Src": "127.0.0.1 and 8.8.8.8"}}], "d").rows
        g = NM.build(rows)
        self.assertEqual(sorted(n["name"] for n in g["nodes"]), ["8.8.8.8", "PC1"])


class LocalAITests(unittest.TestCase):
    def test_status_reads_ollama_tags(self):
        def op(req, timeout=0):
            return Resp(json.dumps({"models": [{"name": "all-minilm:latest"}, {"name": "phi3:latest"}]}).encode())
        st = LLM.local_status(opener=op, which=lambda n: "/usr/bin/ollama")
        self.assertEqual((st["installed"], st["running"], st["models"]), (True, True, ["all-minilm:latest", "phi3:latest"]))

    def test_status_when_nothing_there(self):
        def op(req, timeout=0):
            raise OSError("refused")
        st = LLM.local_status(opener=op, which=lambda n: None)
        self.assertEqual((st["installed"], st["running"], st["models"]), (False, False, []))

    def test_pull_streams_progress_and_rejects_unlisted_models(self):
        seen = []

        def op(req, timeout=0):
            self.assertEqual(json.loads(req.data)["model"], "all-minilm")
            return Resp(b'{"status":"pulling manifest"}\n{"status":"pulling x","total":100,"completed":50}\n{"status":"success"}\n')
        LLM.pull_model("all-minilm", lambda d, t, m: seen.append((d, t, m)), opener=op)
        self.assertIn((50, 100, "pulling x"), seen)
        with self.assertRaises(LLM.LLMError):
            LLM.pull_model("evil/model:latest", opener=op)

    def test_pull_error_is_reported(self):
        with self.assertRaises(LLM.LLMError):
            LLM.pull_model("all-minilm", opener=lambda req, timeout=0: Resp(b'{"error":"no space left"}\n'))

    def test_local_services_need_no_consent_or_key(self):
        self.assertTrue(LLM.is_local("ollama"))
        self.assertTrue(LLM.is_local("compatible", "http://127.0.0.1:1234/v1"))
        self.assertFalse(LLM.is_local("openai"))
        self.assertFalse(LLM.is_local("compatible", "https://api.example.com/v1"))
        seen = {}

        def op(req, timeout=0):
            seen["auth"] = req.get_header("Authorization")
            return Resp(json.dumps({"data": [{"index": 0, "embedding": [0.1, 0.2]}]}).encode())
        self.assertEqual(LLM.embed("ollama", ["x"], opener=op), [[0.1, 0.2]])
        self.assertIsNone(seen["auth"])

    def test_no_embedding_support_gives_a_useful_error(self):
        def op(req, timeout=0):
            raise urllib.error.HTTPError(req.full_url, 501, "x", {}, io.BytesIO(b"{}"))
        with self.assertRaises(LLM.LLMError) as cm:
            LLM.embed("ollama", ["x"], model="phi3", opener=op)
        self.assertIn("embedding model", str(cm.exception))


class NetmapRealWorldTests(unittest.TestCase):
    def test_hayabusa_style_fields(self):
        row = {"Timestamp": "2024-01-01T00:00:00Z", "RuleTitle": "x", "Level": "high", "Computer": "PC01.example.corp",
               "Details": {"SubjectUserName": "admin01", "SubjectDomainName": "EXAMPLE", "SubjectLogonId": "0xaf855", "SubjectUserSid": "S-1-5-21-1-2-3-1108",
                           "TgtUser": "bob", "SrcComp": "alice.insecurebank.local", "IpAddress": "10.0.2.15"}}
        rows = D.Dataset.from_dicts([row, dict(row, Computer="PC01")], "d").rows
        names = sorted(n["id"] for n in NM.build(rows)["nodes"])
        self.assertEqual(names, ["host:alice", "host:pc01", "ip:10.0.2.15", "user:admin01", "user:bob"])
