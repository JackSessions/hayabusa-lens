import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from hayabusa_lens import attackchain as AC  # noqa: E402
from hayabusa_lens import data as D  # noqa: E402
from hayabusa_lens import investigate as INV  # noqa: E402
from hayabusa_lens import llm as LLM  # noqa: E402
from hayabusa_lens import server  # noqa: E402


def rows():
    return [dict(r, i=i) for i, r in enumerate(D.Dataset.from_dicts(D.demo_dicts(), "d").rows)]


def scripted(*replies):
    it = iter(replies)
    prompts = []

    def ask(prompt):
        prompts.append(prompt)
        return next(it)
    ask.prompts = prompts
    return ask


def act(action, **args):
    return json.dumps({"thought": "because", "action": action, "args": args})


class ChainTests(unittest.TestCase):
    def test_stages_in_attack_order_with_aliases(self):
        r = [dict(x) for x in rows()]
        st = AC.stages(r)
        names = [s["stage"] for s in st]
        self.assertEqual(names, sorted(names, key=AC.ORDER.index))
        self.assertEqual(AC.tactic("Stealth"), "Defense Evasion")
        self.assertEqual(AC.tactic("LatMov"), "Lateral Movement")
        self.assertEqual(AC.tactic("credential access"), "Credential Access")

    def test_digest_notes_a_long_span_and_respects_focus(self):
        r = rows()
        r[0]["ts"] -= 40 * 86400000
        self.assertIn("span 40 days", AC.digest(r))
        d = AC.digest(r, "DEMO-DC01")
        self.assertIn("DEMO-DC01", d)
        self.assertLessEqual(len(AC.digest(r, cap=500)), 500)

    def test_explain_prompt_fences_evidence(self):
        p = AC.explain_prompt(rows())
        self.assertIn("UNTRUSTED DATA", p)
        self.assertIn("<evidence>", p)


class ToolTests(unittest.TestCase):
    def test_every_tool_returns_text_and_survives_bad_args(self):
        r = rows()
        self.assertIn("Alerts:", INV.run_tool(r, "overview", {}))
        self.assertIn("DEMO-WS01", INV.run_tool(r, "host", {"name": ["demo-ws01"]}))          # a list instead of a string
        self.assertIn("fired", INV.run_tool(r, "rule", {"rule": "whoami"}))                     # a different key name
        self.assertIn("events contain", INV.run_tool(r, "search", {"query": "svc.backup"}))
        self.assertIn("alerts shown", INV.run_tool(r, "timeline", {"min_level": "critical"}))
        self.assertIn("DEMO", INV.run_tool(r, "event", {"i": "3"}))
        self.assertIn("No such event", INV.run_tool(r, "event", {"i": 99999}))
        self.assertIn("Unknown tool", INV.run_tool(r, "rm -rf", {}))
        self.assertIn("Known computers", INV.run_tool(r, "host", {"name": "nope"}))
        INV.run_tool(r, "search", "not a dict")

    def test_parse_action_handles_prose_fences_and_braces_in_strings(self):
        self.assertEqual(INV.parse_action('Sure!\n```json\n{"thought":"a {b}","action":"search","args":{"text":"x}y"}}\n```')["args"]["text"], "x}y")
        self.assertIsNone(INV.parse_action("no json here"))
        self.assertIsNone(INV.parse_action('{"thought":"missing action"}'))


class LoopTests(unittest.TestCase):
    def test_full_run_records_a_real_trace(self):
        ask = scripted(act("overview"), act("host", name="DEMO-WS01"), act("finish", report="1. Credentials were dumped on DEMO-WS01. " * 6))
        res = INV.investigate(rows(), ask, "", 6)
        kinds = [s["kind"] for s in res["steps"]]
        self.assertEqual(kinds[0], "user")
        self.assertEqual(kinds.count("tool_call"), 3)
        self.assertEqual(kinds.count("tool_result"), 2)
        self.assertEqual(res["steps"][-1]["label"], "report")
        self.assertEqual([s["i"] for s in res["steps"]], list(range(len(res["steps"]))))
        self.assertIn("UNTRUSTED DATA", ask.prompts[1])
        self.assertIn("<result>", ask.prompts[1])

    def test_repeat_calls_are_refused_and_loop_is_bounded(self):
        ask = scripted(*[act("overview")] * 3, "Final write-up " * 20)
        res = INV.investigate(rows(), ask, "", 3)
        results = [s["text"] for s in res["steps"] if s["kind"] == "tool_result"]
        self.assertIn("Already done", results[1])
        self.assertEqual(res["turns"], 3)
        self.assertIn("Final write-up", res["report"])

    def test_short_or_empty_report_triggers_a_proper_writeup(self):
        ask = scripted(act("overview"), act("finish"), "1. Step one.\n2. Step two. " + "detail " * 30)
        res = INV.investigate(rows(), ask, "", 5)
        self.assertIn("Step two", res["report"])
        self.assertIn("<evidence>", ask.prompts[-1])

    def test_prose_reply_becomes_the_report_after_one_retry(self):
        ask = scripted("I think it was bad.", "Still not JSON.")
        res = INV.investigate(rows(), ask, "", 4)
        self.assertEqual(len(ask.prompts), 3)               # the action, one JSON retry, then a last attempt at a proper write-up (which fails here)
        self.assertIn("I think it was bad", res["report"])

    def test_focus_reaches_the_model(self):
        ask = scripted(act("finish", report="x" * 200))
        INV.investigate(rows(), ask, "PC01", 3)
        self.assertIn("PC01", ask.prompts[0])


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.token = server.make_server(0)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.job = cls.post("/api/demo", {})[1]["job"]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    @classmethod
    def req(cls, path, body=None):
        url = f"http://127.0.0.1:{cls.port}{path}{'&' if '?' in path else '?'}token={cls.token}"
        r = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(r) as x:
                return x.status, json.load(x)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    post = req

    def wait(self, jid):
        for _ in range(100):
            code, s = self.req(f"/api/status?job={jid}")
            if s["state"] != "running":
                return s
            time.sleep(0.1)
        self.fail("job did not finish")

    def test_investigate_job_end_to_end_with_a_fake_model(self):
        replies = iter([act("overview"), act("search", text="svc.backup"), act("finish", report="1. The account svc.backup touched several computers. " * 5)])
        with mock.patch.object(server.LLM, "chat", side_effect=lambda *a, **k: next(replies)):
            code, r = self.post("/api/investigate", {"job": self.job, "ai": {"provider": "ollama", "model": "m"}, "steps": 5})
            self.assertEqual(code, 200)
            s = self.wait(r["job"])
        self.assertEqual(s["state"], "done")
        a = s["agent"]
        self.assertTrue(a["investigated"])
        self.assertIn("svc.backup", a["report"])
        self.assertEqual(a["steps"][0]["kind"], "user")
        self.assertTrue(all(-1.0001 <= st[k] <= 1.0001 for st in a["steps"] for k in "xyz"))
        self.assertEqual(self.req("/api/share", {"source": "agent", "id": a["id"], "action": "preview"})[0], 200)

    def test_online_provider_needs_consent_and_a_loaded_result(self):
        r = self.post("/api/investigate", {"job": self.job, "ai": {"provider": "openai"}})[1]
        s = self.wait(r["job"])
        self.assertEqual(s["state"], "error")
        self.assertIn("tick the box", s["error"].lower())
        self.assertEqual(self.post("/api/investigate", {"job": "nope", "ai": {"provider": "ollama"}})[0], 400)

    def test_explain_evtx_and_chain(self):
        with mock.patch.object(server.LLM, "chat", return_value="1. It happened.") as m:
            code, r = self.post("/api/explain/evtx", {"job": self.job, "focus": "DEMO-DC01", "ai": {"provider": "ollama", "model": "m"}})
        self.assertEqual((code, r["text"]), (200, "1. It happened."))
        self.assertIn("DEMO-DC01", m.call_args[0][1])
        code, c = self.req(f"/api/chain?job={self.job}")
        self.assertEqual(code, 200)
        self.assertTrue(c["stages"])
        self.assertEqual(self.post("/api/explain/evtx", {"job": self.job, "ai": {"provider": "claude-code"}})[0], 400)

    def test_session_key_is_held_in_memory_and_never_returned(self):
        try:
            code, r = self.post("/api/llm/key", {"provider": "openai", "key": "sk-session-secret-1"})
            self.assertEqual(code, 200)
            self.assertEqual(r["keys"]["openai"], "session")
            dump = json.dumps(self.req("/api/llm")[1]) + json.dumps(self.req("/api/llm/activity")[1])
            self.assertNotIn("sk-session-secret-1", dump)
            self.assertEqual(LLM.resolve("openai")[1], "sk-session-secret-1")
            self.assertEqual(self.post("/api/llm/key", {"provider": "ollama", "key": "x"})[0], 400)
        finally:
            self.post("/api/llm/key", {"provider": "openai", "key": ""})
        self.assertEqual(self.req("/api/llm")[1]["keys"]["openai"] in ("", "env"), True)


class AILayerTests(unittest.TestCase):
    def test_activity_log_records_chat_and_failures(self):
        before = time.time()
        with mock.patch.object(LLM, "_chat", return_value="hi"):
            LLM.chat("ollama", "p", model="m")
        with mock.patch.object(LLM, "_chat", side_effect=LLM.LLMError("boom")):
            with self.assertRaises(LLM.LLMError):
                LLM.chat("openai", "p")
        msgs = [a["msg"] for a in LLM.activity(before)]
        self.assertTrue(any("answered" in m for m in msgs))
        self.assertTrue(any("boom" in m for m in msgs))

    def test_autostart_when_not_installed_says_so_and_does_not_start_anything(self):
        before = time.time()
        down = {"installed": False, "running": False, "models": [], "pullable": {}}
        with mock.patch.object(LLM, "local_status", return_value=down), mock.patch.object(LLM, "start_ollama") as st:
            LLM.autostart()
        st.assert_not_called()
        self.assertTrue(any("not installed" in a["msg"] for a in LLM.activity(before)))

    def test_autostart_starts_then_verifies_embeddings(self):
        before = time.time()
        states = iter([{"installed": True, "running": False, "models": [], "pullable": {}}, {"installed": True, "running": True, "models": ["all-minilm:latest", "phi3:latest"], "pullable": {}}])
        with mock.patch.object(LLM, "local_status", side_effect=lambda *a, **k: next(states)), mock.patch.object(LLM, "start_ollama") as st, mock.patch.object(LLM, "embed", return_value=[[0.1]]) as em:
            LLM.autostart()
        st.assert_called_once()
        self.assertEqual(em.call_args.kwargs["model"], "all-minilm:latest")
        self.assertTrue(any("verified" in a["msg"] for a in LLM.activity(before)))

    def test_stop_started_only_stops_what_we_started(self):
        p = mock.Mock()
        p.poll.return_value = None
        LLM._STARTED["proc"] = p
        LLM.stop_started()
        p.terminate.assert_called_once()
        LLM._STARTED["proc"] = None
        LLM.stop_started()


if __name__ == "__main__":
    unittest.main()


class CLITests(unittest.TestCase):
    def test_help_lists_the_new_commands_and_no_fake_data_wording(self):
        import contextlib
        import io
        from hayabusa_lens import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--help"])
        text = out.getvalue()
        for flag in ("--agent", "--no-ai-start", "--get-rules", "--samples", "--install-hayabusa", "Ollama"):
            self.assertIn(flag, text)
        self.assertNotIn("fictional", text)

    def test_agent_flag_opens_the_agent_tab_link(self):
        with mock.patch.object(server, "make_server") as mk, mock.patch("webbrowser.open"), mock.patch.object(server.LLM, "autostart") as auto:
            httpd = mock.Mock()
            httpd.server_address = ("127.0.0.1", 1234)
            httpd.serve_forever.side_effect = KeyboardInterrupt
            mk.return_value = (httpd, "tok")
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                server.serve(0, False, None, False, False, "/tmp/x.jsonl", True)
            self.assertIn("agentpath=/tmp/x.jsonl", buf.getvalue())
            time.sleep(0.2)
            auto.assert_called()
            auto.reset_mock()
            with contextlib.redirect_stdout(buf):
                server.serve(0, False, None, False, False, None, False)
            time.sleep(0.2)
            auto.assert_not_called()
