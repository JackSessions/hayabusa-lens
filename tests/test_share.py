import io
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402
from hayabusa_lens import data as D
from hayabusa_lens import llm as LLM
from hayabusa_lens import server
from hayabusa_lens import share as SH
from hayabusa_lens import vectorchain as VC


def crit_row():
    rows = D.Dataset.from_dicts(fixtures.demo_dicts(), "d").rows
    return next(r for r in rows if r["lvl"] == 4 and r["details"].get("SrcIP"))


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FormatTests(unittest.TestCase):
    def test_ecs_event_has_the_fields_siems_search_on(self):
        e = SH.ecs_event(crit_row())
        self.assertEqual(e["event"]["kind"], "alert")
        self.assertEqual(e["event"]["severity"], 99)
        self.assertEqual(e["labels"]["level"], "critical")
        self.assertRegex(e["@timestamp"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
        self.assertEqual(e["source"]["ip"], "10.0.0.21")
        self.assertIn("T1003.001", e["threat"]["technique"]["id"])
        json.dumps(e)

    def test_cef_escapes_separators(self):
        e = SH.ecs_event(crit_row())
        e["rule"]["name"] = "a|b\\c"
        e["message"] = "x=y\nz"
        line = SH.cef(e)
        self.assertTrue(line.startswith("CEF:0|Jack Sessions|Hayabusa Lens|"))
        self.assertIn("a\\|b\\\\c", line)
        self.assertIn("msg=x\\=y z", line)
        self.assertEqual(line.count("\n"), 0)

    def test_audit_events_one_per_question(self):
        a = {"label": "AI investigation of x", "audit": [{"n": 1, "t": 1700000000.5, "ms": 1200, "kind": "turn", "question": "Where should I start?", "answer": "{}", "action": "overview", "args": "{}", "result": "Alerts: 3", "ai": "ollama"},
                                                          {"n": 2, "t": 1700000003.0, "ms": 800, "kind": "turn", "question": "What next?", "answer": "{}", "action": "finish", "args": "{}", "result": "Finished", "ai": "ollama"}]}
        ev = SH.audit_events(a)
        self.assertEqual(len(ev), 2)
        self.assertEqual(ev[0]["event"]["dataset"], "hayabusa-lens.ai_audit")
        self.assertEqual(ev[0]["event"]["duration"], 1_200_000_000)
        self.assertIn("overview", ev[0]["message"])
        json.dumps(ev)

    def test_select_limit_and_level(self):
        rows = D.Dataset.from_dicts(fixtures.demo_dicts(), "d").rows
        self.assertTrue(all(r["lvl"] >= 3 for r in SH.select(rows, 3)))
        with mock.patch.object(SH, "MAX_EVENTS", 3):
            with self.assertRaises(SH.ShareError):
                SH.select(rows, 0)


class DestinationTests(unittest.TestCase):
    def events(self, n=3):
        return [SH.ecs_event(crit_row())] * n

    def test_url_rules(self):
        SH.check_url("https://siem.example.com:9200")
        SH.check_url("http://192.168.1.10:9200")
        SH.check_url("http://localhost:8088")
        for bad in ("http://siem.example.com", "ftp://x", "http://169.254.169.254/latest", "nonsense"):
            with self.assertRaises(SH.ShareError):
                SH.check_url(bad)

    def test_syslog_udp_and_tcp(self):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind(("127.0.0.1", 0))
        u.settimeout(3)
        self.assertEqual(SH.send_syslog(self.events(2), "127.0.0.1", u.getsockname()[1], "udp", "cef"), 2)
        msg = u.recvfrom(9000)[0].decode()
        self.assertRegex(msg, r"^<\d+>1 \d{4}-.* hayabusa-lens - - - CEF:0\|")
        u.close()
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        got = []

        def accept():
            c, _ = srv.accept()
            got.append(c.makefile().read())
            c.close()
        t = threading.Thread(target=accept)
        t.start()
        SH.send_syslog(self.events(2), "127.0.0.1", srv.getsockname()[1], "tcp", "json")
        t.join(3)
        srv.close()
        lines = got[0].strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0].split(" - - - ", 1)[1])["event"]["kind"], "alert")

    def test_syslog_unreachable_is_a_clean_error(self):
        with self.assertRaises(SH.ShareError):
            SH.send_syslog(self.events(1), "127.0.0.1", 1, "tcp")

    def test_elastic_bulk_format_and_auth(self):
        seen = {}

        def op(req, timeout=0):
            seen.update(url=req.full_url, auth=req.get_header("Authorization"), ctype=req.get_header("Content-type"), body=req.data.decode())
            return Resp(b'{"errors":false}')
        self.assertEqual(SH.post(self.events(3), "elastic", "http://localhost:9200", "ApiKey abc", "my-index", opener=op), 3)
        self.assertEqual(seen["url"], "http://localhost:9200/_bulk")
        self.assertEqual((seen["auth"], seen["ctype"]), ("ApiKey abc", "application/x-ndjson"))
        lines = seen["body"].strip().splitlines()
        self.assertEqual(json.loads(lines[0]), {"create": {"_index": "my-index"}})
        self.assertEqual(len(lines), 6)

    def test_elastic_partial_failure_is_reported(self):
        with self.assertRaises(SH.ShareError):
            SH.post(self.events(1), "elastic", "http://localhost:9200", opener=lambda r, timeout=0: Resp(b'{"errors":true}'))

    def test_splunk_and_webhook(self):
        seen = []
        op = lambda req, timeout=0: (seen.append((req.full_url, req.get_header("Authorization"), req.data.decode())), Resp(b"{}"))[1]
        SH.post(self.events(2), "splunk", "https://splunk.example.com:8088", "Splunk tok", opener=op)
        self.assertEqual(seen[0][0], "https://splunk.example.com:8088/services/collector/event")
        self.assertEqual(seen[0][1], "Splunk tok")
        self.assertEqual(json.loads(seen[0][2].split("}{")[0] + ("}" if "}{" in seen[0][2] else ""))["sourcetype"], "hayabusa-lens")
        SH.post(self.events(2), "webhook", "https://hooks.example.com/x", opener=op)
        self.assertEqual(len(json.loads(seen[1][2])), 2)

    def test_batches_of_500(self):
        n = []
        SH.post(self.events(1200), "webhook", "http://localhost:1", opener=lambda req, timeout=0: (n.append(len(json.loads(req.data))), Resp(b"{}"))[1])
        self.assertEqual(n, [500, 500, 200])

    def test_http_error_never_leaks_credentials(self):
        def op(req, timeout=0):
            raise urllib.error.HTTPError(req.full_url, 401, "no", {}, io.BytesIO(b"bad token SECRET123"))
        with self.assertRaises(SH.ShareError) as cm:
            SH.post(self.events(1), "webhook", "http://localhost:1", "Bearer SECRET123", opener=op)
        self.assertNotIn("SECRET123", str(cm.exception))

    def test_file_append(self):
        p = os.path.join(tempfile.mkdtemp(), "sub", "a.ndjson")
        SH.write_file(self.events(2), p)
        SH.write_file(self.events(1), p)
        self.assertEqual(len(open(p).read().splitlines()), 3)


class ShareServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.token = server.make_server(0)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.job = fixtures.make_job(server)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    @classmethod
    def post(cls, path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{cls.port}{path}?token={cls.token}", data=json.dumps(body).encode(), method="POST")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_preview_never_sends_and_send_needs_confirmation(self):
        code, r = self.post("/api/share", {"job": self.job, "minLevel": 3, "action": "preview"})
        self.assertEqual(code, 200)
        self.assertGreater(r["count"], 0)
        self.assertEqual(len(r["sample"]), 2)
        self.assertNotIn("sent", r)
        p = os.path.join(tempfile.mkdtemp(), "o.ndjson")
        code, r = self.post("/api/share", {"job": self.job, "minLevel": 3, "action": "send", "dest": {"type": "file", "path": p}})
        self.assertEqual(code, 400)
        self.assertFalse(os.path.exists(p))
        code, r = self.post("/api/share", {"job": self.job, "minLevel": 3, "action": "send", "confirm": True, "dest": {"type": "file", "path": p}})
        self.assertEqual((code, r["sent"] > 0), (200, True))
        self.assertEqual(len(open(p).read().splitlines()), r["sent"])

    def test_download_formats(self):
        for fmt, marker in (("ndjson", '"kind": "alert"'), ("cef", "CEF:0|")):
            url = f"http://127.0.0.1:{self.port}/api/share/download?token={self.token}&job={self.job}&minLevel=4&fmt={fmt}"
            with urllib.request.urlopen(url) as r:
                self.assertIn("attachment", r.headers["Content-Disposition"])
                self.assertIn(marker, r.read().decode())

    def test_audit_trail_can_be_shared_and_bad_destination_refused(self):
        replies = iter([json.dumps({"thought": "t", "action": "overview", "args": {}}), json.dumps({"thought": "t", "action": "finish", "args": {"report": "x" * 200}})])
        with mock.patch.object(server.LLM, "chat", side_effect=lambda *a, **k: next(replies)):
            _, r = self.post("/api/investigate", {"job": self.job, "ai": {"provider": "ollama", "model": "m"}, "steps": 4})
            for _ in range(400):
                code, s = self.get(f"/api/status?job={r['job']}")
                if s["state"] != "running":
                    break
                time.sleep(0.1)
        code, p = self.post("/api/share", {"source": "audit", "id": s["agent"]["id"], "action": "preview"})
        self.assertEqual((code, p["count"]), (200, 2))
        code, r = self.post("/api/share", {"job": self.job, "action": "send", "confirm": True, "dest": {"type": "elastic", "url": "http://siem.example.com"}})
        self.assertEqual(code, 400)
        self.assertIn("plain http", r["error"])

    @classmethod
    def get(cls, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{cls.port}{path}&token={cls.token}") as x:
            return x.status, json.load(x)


class ClaudeCodeTests(unittest.TestCase):
    def fake_claude(self, reply="looks injected", code=0):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "claude")
        with open(path, "w") as f:
            f.write(f"#!{sys.executable}\nimport sys,json\nopen(sys.argv[0]+'.args','w').write(json.dumps(sys.argv[1:]+[sys.stdin.read()[:40]]))\nprint({reply!r})\nsys.exit({code})\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        return path

    def test_runs_with_all_tools_disabled(self):
        exe = self.fake_claude()
        steps = VC.analyze(VC.parse_trace(fixtures.demo_trace()))["steps"]
        with mock.patch.object(LLM, "claude_code_path", return_value=exe):
            self.assertEqual(LLM.explain("claude-code", steps), "looks injected")
        args = json.loads(open(exe + ".args").read())
        self.assertEqual(args[args.index("--tools") + 1], "")
        self.assertIn("--no-session-persistence", args)
        self.assertIn("You are reviewing", args[-1])

    def test_missing_and_failing(self):
        with mock.patch.object(LLM, "claude_code_path", return_value=""):
            with self.assertRaises(LLM.LLMError):
                LLM.explain("claude-code", [])
        with mock.patch.object(LLM, "claude_code_path", return_value=self.fake_claude(code=1)):
            with self.assertRaises(LLM.LLMError):
                LLM._claude_code("hi")

    def test_status_picks_the_most_private_working_option(self):
        up = {"installed": True, "running": True, "models": ["all-minilm:latest", "phi3:latest"], "pullable": {}}
        down = {"installed": False, "running": False, "models": [], "pullable": {}}
        with mock.patch.object(LLM, "local_status", return_value=up), mock.patch.object(LLM, "claude_code_path", return_value="/x/claude"):
            r = LLM.status()["recommend"]
            self.assertEqual((r["explain"]["provider"], r["explain"]["model"], r["embed"]["provider"], r["embed"]["model"]), ("ollama", "phi3:latest", "ollama", "all-minilm:latest"))
        with mock.patch.object(LLM, "local_status", return_value=down), mock.patch.object(LLM, "claude_code_path", return_value="/x/claude"):
            r = LLM.status()["recommend"]
            self.assertEqual((r["explain"]["provider"], r["embed"]["provider"]), ("claude-code", "local"))
        with mock.patch.object(LLM, "local_status", return_value=down), mock.patch.object(LLM, "claude_code_path", return_value=""), mock.patch.dict(os.environ, {"OPENAI_API_KEY": "k"}):
            self.assertEqual(LLM.status()["recommend"]["explain"]["provider"], "openai")
        with mock.patch.object(LLM, "local_status", return_value=down), mock.patch.object(LLM, "claude_code_path", return_value=""), mock.patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(LLM.status()["recommend"]["explain"])

    def test_connection_test(self):
        op = lambda req, timeout=0: Resp(json.dumps({"data": [{"index": 0, "embedding": [0.0] * 8}]}).encode())
        self.assertEqual(LLM.test("ollama", "embed", opener=op)["detail"], "got a 8-number vector")


if __name__ == "__main__":
    unittest.main()
