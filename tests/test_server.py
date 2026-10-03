import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

from hayabusa_lens import data as D
from hayabusa_lens import runner as R
from hayabusa_lens import server

FAKE = """#!{py}
import sys, json
a = sys.argv[1:]
if a[:1] == ["help"]:
    print("Hayabusa v9.9.9 - Test Release\\nCommands:\\n  dfir-timeline  Create a DFIR timeline"); sys.exit(0)
if a[:1] == ["update-rules"]:
    print("rules are up to date"); sys.exit(0)
if a[:1] == ["dfir-timeline"]:
    out = a[a.index("-o") + 1]
    rows = [
        {{"Timestamp": "2024-05-01T10:00:00.000000Z", "RuleTitle": "Fake Alert", "Level": "high", "Computer": "FAKE-PC", "Channel": "Sec", "EventID": 4625, "MitreTactics": ["CredAccess"], "MitreTags": ["T1110"], "OtherTags": [], "RecordID": 1, "Details": {{"User": "bob"}}, "ExtraFieldInfo": {{}}, "RuleFile": "f.yml", "RuleID": "x", "EvtxFile": a[2]}},
        {{"Timestamp": "2024-05-01T10:05:00.000000Z", "RuleTitle": "Proc Exec", "Level": "info", "Computer": "FAKE-PC", "Channel": "Sysmon", "EventID": 1, "MitreTactics": [], "MitreTags": [], "OtherTags": [], "RecordID": 2, "Details": {{"Cmdline": "x.exe"}}, "ExtraFieldInfo": {{}}, "RuleFile": "g.yml", "RuleID": "y", "EvtxFile": a[2]}},
    ]
    open(out, "w").write("\\n".join(json.dumps(r) for r in rows))
    print("done"); sys.exit(0)
sys.exit(2)
"""


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.fake = os.path.join(cls.tmp, "hayabusa")
        with open(cls.fake, "w") as f:
            f.write(FAKE.format(py=sys.executable))
        os.chmod(cls.fake, os.stat(cls.fake).st_mode | stat.S_IEXEC)
        cls.logs = os.path.join(cls.tmp, "logs")
        os.makedirs(cls.logs)
        server.STATE["hayabusa"] = cls.fake if os.name != "nt" else None
        cls.httpd, cls.token = server.make_server(0)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        server.STATE["hayabusa"] = None

    def call(self, path, body=None, token=True, host=None):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(), method="POST" if body is not None else "GET")
        if token:
            req.add_header("X-HL-Token", self.token)
        if host:
            req.add_header("Host", host)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def finish(self, job):
        for _ in range(200):
            _, raw = self.call(f"/api/status?job={job}")
            s = json.loads(raw)
            if s["state"] != "running":
                return s
            time.sleep(0.05)
        self.fail("job did not finish")

    def test_requires_token_and_local_host(self):
        self.assertEqual(self.call("/api/hayabusa", token=False)[0], 403)
        self.assertEqual(self.call("/", host="evil.example.com")[0], 403)
        self.assertEqual(self.call(f"/?token={self.token}")[0], 200)

    def test_demo_query_filter_event_and_export(self):
        _, raw = self.call("/api/demo", {})
        job = json.loads(raw)["job"]
        self.assertEqual(self.finish(job)["state"], "done")
        _, raw = self.call(f"/api/query?job={job}&levels=3,4&sort=level&limit=5")
        q = json.loads(raw)
        self.assertTrue(q["total"] > 0 and all(r["lvl"] >= 3 for r in q["rows"]))
        self.assertEqual(q["rows"][0]["lvl"], 4)
        self.assertIn("rules", q["facets"])
        _, raw = self.call(f"/api/event?job={job}&i={q['rows'][0]['i']}")
        ev = json.loads(raw)
        self.assertEqual(ev["level"], "critical")
        _, raw = self.call(f"/api/query?job={job}&q=lsass&levels=0,1,2,3,4")
        self.assertTrue(all("LSASS" in r["title"] for r in json.loads(raw)["rows"]))
        for fmt, needle in (("csv", "Timestamp(UTC)"), ("json", "title"), ("html", "Hayabusa Lens")):
            code, body = self.call(f"/api/export?job={job}&fmt={fmt}&levels=4")
            self.assertEqual(code, 200)
            self.assertIn(needle, body.decode())

    def test_open_an_existing_results_file(self):
        path = os.path.join(self.tmp, "r.jsonl")
        with open(path, "w") as f:
            f.write("\n".join(json.dumps(r) for r in [{"Timestamp": "2024-01-01T00:00:00Z", "RuleTitle": "X", "Level": "med", "Computer": "C"}]))
        _, raw = self.call("/api/open", {"path": path})
        s = self.finish(json.loads(raw)["job"])
        self.assertEqual((s["state"], s["summary"]["total"]), ("done", 1))
        _, raw = self.call("/api/open", {"path": os.path.join(self.tmp, "missing.csv")})
        self.assertEqual(self.finish(json.loads(raw)["job"])["state"], "error")

    @unittest.skipIf(os.name == "nt", "the stand-in Hayabusa is a shell-script style executable")
    def test_scan_runs_hayabusa_as_a_subprocess(self):
        _, raw = self.call("/api/hayabusa")
        info = json.loads(raw)
        self.assertEqual((info["found"], info["version"], info["style"]), (True, "9.9.9", "dfir"))
        _, raw = self.call("/api/scan", {"path": self.logs, "minLevel": "low"})
        s = self.finish(json.loads(raw)["job"])
        self.assertEqual(s["state"], "done", s)
        self.assertEqual(s["summary"]["total"], 2)

    @unittest.skipIf(os.name == "nt", "the stand-in Hayabusa is a shell-script style executable")
    def test_scan_errors_are_reported(self):
        _, raw = self.call("/api/scan", {"path": os.path.join(self.tmp, "nope")})
        s = self.finish(json.loads(raw)["job"])
        self.assertEqual(s["state"], "error")
        self.assertIn("not found", s["error"].lower())

    def test_directory_listing(self):
        _, raw = self.call("/api/ls?path=" + urllib.request.quote(self.tmp))
        self.assertIn("logs", {e["name"] for e in json.loads(raw)["entries"]})


class RunnerTests(unittest.TestCase):
    def test_build_command_for_both_command_styles(self):
        with tempfile.TemporaryDirectory() as d:
            new = R.build_command({"path": "/x/hayabusa", "style": "dfir"}, d, "/tmp/o.jsonl", "high", True)
            self.assertEqual(new[1:5], ["dfir-timeline", "-d", d, "-t"])
            self.assertIn("-m", new)
            self.assertIn("-n", new)
            old = R.build_command({"path": "/x/hayabusa", "style": "legacy"}, d, "/tmp/o.jsonl")
            self.assertEqual(old[1], "json-timeline")
            self.assertIn("-L", old)

    def test_rejects_relative_and_missing_paths(self):
        with self.assertRaises(R.HayabusaError):
            R.build_command({"path": "h", "style": "dfir"}, "relative/path", "/tmp/o")
        with self.assertRaises(R.HayabusaError):
            R.build_command({"path": "h", "style": None}, "/tmp", "/tmp/o")

    def test_filters_parse_safely(self):
        f = server.parse_filters({"levels": ["3,4,x,9"], "frm": ["abc"], "q": ["a" * 500]})
        self.assertEqual(f["levels"], {3, 4})
        self.assertIsNone(f["frm"])
        self.assertEqual(len(f["q"]), 200)


if __name__ == "__main__":
    unittest.main()
