"""Hayabusa has changed its command names over time. These tests run stand-in programs for each generation."""
import os
import stat
import sys
import tempfile
import threading
import unittest
import json
import time
import urllib.request

from hayabusa_lens import data as D
from hayabusa_lens import runner as R
from hayabusa_lens import server
from hayabusa_lens import tools as T

SCRIPT = """#!{py}
import sys, json, os
a = sys.argv[1:]
style = {style!r}
cmds = {cmds!r}
if a[:1] == ["help"]:
    print("Hayabusa v" + {ver!r} + " - Test\\nCommands:\\n" + "\\n".join("  " + c for c in cmds)); sys.exit(0)
out = a[a.index("-o") + 1] if "-o" in a else None
row = {{"Timestamp": "2024-05-01T10:00:00.000000Z", "RuleTitle": "Style Alert", "Level": "high", "Computer": "PC", "Channel": "Sec", "EventID": 4625, "MitreTactics": ["CredAccess"], "MitreTags": ["T1110"], "RecordID": 1, "Details": {{"User": "bob"}}}}
if a[0] == "dfir-timeline":
    assert "jsonl" in a, a
    open(out, "w").write(json.dumps(row))
elif a[0] == "json-timeline":
    assert "-L" in a, a
    open(out, "w").write(json.dumps(row))
elif a[0] == "csv-timeline":
    open(out, "w").write('"Timestamp","RuleTitle","Level","Computer","Channel","EventID","MitreTactics","Details"\\n"2024-05-01 10:00:00.000 +00:00","Style Alert","high","PC","Sec",4625,"CredAccess","User: bob"\\n')
elif a[0] == "search":
    kws = [a[i + 1] for i, x in enumerate(a) if x == "-k"]
    rx = a[a.index("-r") + 1] if "-r" in a else ""
    head = "Timestamp,EventTitle,Hostname,Channel,Event ID,Record ID,AllFieldInfo,EvtxFile\\n"
    info = "kw=" + "|".join(kws) + " rx=" + rx + " and=" + str("-a" in a) + " i=" + str("-i" in a)
    hit = (kws or rx) and "nomatch" not in kws
    open(out, "w").write(head + (("2024-05-01 10:00:00,Logon,PC,Sec,4624,1," + chr(34) + info + chr(34) + ",x.evtx\\n") if hit else ""))
elif a[0] == "eid-metrics":
    open(out, "w").write("Total,%,Channel,ID,Event\\n5,50%,Sec,4624,Logon\\n")
elif a[0] == "logon-summary":
    open(out + "-successful.csv", "w").write("Successful,Target Account\\n3,bob\\n")
    open(out + "-failed.csv", "w").write("Failed,Target Account\\n1,eve\\n")
else:
    sys.exit(2)
"""


def fake(tmp, style, cmds, ver="1.0.0"):
    p = os.path.join(tmp, "hayabusa")
    with open(p, "w") as f:
        f.write(SCRIPT.format(py=sys.executable, style=style, cmds=cmds, ver=ver))
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    return p


@unittest.skipIf(os.name == "nt", "stand-in programs are shell-script style executables")
class StyleTests(unittest.TestCase):
    def check_style(self, cmds, expect_style):
        with tempfile.TemporaryDirectory() as d:
            logs = os.path.join(d, "logs")
            os.makedirs(logs)
            path = fake(d, expect_style, cmds)
            info = R.probe(path)
            self.assertEqual(info["style"], expect_style)
            out = R.scan(info, logs, "informational", False, [])
            try:
                ds = D.Dataset.load(out)
            finally:
                os.unlink(out)
            self.assertEqual(ds.summary()["total"], 1)
            self.assertEqual(ds.rows[0]["title"], "Style Alert")
            self.assertEqual(ds.rows[0]["tactics"], ["Credential Access"])

    def test_current_dfir_timeline(self):
        self.check_style(["dfir-timeline", "eid-metrics", "logon-summary"], "dfir")

    def test_older_json_timeline(self):
        self.check_style(["csv-timeline", "json-timeline", "eid-metrics"], "legacy")

    def test_oldest_csv_timeline_only(self):
        self.check_style(["csv-timeline", "eid-metrics"], "csv")

    def test_unknown_version_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            info = R.probe(fake(d, "none", ["something-else"]))
            self.assertIsNone(info["style"])
            with self.assertRaises(R.HayabusaError):
                R.build_command(info, d, "/tmp/o")

    def test_tools_are_detected_and_run(self):
        with tempfile.TemporaryDirectory() as d:
            info = R.probe(fake(d, "dfir", ["dfir-timeline", "eid-metrics", "logon-summary"]))
            self.assertEqual(sorted(info["tools"]), ["eid-metrics", "logon-summary"])
            tabs = T.run_tool(info, "eid-metrics", d, [])
            self.assertEqual((tabs[0]["header"][:2], tabs[0]["rows"][0][:2], tabs[0]["total"]), (["Total", "%"], ["5", "50%"], 1))
            tabs = T.run_tool(info, "logon-summary", d, [])
            self.assertEqual([t["title"] for t in tabs], ["Successful logons", "Failed logons"])
            with self.assertRaises(R.HayabusaError):
                T.run_tool(info, "computer-metrics", d, [])
            with self.assertRaises(R.HayabusaError):
                T.build_command(info, "eid-metrics", "relative/path", "/tmp/o")

    def test_search_builds_the_right_command_and_reads_results(self):
        with tempfile.TemporaryDirectory() as d:
            info = R.probe(fake(d, "dfir", ["dfir-timeline", "search"]))
            self.assertIn("search", info["tools"])
            t = T.run_search(info, d, ["4624", "admin"], "", True, True, [])[0]
            self.assertEqual(t["rows"][0][4], "4624")
            self.assertIn("kw=4624|admin", t["rows"][0][6])
            self.assertIn("and=True", t["rows"][0][6])
            rx = T.run_search(info, d, [], "ALICE.*", False, True, [])[0]
            self.assertIn("rx=(?i)ALICE.*", rx["rows"][0][6], "regex mode must use an inline flag, because -r cannot be combined with -i")
            self.assertIn("i=False", rx["rows"][0][6])
            self.assertEqual(T.run_search(info, d, ["nomatch"], "", False, True, [])[0]["rows"], [["No events matched."]])
            with self.assertRaises(R.HayabusaError):
                T.run_search(info, d, [], "", False, True, [])
            with self.assertRaises(R.HayabusaError):
                T.search_command({"path": "h", "tools": []}, d, "/tmp/o", ["x"])

    def test_the_summaries_api_returns_tables(self):
        with tempfile.TemporaryDirectory() as d:
            server.STATE["hayabusa"] = fake(d, "dfir", ["dfir-timeline", "eid-metrics"])
            httpd, token = server.make_server(0)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            try:
                def call(path, body=None):
                    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), method="POST" if body is not None else "GET", headers={"X-HL-Token": token})
                    with urllib.request.urlopen(req) as r:
                        return json.loads(r.read())
                info = call("/api/hayabusa")
                self.assertIn("eid-metrics", info["tools"])
                self.assertIn("eid-metrics", info["tool_info"])
                job = call("/api/tool", {"tool": "eid-metrics", "path": d})["job"]
                for _ in range(100):
                    s = call(f"/api/status?job={job}")
                    if s["state"] != "running":
                        break
                    time.sleep(0.05)
                self.assertEqual(s["state"], "done", s)
                self.assertEqual(s["tables"][0]["rows"][0][3], "4624")
            finally:
                httpd.shutdown()
                httpd.server_close()
                server.STATE["hayabusa"] = None


if __name__ == "__main__":
    unittest.main()
