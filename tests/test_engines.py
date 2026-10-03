"""Chainsaw support, the rule viewer, compare, and themes."""
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
import io
import zipfile
import hashlib

from hayabusa_lens import chainsaw as CS
from hayabusa_lens import compare as CP
from hayabusa_lens import data as D
from hayabusa_lens import install as I
from hayabusa_lens import rulesidx as RI
from hayabusa_lens import server
from hayabusa_lens.page import PAGE

CS_DOC = {"group": "Sigma", "kind": "individual", "name": "Security Audit Logs Cleared", "timestamp": "2024-05-01T10:00:00.000000+00:00", "authors": ["someone"], "level": "critical", "status": "stable", "source": "chainsaw",
          "document": {"kind": "evtx", "path": "/logs/Security.evtx", "data": {"Event": {"System": {"EventID": 1102, "Computer": "PC1", "Channel": "Security", "EventRecordID": 7, "TimeCreated_attributes": {"SystemTime": "2024-05-01T10:00:00Z"}},
                                                                                         "UserData": {"LogFileCleared": {"SubjectUserName": "admin"}, "LogFileCleared_attributes": {"xmlns": "x"}}}}}}

RULE = """title: Security Audit Logs Cleared
id: 11111111-2222-3333-4444-555555555555
status: stable
level: high
tags:
  - attack.defense_evasion
  - attack.t1070.001
logsource:
  product: windows
detection:
  selection:
    EventID: 1102
  condition: selection
"""

FAKE_CS = """#!{py}
import sys, json
a = sys.argv[1:]
if a[:1] == ["--version"]:
    print("chainsaw 9.9.9"); sys.exit(0)
if a[:1] == ["hunt"]:
    out = a[a.index("-o") + 1]
    open(out, "w").write(json.dumps({doc!r}) if False else {line!r})
    sys.exit(0)
sys.exit(2)
"""


def make_chainsaw(tmp, ready=True):
    p = os.path.join(tmp, "chainsaw")
    with open(p, "w") as f:
        f.write(FAKE_CS.format(py=sys.executable, doc=CS_DOC, line=json.dumps(CS_DOC) + "\n"))
    os.chmod(p, os.stat(p).st_mode | stat.S_IEXEC)
    if ready:
        os.makedirs(os.path.join(tmp, "sigma"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "mappings"), exist_ok=True)
        open(os.path.join(tmp, "mappings", "sigma-event-logs-all.yml"), "w").write("kind: evtx\n")
        with open(os.path.join(tmp, "sigma", "audit_cleared.yml"), "w") as f:
            f.write(RULE)
    return p


class ConversionTests(unittest.TestCase):
    def test_chainsaw_detections_become_rows(self):
        ds = D.Dataset.from_dicts([CS_DOC])
        r = ds.rows[0]
        self.assertEqual((r["title"], r["lvl"], r["comp"], r["chan"], r["eid"], r["rid"]), ("Security Audit Logs Cleared", 4, "PC1", "Security", "1102", "7"))
        self.assertEqual(r["details"], {"SubjectUserName": "admin"})
        self.assertIn("Sigma", r["other"])
        self.assertEqual(r["evtx"], "/logs/Security.evtx")


class RuleIndexTests(unittest.TestCase):
    def test_index_find_search_and_safe_read(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "windows"))
            with open(os.path.join(d, "windows", "audit_cleared.yml"), "w") as f:
                f.write(RULE)
            with open(os.path.join(d, "notes.txt"), "w") as f:
                f.write("title: not a rule")
            ix = RI.RuleIndex([d])
            self.assertEqual(len(ix.entries), 1)
            e = ix.find(rule_id="11111111-2222-3333-4444-555555555555")
            self.assertEqual((e["title"], e["level"]), ("Security Audit Logs Cleared", "high"))
            self.assertIs(ix.find(title="security audit logs cleared"), e)
            self.assertIs(ix.find(rule_file="AUDIT_CLEARED.yml"), e)
            self.assertEqual(len(ix.search("audit t1070")), 1)
            self.assertEqual(ix.search("zzz"), [])
            self.assertIn("EventID: 1102", ix.read(e["path"]))
            self.assertIsNone(ix.read(os.path.join(d, "notes.txt")), "only indexed rule files may be served")
            self.assertIsNone(ix.read("/etc/passwd"))
            tech, tac = RI.mitre_from_tags(e["tags"])
            self.assertEqual((tech, tac), (["T1070.001"], ["Defense Evasion"]))


class CompareTests(unittest.TestCase):
    def rows(self, specs):
        return D.Dataset.from_dicts([{"Timestamp": "2024-01-01T10:00:%02dZ" % s, "RuleTitle": t, "Level": l, "Computer": "PC", "EventID": e, "RecordID": r, "Channel": "Sec"} for t, l, e, r, s in specs])

    def test_new_gone_and_unchanged(self):
        a = self.rows([("Rule A", "high", 1, 1, 1), ("Rule B", "low", 2, 2, 2)])
        b = self.rows([("Rule B", "low", 2, 2, 2), ("Rule C", "crit", 3, 3, 3)])
        c = CP.compare(a, b)
        self.assertEqual(c["counts"], {"new": 1, "gone": 1, "same": 1})
        self.assertEqual(c["new_levels"][4], 1)
        self.assertEqual(c["rules_only_in_b"], ["Rule C"])
        self.assertEqual(CP.compare(a, a)["counts"], {"new": 0, "gone": 0, "same": 2})

    def test_event_mode_ignores_which_rule_fired(self):
        a = self.rows([("Hayabusa rule", "high", 1, 1, 1)])
        b = self.rows([("Chainsaw rule", "high", 1, 1, 1)])
        self.assertEqual(CP.compare(a, b, "rule")["counts"]["same"], 0)
        self.assertEqual(CP.compare(a, b, "event")["counts"], {"new": 0, "gone": 0, "same": 1})


class InstallChainsawTests(unittest.TestCase):
    def test_triples(self):
        self.assertEqual(I.chainsaw_triple("Linux", "x86_64"), "x86_64-unknown-linux-gnu")
        self.assertEqual(I.chainsaw_triple("Windows", "AMD64"), "x86_64-pc-windows-msvc")
        with self.assertRaises(I.InstallError):
            I.chainsaw_triple("Windows", "arm64")

    def test_install_extracts_binary_and_rules_and_verifies_checksum(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("chainsaw/chainsaw_x86_64-unknown-linux-gnu", "#!/bin/sh\n")
            z.writestr("chainsaw/sigma/rule.yml", RULE)
            z.writestr("chainsaw/mappings/sigma-event-logs-all.yml", "kind: evtx\n")
        data = buf.getvalue()

        def opener(digest):
            release = {"tag_name": "v9.9.9", "assets": [{"name": "chainsaw_all_platforms+rules.zip", "size": len(data), "browser_download_url": "https://x.test/c.zip", "digest": digest}]}

            def op(req, timeout=0):
                url = req.full_url
                return type("R", (io.BytesIO,), {"__enter__": lambda s: s, "__exit__": lambda s, *a: False})(json.dumps(release).encode() if "api" in url else data)
            return op
        with tempfile.TemporaryDirectory() as d:
            p = I.install_chainsaw(d, opener=opener("sha256:" + hashlib.sha256(data).hexdigest()), system="Linux", machine="x86_64")
            self.assertTrue(os.access(p, os.X_OK))
            self.assertTrue(os.path.isfile(os.path.join(os.path.dirname(p), "mappings", "sigma-event-logs-all.yml")))
        with tempfile.TemporaryDirectory() as d, self.assertRaises(I.InstallError):
            I.install_chainsaw(d, opener=opener("sha256:" + "0" * 64), system="Linux", machine="x86_64")


@unittest.skipIf(os.name == "nt", "stand-in programs are shell-script style executables")
class ChainsawEngineTests(unittest.TestCase):
    def test_find_probe_and_scan(self):
        with tempfile.TemporaryDirectory() as d:
            p = make_chainsaw(d)
            self.assertEqual(CS.find_chainsaw(d), p)
            info = CS.probe(p)
            self.assertEqual((info["version"], info["ready"]), ("9.9.9", True))
            cmd = CS.build_command(info, d, "/tmp/o.jsonl")
            self.assertEqual(cmd[1:3], ["hunt", d])
            self.assertIn("--mapping", cmd)
            out = CS.scan(info, d, [])
            try:
                self.assertEqual(D.Dataset.load(out).summary()["total"], 1)
            finally:
                os.unlink(out)

    def test_not_ready_without_rules(self):
        with tempfile.TemporaryDirectory() as d:
            info = CS.probe(make_chainsaw(d, ready=False))
            self.assertFalse(info["ready"])
            with self.assertRaises(Exception):
                CS.build_command(info, d, "/tmp/o")

    def test_server_scan_enrich_rule_viewer_jobs_and_compare(self):
        with tempfile.TemporaryDirectory() as d:
            make_chainsaw(d)
            server.STATE["chainsaw"] = os.path.join(d, "chainsaw")
            server.STATE["hayabusa"] = None
            RI.invalidate()
            httpd, token = server.make_server(0)
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            try:
                def call(path, body=None):
                    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), method="POST" if body is not None else "GET", headers={"X-HL-Token": token})
                    with urllib.request.urlopen(req) as r:
                        return json.loads(r.read())

                def finish(job):
                    for _ in range(200):
                        s = call(f"/api/status?job={job}")
                        if s["state"] != "running":
                            return s
                        time.sleep(0.05)
                    self.fail("timeout")
                self.assertTrue(call("/api/hayabusa")["chainsaw"]["ready"])
                ja = call("/api/scan", {"path": d, "engine": "chainsaw"})["job"]
                self.assertEqual(finish(ja)["state"], "done")
                q = call(f"/api/query?job={ja}&levels=0,1,2,3,4")
                self.assertEqual(q["rows"][0]["tactics"], ["Defense Evasion"], "ATT&CK tactics come from the Sigma rule")
                rule = call(f"/api/rule?job={ja}&i=0")
                self.assertTrue(rule["found"])
                self.assertIn("EventID: 1102", rule["text"])
                self.assertEqual(list(rule["techniques"]), ["T1070.001"])
                self.assertIn("audit_cleared.yml", {r["file"] for r in call("/api/rules?q=audit")["rules"]})
                jb = call("/api/demo", {})["job"]
                finish(jb)
                jobs = call("/api/jobs")["jobs"]
                self.assertEqual(len(jobs), 2)
                cmp_ = call(f"/api/compare?a={ja}&b={jb}&which=new&mode=event")
                self.assertEqual(cmp_["counts"]["gone"], 1)
                self.assertTrue(cmp_["total"] > 0)
            finally:
                httpd.shutdown()
                httpd.server_close()
                server.STATE["chainsaw"] = None
                RI.invalidate()


class HelpTests(unittest.TestCase):
    def test_help_has_every_section_and_covers_each_tab(self):
        for sec in ("start", "dash", "tabs", "recipes", "ref", "fix", "about"):
            self.assertIn(f'data-h="{sec}"', PAGE)
        for topic in ("Scan logs", "Open results", "Summaries", "Search events", "Rules", "Compare", "Agent chain 3D", "Network map 3D", "The AI helper", "Investigate with AI", "Share", "Real samples", "4624", "Credential dumping"):
            self.assertIn(topic, PAGE, f"help should mention {topic}")


class UITests(unittest.TestCase):
    def test_tabs_hero_and_ai_controls_exist(self):
        for t in ("scan", "open", "tools", "search", "rules", "compare", "net", "agent", "share", "demo"):
            self.assertIn(f'data-t="{t}"', PAGE)
            self.assertIn(f'id="p-{t}"', PAGE)
        for i in ("hero", "aimodal", "aibtn", "aiseg", "aikeyset", "aitest", "aihint", "aifeed", "toast", "inv", "aexp", "nexplain", "shprev", "shsend", "shconfirm", "shdl1", "shdl2"):
            self.assertIn(f'id="{i}"', PAGE)
        self.assertIn("claude-code", PAGE)
        self.assertEqual(PAGE.count("<script>"), PAGE.count("</script>"))


class ThemeTests(unittest.TestCase):
    def test_three_themes_exist_and_colours_come_from_variables(self):
        self.assertIn(':root[data-theme="grey"]', PAGE)
        self.assertIn(':root[data-theme="light"]', PAGE)
        self.assertIn("setTheme", PAGE)
        self.assertIn("var(--l4)", PAGE)


if __name__ == "__main__":
    unittest.main()
