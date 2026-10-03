import sys
import json
import os
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fixtures  # noqa: E402
from hayabusa_lens import data as D

ROWS = [
    {"Timestamp": "2024-01-01T10:00:00.500000Z", "RuleTitle": "Proc Exec", "Level": "info", "Computer": "PC1", "Channel": "Sysmon", "EventID": 1, "MitreTactics": [], "MitreTags": [], "OtherTags": ["sysmon"], "RecordID": 1, "Details": {"Cmdline": "calc.exe"}, "ExtraFieldInfo": {}, "RuleFile": "a.yml", "RuleID": "1", "EvtxFile": "a.evtx"},
    {"Timestamp": "2024-01-01T11:00:00.000000Z", "RuleTitle": "Whoami Execution", "Level": "low", "Computer": "PC1", "Channel": "Sysmon", "EventID": 1, "MitreTactics": ["Disc"], "MitreTags": ["T1033"], "OtherTags": [], "RecordID": 2, "Details": {"Cmdline": "whoami /all"}, "ExtraFieldInfo": {}, "RuleFile": "b.yml", "RuleID": "2", "EvtxFile": "a.evtx"},
    {"Timestamp": "2024-01-01T12:30:00.000000Z", "RuleTitle": "Log Cleared", "Level": "high", "Computer": "DC1", "Channel": "Sec", "EventID": 1102, "MitreTactics": ["Stealth"], "MitreTags": ["T1070.001"], "OtherTags": [], "RecordID": 3, "Details": {"User": "admin"}, "ExtraFieldInfo": {}, "RuleFile": "c.yml", "RuleID": "3", "EvtxFile": "b.evtx"},
    {"Timestamp": "2024-01-01T12:45:00.000000Z", "RuleTitle": "LSASS Access", "Level": "crit", "Computer": "DC1", "Channel": "Sysmon", "EventID": 10, "MitreTactics": ["CredAccess"], "MitreTags": ["T1003.001"], "OtherTags": [], "RecordID": 4, "Details": "TargetImage: lsass.exe", "ExtraFieldInfo": "", "RuleFile": "d.yml", "RuleID": "4", "EvtxFile": "b.evtx"},
    {"Timestamp": "not a time", "RuleTitle": "Broken", "Level": "high"},
]


class DataTests(unittest.TestCase):
    def ds(self):
        return D.Dataset.from_dicts(ROWS, "test")

    def test_levels_are_normalised_and_bad_rows_skipped(self):
        s = self.ds().summary()
        self.assertEqual(s["levels"], [1, 1, 0, 1, 1])
        self.assertEqual((s["total"], s["skipped"]), (4, 1))

    def test_timestamp_parsing_handles_zones_and_fractions(self):
        z = D.parse_ts("2024-01-01T10:00:00Z")
        self.assertEqual(D.parse_ts("2024-01-01 19:00:00.000 +09:00"), z)
        self.assertEqual(D.parse_ts("2024-01-01T10:00:00.500000Z"), z + 500)
        self.assertEqual(D.iso(z), "2024-01-01 10:00:00")
        self.assertIsNone(D.parse_ts("yesterday"))

    def test_filters(self):
        ds = self.ds()
        self.assertEqual(len(ds.select({"levels": {3, 4}})), 2)
        self.assertEqual([r["title"] for r in ds.select({"q": "lsass"})], ["LSASS Access"])
        self.assertEqual(len(ds.select({"computer": "DC1"})), 2)
        self.assertEqual(len(ds.select({"tactic": "Stealth"})), 1)
        self.assertEqual(len(ds.select({"tag": "T1033"})), 1)
        self.assertEqual(len(ds.select({"frm": D.parse_ts("2024-01-01T12:00:00Z")})), 2)
        self.assertEqual(len(ds.select({"q": "whoami all"})), 1, "search words are ANDed")

    def test_facets_ignore_their_own_selection_so_alternatives_stay_visible(self):
        ds = self.ds()
        f = ds.facets({"levels": {0, 1, 2, 3, 4}, "computer": "DC1"})
        self.assertEqual({c["name"] for c in f["computers"]}, {"PC1", "DC1"})
        self.assertIn("Credential Access", {t["name"] for t in f["tactics"]})

    def test_timeline_buckets_cover_all_rows(self):
        tl = self.ds().timeline({"levels": {0, 1, 2, 3, 4}})
        self.assertEqual(sum(sum(b) for b in tl["buckets"]), 4)

    def test_loading_jsonl_json_and_csv(self):
        with tempfile.TemporaryDirectory() as d:
            jl, js, cs = (os.path.join(d, n) for n in ("a.jsonl", "a.json", "a.csv"))
            with open(jl, "w") as f:
                f.write("\n".join(json.dumps(r) for r in ROWS[:4]))
            with open(js, "w") as f:
                json.dump(ROWS[:4], f)
            with open(cs, "w", encoding="utf-8") as f:
                f.write('"Timestamp","RuleTitle","Level","Computer","Channel","EventID","MitreTactics","MitreTags","Details"\n'
                        '"2024-01-01 10:00:00.500 +00:00","Proc Exec","info","PC1","Sysmon",1,"Exec ¦ Persis","T1053.005","Cmdline: x ¦ User: y"\n')
            self.assertEqual(D.Dataset.load(jl).summary()["total"], 4)
            self.assertEqual(D.Dataset.load(js).summary()["total"], 4)
            c = D.Dataset.load(cs)
            self.assertEqual(c.rows[0]["tactics"], ["Execution", "Persistence"])
            self.assertEqual(c.rows[0]["dtext"], "Cmdline: x ¦ User: y")

    def test_garbage_is_a_clean_error(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write('{"broken": ')
        try:
            with self.assertRaises(D.LoadError):
                D.Dataset.load(f.name)
        finally:
            os.unlink(f.name)

    def test_mitre_links(self):
        self.assertEqual(D.mitre_url("T1059.001"), "https://attack.mitre.org/techniques/T1059/001/")
        self.assertEqual(D.mitre_url("attack.t1055"), "https://attack.mitre.org/techniques/T1055/")
        self.assertIsNone(D.mitre_url("sysmon"))

    def test_demo_data_is_deterministic_and_clearly_made_up(self):
        a, b = fixtures.demo_dicts(), fixtures.demo_dicts()
        self.assertEqual([x["RuleID"] for x in a], [x["RuleID"] for x in b])
        self.assertTrue(all(x["RuleID"].startswith("demo-") and x["Computer"].startswith("DEMO-") for x in a))


if __name__ == "__main__":
    unittest.main()
