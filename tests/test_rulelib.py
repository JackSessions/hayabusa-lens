import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile

from hayabusa_lens import rulelib as RL
from hayabusa_lens import rulesidx as RI

RULE = "title: Fake Rule {n}\nid: 00000000-0000-0000-0000-00000000000{n}\nlevel: high\ntags:\n  - attack.t1003\nlogsource:\n  product: windows\ndetection:\n  s:\n    EventID: 1\n  condition: s\n"


def make_zip(n=3):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for i in range(n):
            z.writestr(f"rules/windows/r{i}.yml", RULE.format(n=i))
    return b.getvalue()


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def fake_opener(blob, digest=None, with_asset=True):
    rel = {"tag_name": "r2099-01-01", "assets": [{"name": "sigma_core.zip", "size": len(blob), "browser_download_url": "https://example.invalid/sigma_core.zip",
                                                   "digest": digest or "sha256:" + hashlib.sha256(blob).hexdigest()}] if with_asset else []}

    def op(req, timeout=0):
        url = req.full_url if hasattr(req, "full_url") else req
        return Resp(json.dumps(rel).encode() if "api" in url else blob)
    return op


class RuleLibTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.mkdtemp()
        self.lib, self.cache = os.path.join(self.t, "rules"), os.path.join(self.t, "cache")

    def test_starter_always_present(self):
        s = RL.status(self.lib)
        self.assertGreaterEqual(s["count"], 12)
        m = RL.update("core", "offline", lib=self.lib, cache=self.cache)
        self.assertIn("starter", m["source"])

    def test_online_then_offline_cache(self):
        blob = make_zip()
        m = RL.update_online("core", lib=self.lib, cache=self.cache, opener=fake_opener(blob))
        self.assertEqual(m["tag"], "r2099-01-01")
        self.assertEqual(len(RI.RuleIndex([self.lib]).search("Fake Rule")), 3)
        import shutil
        shutil.rmtree(self.lib)
        m = RL.use_offline("core", lib=self.lib, cache=self.cache)
        self.assertIn("cached", m["source"])
        self.assertEqual(len(RI.RuleIndex([self.lib]).search("Fake Rule")), 3)

    def test_bad_checksum_rejected(self):
        with self.assertRaises(RL.RuleLibError):
            RL.update_online("core", lib=self.lib, cache=self.cache, opener=fake_opener(make_zip(), digest="sha256:" + "0" * 64))
        self.assertFalse(os.path.isdir(self.cache) and any(f.endswith(".zip") and f.startswith("core-") for f in os.listdir(self.cache)))

    def test_auto_falls_back_when_offline(self):
        def boom(*a, **k):
            raise OSError("no network")
        m = RL.update("core", "auto", lib=self.lib, cache=self.cache, opener=boom)
        self.assertIn("Offline", m["note"])
        with self.assertRaises(RL.RuleLibError):
            RL.update("core", "online", lib=self.lib, cache=self.cache, opener=boom)

    def test_unknown_set_and_missing_asset(self):
        with self.assertRaises(RL.RuleLibError):
            RL.update_online("nope", lib=self.lib, cache=self.cache)
        with self.assertRaises(RL.RuleLibError):
            RL.update_online("core", lib=self.lib, cache=self.cache, opener=fake_opener(b"", with_asset=False))

    def test_zip_slip_blocked(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("../evil.yml", "x")
        with self.assertRaises(Exception):
            RL.update_online("core", lib=self.lib, cache=self.cache, opener=fake_opener(b.getvalue()))
        self.assertFalse(os.path.exists(os.path.join(self.t, "evil.yml")))


if __name__ == "__main__":
    unittest.main()
