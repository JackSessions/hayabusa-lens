"""Runs the real Hayabusa on real sample logs. Skipped unless HAYABUSA_PATH and HAYABUSA_SAMPLES are set (CI does this)."""
import os
import unittest

from hayabusa_lens import data as D
from hayabusa_lens import runner as R

SAMPLES = os.environ.get("HAYABUSA_SAMPLES", "")


@unittest.skipUnless(os.environ.get("HAYABUSA_PATH") and os.path.isdir(SAMPLES), "needs a real Hayabusa and sample .evtx files")
class RealHayabusaTests(unittest.TestCase):
    def test_scan_a_folder_and_read_the_results(self):
        path = R.find_hayabusa()
        self.assertTrue(path)
        info = R.probe(path)
        self.assertIsNotNone(info["style"])
        out = R.scan(info, os.path.abspath(SAMPLES), "low", False, [])
        try:
            ds = D.Dataset.load(out)
        finally:
            os.unlink(out)
        s = ds.summary()
        self.assertGreater(s["total"], 50)
        self.assertEqual(s["skipped"], 0)
        self.assertTrue(any(r["tactics"] for r in ds.rows), "MITRE tactics should be present")
        self.assertTrue(any(r["lvl"] >= 3 for r in ds.rows), "expected at least one high or critical detection")


if __name__ == "__main__":
    unittest.main()
