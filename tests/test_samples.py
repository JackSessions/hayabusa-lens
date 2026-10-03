import io
import os
import tempfile
import unittest

from hayabusa_lens import samples as SM


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class SamplesTests(unittest.TestCase):
    def test_download_fetches_each_file_once_and_writes_credit(self):
        calls = []

        def opener(req, timeout=0):
            calls.append(req.full_url)
            return FakeResp(b"EVTXDATA")
        files = [("Folder A/one two.evtx", 8), ("Folder B/three.evtx", 8)]
        with tempfile.TemporaryDirectory() as d:
            seen = []
            SM.download(d, progress=lambda a, b, n: seen.append((a, b)), base="https://x.test/", files=files, opener=opener)
            self.assertEqual(sorted(os.listdir(d)), ["README.txt", "one two.evtx", "three.evtx"])
            self.assertIn("Folder%20A/one%20two.evtx", calls[0])
            SM.download(d, base="https://x.test/", files=files, opener=opener)
            self.assertEqual(len(calls), 2, "files already downloaded must not be fetched again")
            self.assertEqual(seen[-1], (2, 2))
            with open(os.path.join(d, "README.txt"), encoding="utf-8") as f:
                self.assertIn("Yamato-Security/hayabusa-sample-evtx", f.read())

    def test_network_failure_is_a_clean_error_and_leaves_no_partial_file(self):
        def boom(req, timeout=0):
            raise OSError("offline")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SM.SamplesError):
                SM.download(d, base="https://x.test/", files=[("a/b.evtx", 1)], opener=boom)
            self.assertEqual(os.listdir(d), [])

    def test_the_curated_list_is_small_and_sane(self):
        self.assertGreaterEqual(len(SM.FILES), 6)
        self.assertLess(SM.total_mb(), 10)
        self.assertTrue(all(p.lower().endswith(".evtx") for p, _ in SM.FILES))


if __name__ == "__main__":
    unittest.main()
