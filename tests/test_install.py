import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile

from hayabusa_lens import install as I


def make_zip(name="hayabusa-9.9.9-lin-x64-musl", extra=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(name, "#!/bin/sh\necho hi\n")
        z.writestr("rules/readme.txt", "rules")
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return buf.getvalue()


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(zip_bytes, digest=None, assets=None):
    release = {"tag_name": "v9.9.9", "assets": assets or [
        {"name": "hayabusa-9.9.9-lin-x64-musl.zip", "size": len(zip_bytes), "browser_download_url": "https://example.test/lin.zip", **({"digest": digest} if digest else {})},
        {"name": "hayabusa-9.9.9-win-x64.zip", "size": 1, "browser_download_url": "https://example.test/win.zip"},
    ]}

    def opener(req, timeout=0):
        url = req.full_url if hasattr(req, "full_url") else req
        return FakeResp(json.dumps(release).encode() if "api" in url else zip_bytes)
    return opener


class InstallTests(unittest.TestCase):
    def test_platform_keys(self):
        self.assertEqual(I.platform_key("Linux", "x86_64"), "lin-x64")
        self.assertEqual(I.platform_key("Darwin", "arm64"), "mac-aarch64")
        self.assertEqual(I.platform_key("Windows", "AMD64"), "win-x64")
        with self.assertRaises(I.InstallError):
            I.platform_key("Plan9", "mips")

    def test_pick_asset_prefers_static_linux_and_skips_live_response(self):
        assets = [{"name": n} for n in ("hayabusa-4.1.0-lin-x64-gnu.zip", "hayabusa-4.1.0-lin-x64-musl.zip", "hayabusa-4.1.0-win-x64-live-response.zip", "hayabusa-4.1.0-win-x64.zip", "hayabusa-4.1.0-all-platforms.zip")]
        self.assertTrue(I.pick_asset(assets, "lin-x64")["name"].endswith("musl.zip"))
        self.assertEqual(I.pick_asset(assets, "win-x64")["name"], "hayabusa-4.1.0-win-x64.zip")
        with self.assertRaises(I.InstallError):
            I.pick_asset(assets, "mac-x64")

    def test_install_with_matching_checksum(self):
        z = make_zip()
        with tempfile.TemporaryDirectory() as d:
            seen = []
            p = I.install(d, progress=lambda a, b, m: seen.append(m), opener=opener_for(z, "sha256:" + hashlib.sha256(z).hexdigest()), system="Linux", machine="x86_64")
            self.assertTrue(os.path.isfile(p) and os.access(p, os.X_OK))
            self.assertTrue(os.path.isdir(os.path.join(os.path.dirname(p), "rules")))
            self.assertEqual(seen[-1], "done")

    def test_checksum_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(I.InstallError) as cm:
            I.install(d, opener=opener_for(make_zip(), "sha256:" + "0" * 64), system="Linux", machine="x86_64")
        self.assertIn("checksum", str(cm.exception))

    def test_unsafe_archive_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as d, self.assertRaises(I.InstallError):
            I.install(d, opener=opener_for(make_zip(extra={"../evil.txt": "x"})), system="Linux", machine="x86_64")
        self.assertFalse(os.path.exists(os.path.join(d, "..", "evil.txt")))

    def test_network_failure_is_a_clean_error(self):
        def boom(req, timeout=0):
            raise OSError("no network")
        with self.assertRaises(I.InstallError):
            I.install(tempfile.gettempdir(), opener=boom)


if __name__ == "__main__":
    unittest.main()
