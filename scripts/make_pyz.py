"""Builds dist/hayabusa-lens.pyz: ONE file that runs on Windows, macOS and Linux with just Python 3.9+.
Usage: python scripts/make_pyz.py   then   python dist/hayabusa-lens.pyz --version"""
import os
import shutil
import tempfile
import zipapp

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.makedirs(os.path.join(root, "dist"), exist_ok=True)
with tempfile.TemporaryDirectory() as tmp:
    shutil.copytree(os.path.join(root, "hayabusa_lens"), os.path.join(tmp, "hayabusa_lens"), ignore=shutil.ignore_patterns("__pycache__"))
    with open(os.path.join(tmp, "__main__.py"), "w") as f:
        f.write("from hayabusa_lens.cli import main\nraise SystemExit(main())\n")
    out = os.path.join(root, "dist", "hayabusa-lens.pyz")
    zipapp.create_archive(tmp, out, interpreter="/usr/bin/env python3", compressed=True)
print("built", out)
