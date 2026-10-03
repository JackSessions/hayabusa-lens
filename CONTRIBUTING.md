# Contributing

Thanks for looking. This is a small project by one person, so the process is light.

1. Open an issue first for anything bigger than a bug fix, so we agree on the direction.
2. `python -m unittest discover -s tests -v` must pass. There are no dependencies to install.
3. Keep the tool dependency-free (Python standard library only) and local-first.
4. For UI changes, include a screenshot. For anything that touches the AI layer, keep these rules: read-only tools, untrusted-data fencing, consent before anything leaves the machine, no keys on disk.
5. Never include real case logs, API keys or personal data in issues, tests or screenshots.

Hayabusa Lens is MIT licensed. Hayabusa (AGPL-3.0) and Chainsaw (GPL-3.0) are separate programs and are not bundled.
