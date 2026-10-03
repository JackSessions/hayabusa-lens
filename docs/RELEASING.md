# Releasing to PyPI

One-time setup (about 5 minutes):

1. Create the repository `JackSessions/hayabusa-lens` on GitHub and push `main`.
2. On https://pypi.org, log in, then **Your account > Publishing > Add a new pending publisher**:
   - PyPI project name: `hayabusa-lens`
   - Owner: `JackSessions`
   - Repository name: `hayabusa-lens`
   - Workflow name: `publish.yml`
   - Environment name: `pypi`
3. In the GitHub repository: **Settings > Environments > New environment**, name it `pypi` (optionally require your approval).

Each release:

1. Update the version in `pyproject.toml`, `hayabusa_lens/__init__.py` and `CITATION.cff`, and add a section to `CHANGELOG.md`.
2. `python -m unittest discover -s tests` and `python -m build && python -m twine check dist/*`.
3. Commit, push, then create a GitHub Release with the tag `vX.Y.Z` (the tag must match the version). Publishing the release runs `.github/workflows/publish.yml`: it builds, checks, publishes to PyPI with trusted publishing (no token stored), and attaches a single-file `hayabusa-lens.pyz` to the release.
4. Check https://pypi.org/project/hayabusa-lens/ and try `pipx install hayabusa-lens` on a clean machine.

Manual fallback (only if the workflow is unavailable): create an API token scoped to the project on PyPI, then `python -m twine upload dist/*` and enter `__token__` as the username. Never commit the token.

A version number can only be uploaded once, even if you delete the release, so run the checks above first. To rehearse, use TestPyPI (https://test.pypi.org) with `python -m twine upload --repository testpypi dist/*`.
