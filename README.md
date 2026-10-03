# Hayabusa Lens

![tests](https://github.com/JackSessions/hayabusa-lens/actions/workflows/test.yml/badge.svg)

**An unofficial point-and-click front end for [Hayabusa](https://github.com/Yamato-Security/hayabusa)**, Yamato Security's fast Sigma-based threat-hunting and timeline tool for Windows event logs. Scan `.evtx` files, then filter, search, zoom the timeline, explore MITRE ATT&CK and export, all in your browser.

![Hayabusa Lens screenshot (demo data)](https://raw.githubusercontent.com/JackSessions/hayabusa-lens/main/docs/screenshot.png)
*Screenshot uses the built-in fictional demo data.*

## What you get

- **One-click scans.** Pick a `.evtx` file or a folder, press **Scan**. A built-in file browser helps, and Hayabusa's live progress shows while it runs.
- **Open existing results.** Load a Hayabusa `.csv`, `.jsonl` or `.json` timeline you already made.
- **Severity at a glance.** Click the critical / high / medium / low / informational tiles to filter.
- **Zoomable timeline.** A stacked chart of detections over time. Drag across it to zoom into a window.
- **Pivot with a click.** Top rules, MITRE tactics and techniques, computers, event IDs and channels all filter the table. Techniques link to the ATT&CK site.
- **Search.** Rules, computers, command lines, users, anything in the event.
- **Event drawer.** Every field of a detection, its tags, rule file and source log, with *Copy as JSON*.
- **Export what you filtered.** CSV, JSON, or a self-contained HTML report.
- **Demo mode.** `hayabusa-lens --demo` loads clearly fictional data, so you can try everything with no logs and no Hayabusa.

## Install and run (Windows, macOS, Linux)

You need **Python 3.9 or newer**. Hayabusa Lens has no other dependencies. Pick one:

```
pipx install hayabusa-lens                                      # once published on PyPI
pipx install git+https://github.com/JackSessions/hayabusa-lens  # latest from GitHub
python hayabusa-lens.pyz                                        # no install: one file from the Releases page
```

Then:

```
hayabusa-lens --install-hayabusa     # downloads the official Hayabusa for your computer (about 47 MB), checksum-verified
hayabusa-lens                        # opens the dashboard in your browser
```

You can also skip the first command and press **Download it for me** in the interface. Or install Hayabusa yourself from https://github.com/Yamato-Security/hayabusa/releases; Lens finds it automatically.

## Use

```
hayabusa-lens                          # open the dashboard
hayabusa-lens /cases/host1/Logs        # scan a folder straight away
hayabusa-lens results.csv              # open an existing Hayabusa timeline
hayabusa-lens --demo                   # explore with fictional sample data
hayabusa-lens --hayabusa PATH          # use a specific Hayabusa
hayabusa-lens --help                   # every option, with examples
```

Hayabusa is looked for in `--hayabusa`, `$HAYABUSA_PATH`, your `PATH`, `~/.hayabusa-lens`, then common download folders (`~/hayabusa*`, `~/Downloads/hayabusa*`, `/opt/hayabusa*`). **Update rules** in the interface runs `hayabusa update-rules` (needs internet).

## How it works

Hayabusa Lens runs `hayabusa dfir-timeline` (or `json-timeline` on older versions) as a separate process, writes JSONL to a temporary file, reads it, and deletes it. It does not copy or include any Hayabusa code. Everything else (filtering, charts, export) is the Lens.

It starts a tiny web server on `127.0.0.1` only, protected by a random one-time token in the address, rejecting any other host name. It only reads files you point it at. No internet connection is used by the interface.

## Tested

Unit tests cover loading (JSONL, JSON, CSV), time-zone parsing, filtering, facets, the server's security checks, exports, and the Hayabusa subprocess flow (with a stand-in program). In CI, a separate job runs the **real Hayabusa on real sample logs** so a Hayabusa release that changes its output breaks the build first.

Run them: `python -m unittest discover -s tests -v`

## Known limitations (v0.1)

- Scans with `dfir-timeline` / `json-timeline`. Hayabusa's other commands (logon summary, metrics, search, pivot keywords) are not in the interface yet.
- Results are held in memory, which is comfortable for hundreds of thousands of detections but not tens of millions. Use a minimum level to cut down huge scans.
- Live analysis of the local machine is not exposed; point it at saved logs.
- Tested against Hayabusa 4.1.0 (and the older `json-timeline` style). Other versions may differ.

## Credit and licence

Created and maintained by **Jack Sessions**. Parts of the code were written with AI assistance (Claude); the behaviour is covered by the tests above.

This is an **unofficial** tool and is not affiliated with Yamato Security. **Hayabusa** is by [Yamato Security](https://github.com/Yamato-Security) and is licensed AGPL-3.0; please credit them and read their licence if you redistribute it. Hayabusa Lens is a separate program under the **MIT licence** (`LICENSE`): free to use, change and share as long as the copyright notice stays with the code. If you use it in a report, talk or course, please credit Jack Sessions and link https://github.com/JackSessions/hayabusa-lens (`CITATION.cff` has the details).
