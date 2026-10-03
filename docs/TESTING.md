# Testing Hayabusa Lens

## 1. Automated tests (about 5 seconds)

```
cd hayabusa-lens
python3 -m unittest discover -s tests -v        # Windows: py -m unittest discover -s tests -v
```

Expected: every test passes; a couple are skipped unless a real Hayabusa / Chainsaw is installed.

To also run the **real programs on real logs**:

```
python3 -m hayabusa_lens --install-hayabusa
python3 -m hayabusa_lens --install-chainsaw
python3 -m hayabusa_lens --samples --no-browser   # let it download the sample logs once, then Ctrl+C
HAYABUSA_PATH=~/.hayabusa-lens/hayabusa-* HAYABUSA_SAMPLES=~/.hayabusa-lens/sample-logs python3 -m unittest tests.test_integration -v
```

## 2. Five-minute click-through

Start it: `python3 -m hayabusa_lens` (or `hayabusa-lens`). Tick each line:

| Step | What to do | Expected |
|---|---|---|
| 1 | Look at the two chips under the tabs | Hayabusa and Chainsaw show a version (green), or a *Download it for me* button |
| 2 | **Real samples** tab, *Download and scan* | Progress, then about 400 detections, 11 critical |
| 3 | Click the red CRITICAL tile | Table narrows to critical only; click again to restore |
| 4 | Drag across a timeline bar | A *time range* chip appears; the table and lists narrow; the chip's x zooms back out |
| 5 | Click a MITRE tactic on the right | Table filters to it; click again to clear |
| 6 | Press `/` and type `lsass` | Search box focuses; the table shows only matching events |
| 7 | Click a row | Drawer opens with all fields; the drawer shows the **Detection rule** inline and **View rule (large)** opens it bigger; Esc closes |
| 8 | Export CSV, JSON, HTML | Three files download and open |
| 9 | **Scan logs**: pick your sample folder, Engine = *Chainsaw*, Scan | A second result loads (about 185 detections) |
| 10 | **Compare**: A = Hayabusa, B = Chainsaw, *Compare* | +/- counts and unchanged count; switch *Match by* to *event only* |
| 11 | **Rules** tab, search `mimikatz`, click a result | Hundreds of rules listed; the YAML opens on the right |
| 12 | **Summaries**, *Logon summary*, run on the sample folder | Successful and failed logon tables, filterable, CSV download |
| 13 | **Search events**, keywords `lsass, dump`, tick *all* | A table of matching events |
| 14 | **Theme** button three times | Dark, Grey (monochrome), Light, then back; reload keeps the choice |
| 15 | **Help** (or `?`) and click through the tabs | The Help sections; Esc closes |
| 16 | `python3 -m hayabusa_lens --help` | Banner and every option, including `--agent` and `--no-ai-start` |
| 17 | Press **AI** at the top | A box with status chips and Auto / Ollama / Claude / OpenAI. *What is happening* shows Ollama starting (if installed) |
| 18 | Choose a helper, press **Test connection** | A tick and a time, or a plain-English reason it failed. Online choices ask for the consent tick first |
| 19 | With results loaded, press **Investigate with AI** (results header) | The AI path tab with a live audit trail, then a *What the AI found* report |
| 20 | **Network map**, then **Explain the attack chain** | An attack-stage list on the right, then a plain-English explanation. Click a node: *Explain this* / *Investigate* |
| 21 | On the dashboard press **Investigate** (or tick *run automatically*) | The audit trail fills in live: question, AI answered, tool, result. Click a step for the full question. *Audit (Markdown)* downloads it |
| 22 | **AI path** tab, then **Network map** | The investigation drawn in 3D; the map shows numbered attack paths. **←** goes back, the shield goes home with a DFIR field note |
| 23 | **Share**, choose *AI audit trail*, *Preview*, then *Send* to a file without ticking the box | Refused until you tick the confirmation; with it, an NDJSON file appears |

## 3. Things that should fail politely

- Scan an empty folder or a non-log file: a clear red message, no crash.
- Type a nonsense path on any tab: "Path not found".
- Stop Hayabusa from being found (`--hayabusa /nonexistent`): the chip offers a download; scans explain why they cannot run.
- Open the address without the `token=` part: "missing or wrong token".

## 4. On Windows

Install Python 3.9+ from python.org (tick *Add to PATH*), then in PowerShell:

```
py -m pip install --user pipx ; py -m pipx ensurepath      # open a new terminal afterwards
pipx install git+https://github.com/JackSessions/hayabusa-lens
hayabusa-lens --install-hayabusa
hayabusa-lens --install-chainsaw
hayabusa-lens --samples
```

Then repeat the click-through above. Please report anything that differs from Linux (paths with backslashes, antivirus blocking the sample logs or the downloaded programs, the browser not opening).

## 5. Report a bug

Open an issue with: the step you were on, what you expected, what happened, your operating system, `hayabusa-lens --version`, and the red message if any. A screenshot helps.
