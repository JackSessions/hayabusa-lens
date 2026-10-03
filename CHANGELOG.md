# Changelog

## 0.9.0
- **Tutorial.** A guided two-minute tour (top-bar button, home-screen card, opens on the first visit) that highlights the real controls: engine, logs, dashboard, AI helper, investigation and audit trail, map, share.
- **No bundled sample data.** Removed the built-in demo alerts, `--demo`, the demo buttons and the sample-data pill. The tab is now **Practice logs**, which downloads 14 public attack-simulation logs only when you ask.
- **PyPI-ready.** New README ("why use this", tutorial, install, commands) with absolute image links so it renders on PyPI, richer package metadata, `SECURITY.md`, `CONTRIBUTING.md`, issue templates and `docs/RELEASING.md`.
- Tests no longer depend on product code for sample rows (they use test fixtures).


## 0.8.0
- **AI audit trail.** Every question put to the AI and every answer, the tool it chose and what it returned, live on the dashboard, with full prompts on click and Markdown/JSON export. It can also be sent to a SIEM (`hayabusa-lens.ai_audit` events).
- **AI works on your EVTX, not on agent prompts.** Removed the agent-log analysis, the Claude Code / Codex log discovery and `--agent`. The AI path tab now draws the investigation's own steps in 3D.
- **Auto-investigate** when results load (on by default only for a local model; a toggle on the dashboard).
- **Attack paths** on the network map (numbered, glowing arrows between computers in time order), and a cleaner hub-style layout.
- **Map fix:** version strings such as `FileVersion 2.5.0.0` were being drawn as external IP addresses; broadcast addresses are ignored too.
- **Rules fix:** *Update rules* no longer ends in a red "No detections found" error. Rules are de-duplicated (each Sigma rule was listed up to three times) and show their sources.
- **New look:** frosted glass, a night-security backdrop in Google colours, a four-colour shield, glowing animated rings on buttons, a Back button with history, and a DFIR field note on the home screen. Honours reduced-motion settings.
- Fixed the Back/Home state after scans.


## 0.7.0
- **Investigate with AI.** An AI helper explores loaded EVTX results step by step with read-only tools (overview, host, rule, search, timeline, event), then writes the attack chain in plain English. The whole run is recorded and drawn as a path in 3D. Works with Ollama, Claude (Claude Code login or API key) and OpenAI.
- **Attack chain from the alerts.** The Network map lists ATT&CK stages in attack order (no AI needed), with *Explain the attack chain* and per-node *Explain* / *Investigate*.
- **Simpler AI setup.** One AI button: Auto, Ollama, Claude, OpenAI. Paste an API key once (kept in memory for the session only). Ollama is started automatically when installed, verified, and stopped again on exit (`--no-ai-start` to disable). A live "what is happening" feed, test connection, and snackbar messages where you are looking.
- **New design.** Google-style colours, type and components in the spirit of jacksessions.dev: calmer cards, pill tabs, tonal buttons, clearer dashboard, welcome screen.
- **Less clutter.** Removed the scripted demo agent trace and the "fictional / demo data" labels; sample alerts are now a quiet "sample data" pill. Agent analysis now works on real logs only.
- Updated `--help`, README and in-app Help. New `--agent TRACE` and `--no-ai-start` options.
- Fixed: viewing the Agent tab no longer hides the results table.


## 0.6.0
- **AI that works out of the box.** An AI assistant box shows what is available (Ollama, Claude Code, API keys), picks the best private option with **Auto**, and has **Test connection**. New provider: **Claude through your Claude Code login**, no API key needed, with every tool disabled. Errors now appear next to the controls, and explanations show a live timer.
- **Share tab.** Preview, then export ECS JSON lines or CEF, or send alerts and flagged agent steps to a file, syslog (UDP/TCP), Elasticsearch/OpenSearch, Splunk HEC or a webhook. Off by default, explicit confirmation, credentials never stored. Hayabusa Lens stays a standalone tool, not a SIEM.
- **New look.** Welcome screen with one-click starts, grouped tabs with icons, calmer cards and controls, focus rings, better spacing.

## 0.5.0
- **Local models.** Agent chain 3D can use Ollama on this computer for real embeddings and for explanations: it detects Ollama, can start it, and can download `all-minilm`, `nomic-embed-text`, `mxbai-embed-large`, `llama3.2:3b` or `qwen2.5:3b` for you. Nothing leaves the machine, no key or consent box needed.
- **Network map 3D** opens from any scan, opened result or demo (link above the results table), exports PNG/JSON, and no longer counts logon IDs, SIDs or domain names as accounts or splits `PC01` from `PC01.example.corp`.
- **Detection rule shown in the event drawer** automatically, with a one-click "Get rules" when it is missing.
- Agent chain: trace discovery (Claude Code, Codex), drop/choose/paste a file, HTML report export, 5x faster analysis, far fewer false flags on agents that write about injection.
- Fixed severity pills being restyled by the new list dots.

## 0.4.0
- Agent chain 3D, Network map 3D, rule library (SigmaHQ online / cached / starter set), OpenAI-compatible and Claude connections.

## 0.3.0
- Chainsaw support, Sigma rule viewer, themes, compare two scans, help.
