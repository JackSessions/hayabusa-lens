# Changelog

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
