# Security

Hayabusa Lens runs on your own computer and is meant to be used on logs you are allowed to analyse.

## Design choices you can rely on

- The web interface listens on `127.0.0.1` only, with a random one-time token and a host-name check.
- It only reads files you point it at. Results are kept in memory.
- The AI investigator can only use read-only tools over alerts already in memory. It cannot run commands, read files or reach the network. Log text is passed to the model as untrusted data.
- Nothing is sent to an online AI service unless you choose one and tick the consent box. API keys you paste are kept in memory until the program closes and are never written to disk or logs.
- Sharing to a SIEM only happens after a preview and an explicit confirmation. Plain `http://` to public addresses is refused.

## Reporting a problem

Please open a private security advisory on GitHub (Security tab, "Report a vulnerability") or open an issue for anything that is not sensitive. Include the version (`hayabusa-lens --version`), your operating system, and steps to reproduce. Do not attach real case logs or API keys.

Hayabusa, Chainsaw and the Sigma rules are separate projects; report problems in them to their own maintainers.
