from __future__ import annotations

import argparse
import sys

from . import __author__, __url__, __version__
from . import server, term


class _Help(argparse.Action):
    """-h / --help: shows the banner first when talking to a terminal."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if term.color_ok():
            term.enable_windows_ansi()
            print(term.rainbow(term.BANNER.strip("\n")) + "\n" + term.paint(f"  v{__version__}  |  event logs, attack chains and AI agents, explained  |  ", term.AMBER) + term.paint("by Jack Sessions", term.GREEN) + "\n")
        parser.print_help()
        parser.exit()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="hayabusa-lens", add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter,
        description=("Hayabusa Lens: find what happened in Windows event logs, fast.\n"
                     "Scan .evtx files with Hayabusa or Chainsaw, explore the alerts as a dashboard and a 3D map, let an AI helper\n"
                     "(a local model, Claude, or OpenAI) investigate the attack chain in plain English, keep an audit trail of every question it asks\n"
                     "and every answer it gets, and share findings with a SIEM. Everything runs in your browser, on this computer."),
        epilog=("examples:\n"
                "  hayabusa-lens                               open the app (Hayabusa is found automatically; Ollama is started if installed)\n"
                "  hayabusa-lens /cases/host1/Logs             scan a folder of .evtx files straight away\n"
                "  hayabusa-lens results.csv                   open an existing Hayabusa CSV / JSONL timeline\n"
                "  hayabusa-lens --samples                     download a few REAL attack-simulation logs and scan them\n"
                "  hayabusa-lens --get-rules                   fill the rule library with the newest SigmaHQ rules\n"
                "  hayabusa-lens --install-hayabusa            download Hayabusa for this computer (and --install-chainsaw)\n"
                "  hayabusa-lens --no-ai-start                 do not start Ollama automatically\n"
                "  hayabusa-lens --demo                        explore built-in sample alerts (no Hayabusa needed)\n\n"
                "AI helper (optional): install Ollama (free, private) or log in to Claude Code, or set OPENAI_API_KEY /\n"
                "ANTHROPIC_API_KEY, then open the AI button in the app. Nothing leaves this computer unless you choose an\n"
                "online service and tick the consent box.\n\n"
                "Hayabusa and Chainsaw are separate programs (AGPL-3.0 / GPL-3.0) that you download yourself:\n"
                "  https://github.com/Yamato-Security/hayabusa/releases\n"
                "Runs only on this computer (127.0.0.1) with a one-time token.\n\n"
                f"Created by {__author__} | MIT licence | {__url__}"))
    ap.add_argument("-h", "--help", action=_Help, help="show this help message and exit")
    ap.add_argument("path", nargs="?", help="a .evtx file or folder to scan, or a Hayabusa .csv/.jsonl/.json timeline to open")
    ap.add_argument("--hayabusa", metavar="PATH", help="path to the hayabusa program or the folder containing it (also: $HAYABUSA_PATH)")
    ap.add_argument("--chainsaw", metavar="PATH", help="path to the chainsaw program or its folder (also: $CHAINSAW_PATH)")
    ap.add_argument("--install-chainsaw", action="store_true", help="download Chainsaw with its Sigma rules into ~/.hayabusa-lens, then exit")
    ap.add_argument("--get-rules", nargs="?", const="core", metavar="SET", help="fill ~/.hayabusa-lens/rules with SigmaHQ rules (core, core+, core++, all, emerging; default core), then exit")
    ap.add_argument("--offline", action="store_true", help="with --get-rules: do not use the internet (cached download, else the built-in starter rules)")
    ap.add_argument("--samples", action="store_true", help="download a few real sample logs and scan them (the quickest way to see it working)")
    ap.add_argument("--no-ai-start", action="store_true", help="do not start Ollama automatically (default: start it if installed, and stop it again on exit)")
    ap.add_argument("--demo", action="store_true", help="load built-in sample alerts (works offline, no Hayabusa needed)")
    ap.add_argument("--port", type=int, default=0, metavar="N", help="port to listen on (default: a free one)")
    ap.add_argument("--no-browser", action="store_true", help="print the address instead of opening a browser")
    ap.add_argument("--install-hayabusa", action="store_true", help="download the official Hayabusa for this computer into ~/.hayabusa-lens, then exit")
    ap.add_argument("--version", action="version", version=f"hayabusa-lens {__version__}")
    a = ap.parse_args(argv)
    if a.install_hayabusa:
        from . import install
        try:
            path = install.install(progress=lambda d, t, m: print(f"\r  {m}" + (f" {d * 100 // t}%" if t and m.startswith("down") else "") + "      ", end="", flush=True))
        except install.InstallError as e:
            print(f"\nError: {e}", file=sys.stderr)
            return 2
        print(f"\nInstalled Hayabusa: {path}\nHayabusa Lens will find it automatically.")
        return 0
    if a.get_rules:
        from . import rulelib
        try:
            m = rulelib.update(a.get_rules, "offline" if a.offline else "auto",
                               progress=lambda d, t, msg: print(f"\r  {msg}" + (f" {d * 100 // t}%" if t and msg.startswith("down") else "") + "      ", end="", flush=True))
        except rulelib.RuleLibError as e:
            print(f"\nError: {e}", file=sys.stderr)
            return 2
        st = rulelib.status()
        print(f"\n{m.get('note') or 'Rules ready.'}\n  {st['count']:,} rules in {st['dir']}\n  source: {st['source']}")
        return 0
    if a.install_chainsaw:
        from . import install
        try:
            path = install.install_chainsaw(progress=lambda d, t, m: print(f"\r  {m}" + (f" {d * 100 // t}%" if t and m.startswith("down") else "") + "      ", end="", flush=True))
        except install.InstallError as e:
            print(f"\nError: {e}", file=sys.stderr)
            return 2
        print(f"\nInstalled Chainsaw: {path}\nHayabusa Lens will find it automatically.")
        return 0
    server.STATE["hayabusa"] = a.hayabusa
    server.STATE["chainsaw"] = a.chainsaw
    return server.serve(a.port, not a.no_browser, a.path, a.demo, a.samples, not a.no_ai_start)


if __name__ == "__main__":
    sys.exit(main())
