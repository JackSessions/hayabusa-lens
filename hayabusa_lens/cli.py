from __future__ import annotations

import argparse
import sys

from . import __author__, __url__, __version__
from . import server, term


class _Help(argparse.Action):
    """-h / --help: shows the rainbow banner first when talking to a terminal."""
    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        if term.color_ok():
            term.enable_windows_ansi()
            print(term.rainbow(term.BANNER.strip("\n")) + f"\n  v{__version__}  |  unofficial front end for Hayabusa\n")
        parser.print_help()
        parser.exit()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="hayabusa-lens", add_help=False, formatter_class=argparse.RawDescriptionHelpFormatter,
        description=("Hayabusa Lens: an unofficial point-and-click front end for Hayabusa (Yamato Security's Windows event-log\n"
                     "threat-hunting and timeline tool). Scan .evtx logs, or open an existing Hayabusa timeline, then filter,\n"
                     "search, zoom the timeline, explore MITRE ATT&CK tactics and export results, all in your browser."),
        epilog=("examples:\n"
                "  hayabusa-lens                               open the interface (Hayabusa is found automatically)\n"
                "  hayabusa-lens /cases/host1/Logs             scan a folder of .evtx files straight away\n"
                "  hayabusa-lens results.csv                   open an existing Hayabusa CSV / JSONL timeline\n"
                "  hayabusa-lens --demo                        explore the interface with fictional sample data\n"
                "  hayabusa-lens --hayabusa ~/hayabusa/hayabusa-4.1.0-lin-x64-musl\n\n"
                "Hayabusa is a separate program by Yamato Security (AGPL-3.0) that you download yourself:\n"
                "  https://github.com/Yamato-Security/hayabusa/releases\n"
                "Runs only on this computer (127.0.0.1) with a one-time token, and only reads your files.\n\n"
                f"Created by {__author__} | MIT licence | {__url__}"))
    ap.add_argument("-h", "--help", action=_Help, help="show this help message and exit")
    ap.add_argument("path", nargs="?", help="a .evtx file or folder to scan, or a Hayabusa .csv/.jsonl/.json timeline to open")
    ap.add_argument("--hayabusa", metavar="PATH", help="path to the hayabusa program or the folder containing it (also: $HAYABUSA_PATH)")
    ap.add_argument("--demo", action="store_true", help="load fictional demo data instead of real logs")
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
    server.STATE["hayabusa"] = a.hayabusa
    return server.serve(a.port, not a.no_browser, a.path, a.demo)


if __name__ == "__main__":
    sys.exit(main())
