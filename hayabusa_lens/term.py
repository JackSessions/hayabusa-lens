"""Terminal niceties: a banner for --help (only when talking to a real terminal)."""
from __future__ import annotations

import os
import sys

BANNER = r"""
  _   _                _                  _
 | | | | __ _ _   _ __| |__  _   _ ___  __ _
 | |_| |/ _` | | | / _` | '_ \| | | / __|/ _` |
 |  _  | (_| | |_| | (_| | |_) | |_| \__ \ (_| |
 |_| |_|\__,_|\__, |\__,_|_.__/ \__,_|___/\__,_|
              |___/        _
                          | |    ___ _ __  ___
                          | |   / _ \ '_ \/ __|
                          | |__|  __/ | | \__ \
                          |_____\___|_| |_|___/
"""


BLUE, AMBER, GREEN = (138, 180, 248), (253, 214, 99), (129, 201, 149)     # soft Google-style blue, yellow and green


def paint(text: str, rgb: tuple[int, int, int], bold: bool = False) -> str:
    return f"\x1b[{'1;' if bold else ''}38;2;{rgb[0]};{rgb[1]};{rgb[2]}m{text}\x1b[0m"


def rainbow(text: str) -> str:
    """Name kept for compatibility: the banner is drawn in one calm blue."""
    return "\n".join(paint(line, BLUE) for line in text.split("\n"))


def color_ok() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def enable_windows_ansi() -> None:
    if os.name == "nt":
        os.system("")
