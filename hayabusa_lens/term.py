"""Terminal niceties: a rainbow banner for --help (only when talking to a real terminal)."""
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


def hsv_rgb(h: float) -> tuple[int, int, int]:
    i = int(h * 6) % 6
    f = h * 6 - int(h * 6)
    r, g, b = [(1, f, 0), (1 - f, 1, 0), (0, 1, f), (0, 1 - f, 1), (f, 0, 1), (1, 0, 1 - f)][i]
    return int(r * 255), int(g * 255), int(b * 255)


def rainbow(text: str) -> str:
    out = []
    for row, line in enumerate(text.split("\n")):
        chars = []
        for col, ch in enumerate(line):
            if ch == " ":
                chars.append(ch)
                continue
            r, g, b = hsv_rgb(((col * 5 + row * 18) % 360) / 360)
            chars.append(f"\x1b[1;38;2;{r};{g};{b}m{ch}")
        out.append("".join(chars) + "\x1b[0m")
    return "\n".join(out)


def color_ok() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def enable_windows_ansi() -> None:
    if os.name == "nt":
        os.system("")
