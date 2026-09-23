"""Escaping for provider-sourced text that lands in Markdown reports.

Names, labels, and descriptions come from the Hetzner API and may be crafted. Newlines,
table pipes, link brackets, and HTML angle brackets are neutralized so a value cannot break
a table, inject a link or HTML, or smuggle instructions into an agent-read report.
Backticks and underscores are kept: Hetzner names cannot contain backticks, and our own
report text uses code spans.
"""

from __future__ import annotations

_SPECIAL = "\\|[]<>"


def md(value: object) -> str:
    text = " ".join(str(value).split())  # collapses newlines, tabs, and runs of spaces
    for char in _SPECIAL:
        text = text.replace(char, "\\" + char)
    return text
