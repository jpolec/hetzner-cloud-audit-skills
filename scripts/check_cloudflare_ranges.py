"""Kept for compatibility: checks every bundled edge-provider list, not only Cloudflare.

Equivalent to `python scripts/update_provider_ranges.py --check`.
"""

from __future__ import annotations

import runpy
import sys

if __name__ == "__main__":
    sys.argv = [sys.argv[0], "--check"]
    runpy.run_path(str(__import__("pathlib").Path(__file__).with_name("update_provider_ranges.py")), run_name="__main__")
