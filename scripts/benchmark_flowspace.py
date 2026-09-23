"""Measure the exact flow-space diff at scale (runtime, peak memory, slabs). Not a CI gate.

Usage: uv run python scripts/benchmark_flowspace.py [rules per side ...]   (default: 100 500 2500)
The generator is a deliberately adversarial checkerboard: heavily overlapping source ranges and ports.
"""

from __future__ import annotations

import ipaddress
import random
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hetzner_security.flows import space_minus_slabs  # noqa: E402

BASE = int(ipaddress.ip_address("198.51.100.0"))


def rules(rng: random.Random, count: int) -> list[tuple[int, int, int, int]]:
    output = []
    for _ in range(count):
        start, port = BASE + rng.randint(0, 4000), rng.randint(1, 60000)
        output.append((start, start + rng.randint(0, 512), port, port + rng.randint(0, 200)))
    return output


def main() -> int:
    sizes = [int(value) for value in sys.argv[1:]] or [100, 500, 2500]
    rng = random.Random(3)  # noqa: S311 -- deterministic benchmark data, not cryptography
    print("| Rules per side | Runtime | Peak memory | Slabs |\n|---|---|---|---|")
    for size in sizes:
        after, before = rules(rng, size), rules(rng, size)
        started = time.perf_counter()
        slabs = space_minus_slabs(after, before)
        elapsed = time.perf_counter() - started
        tracemalloc.start()
        space_minus_slabs(after, before)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        print(f"| {size} | {elapsed:.2f} s | {peak / 1e6:.1f} MB | {len(slabs)} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
