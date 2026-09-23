"""Score rules on generated projects with known ground truth: python scripts/benchmark_generated.py [count] [seed]."""

from __future__ import annotations

import sys

from hetzner_security.benchmark import render_score_markdown, score

if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 150
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 20260923
    print(render_score_markdown(score(seed, count), seed, count))
