from __future__ import annotations

import unittest

from hetzner_security.benchmark import SCENARIOS, score


class GeneratedBenchmarkTest(unittest.TestCase):
    def test_every_benchmarked_rule_has_no_false_positives_or_negatives(self) -> None:
        for seed in (1, 2, 3):
            results = score(seed, 40)
            for rule in SCENARIOS:
                self.assertEqual((results[rule]["fp"], results[rule]["fn"]), (0, 0), f"{rule} seed {seed}: {results[rule]}")
            self.assertTrue(sum(value["planted"] for value in results.values()) > 100)


if __name__ == "__main__":
    unittest.main()
