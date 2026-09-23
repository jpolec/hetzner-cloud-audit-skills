# Benchmark methodology

The v0.1 benchmark is a synthetic normalized snapshot. It contains 33 deliberately planted problems across public exposure, firewall coverage, IaC drift, cross-environment reachability, Docker isolation, PostgreSQL, Redis, backup evidence, and vulnerability context. All names, IP addresses, and CVE IDs are examples; no production data is used.

Run:

```sh
PYTHONPATH=src ./scripts/demo.sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Ground truth lives in `expected-findings/v0.1-insecure.json`. The test compares total candidates, per-rule counts, and verifier verdict counts. The current fixture expects 33 candidates: 23 confirmed and 10 `needs_validation`. The latter are intentional: five absence-based backup observations, two public hosts without complete firewall coverage, one provider-only SSH exposure, one unreachable PostgreSQL HBA weakness, and one scanner signal without runtime-applicability evidence must not be silently confirmed.

The benchmark currently measures deterministic fixture recall and verifier state handling, not real-world precision. Its fixture contains no clean lookalike population large enough to calculate a meaningful false-positive rate; focused unit tests cover VPN-scoped SSH and unattached firewall rules. We therefore do not claim “AI found everything,” general recall, or production accuracy.

The separate `v0.3-cost.json` fixture measures accounting semantics rather than a planted-vulnerability count. Its catalog baseline is EUR 220/month. It contains a EUR 40/month stopped server plus two mutually exclusive EUR 40/50 alternatives for one running server. The expected headline is therefore EUR 90/month (EUR 1,080/year), not EUR 130/month. Confirmed savings remain zero because RAM, owner intent, and rollback evidence are absent.

v0.3 unit fixtures additionally verify live-response normalization, temporal fact identity, new-exposure diffing, coverage regression, `cloud_path_present` classification, and architecture-recommendation schema compliance.

Planned benchmark improvements: clean twins for every scenario, independent fixture authorship, mutation tests, stale/conflicting evidence cases, timing and memory measurements, and multiple agent-run coverage comparisons against the Cloudflare UX/methodology baseline.

## Generated-project benchmark

`scripts/benchmark_generated.py` builds random projects. For 18 rules (cloud, host evidence, Robot, Object Storage, and Kubernetes) it plants the problem or its clean twin (the safe variant of the same configuration), then scores each finding per (rule, asset) against ground truth. It is regression-tested in `tests/test_generated_benchmark.py` with three seeds.

Generated benchmark: 150 projects, seed 20260923. Each planted issue has a clean twin in the same run.

| Rule | Planted | True positives | False positives | False negatives | Precision | Recall |
|---|---|---|---|---|---|---|
| HETZ-NET-001 | 87 | 87 | 0 | 0 | 1.00 | 1.00 |
| HETZ-NET-003 | 87 | 87 | 0 | 0 | 1.00 | 1.00 |
| HETZ-FW-001 | 74 | 74 | 0 | 0 | 1.00 | 1.00 |
| HETZ-FW-003 | 76 | 76 | 0 | 0 | 1.00 | 1.00 |
| HETZ-FW-002 | 67 | 67 | 0 | 0 | 1.00 | 1.00 |
| HETZ-NET-005 | 78 | 78 | 0 | 0 | 1.00 | 1.00 |
| HETZ-NET-006 | 77 | 77 | 0 | 0 | 1.00 | 1.00 |
| HETZ-GOV-004 | 64 | 64 | 0 | 0 | 1.00 | 1.00 |
| HETZ-KEY-001 | 77 | 77 | 0 | 0 | 1.00 | 1.00 |
| HETZ-STO-001 | 82 | 82 | 0 | 0 | 1.00 | 1.00 |
| HETZ-DKR-005 | 76 | 76 | 0 | 0 | 1.00 | 1.00 |
| HETZ-SSH-001 | 79 | 79 | 0 | 0 | 1.00 | 1.00 |
| HETZ-HOST-001 | 66 | 66 | 0 | 0 | 1.00 | 1.00 |
| HETZ-HOST-002 | 83 | 83 | 0 | 0 | 1.00 | 1.00 |
| HETZ-PG-003 | 67 | 67 | 0 | 0 | 1.00 | 1.00 |
| HETZ-ROB-005 | 76 | 76 | 0 | 0 | 1.00 | 1.00 |
| HETZ-OBJ-001 | 63 | 63 | 0 | 0 | 1.00 | 1.00 |
| HETZ-K8S-002 | 86 | 86 | 0 | 0 | 1.00 | 1.00 |

What this proves and what it does not: every rule matches its own specification across many random combinations, and scenarios do not interfere. One interference found while building the generator, a world-open 443 next to Cloudflare-only peers, turned out to be a correct `HETZ-NET-006`. Another, in v0.7, was a real bug: `HETZ-HOST-001` fired when a bundle carried no firewall data at all; it now needs a known engine. It does **not** measure real-world detection accuracy, which needs labeled real projects.

