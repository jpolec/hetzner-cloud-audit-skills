# Benchmark methodology

The v0.1 benchmark is a synthetic normalized snapshot. It contains 33 deliberately planted problems across public exposure, firewall coverage, IaC drift, cross-environment reachability, Docker isolation, PostgreSQL, Redis, backup evidence, and vulnerability context. All names, IP addresses, and CVE IDs are examples; no production data is used.

Run:

```sh
PYTHONPATH=src ./scripts/demo.sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Ground truth lives in `expected-findings/v0.1-insecure.json`. The test compares total candidates, per-rule counts, and verifier verdict counts. The current fixture expects 33 candidates: 23 confirmed and 10 `needs_validation`. The latter are intentional: five absence-based backup observations, two public hosts without complete firewall coverage, one provider-only SSH exposure, one unreachable PostgreSQL HBA weakness, and one scanner signal without runtime-applicability evidence must not be silently confirmed.

The benchmark currently measures deterministic fixture recall and verifier state handling, not real-world precision. Its fixture contains no clean lookalike population large enough to calculate a meaningful false-positive rate; focused unit tests cover VPN-scoped SSH and unattached firewall rules. We therefore do not claim “AI found everything,” general recall, or production accuracy.

Planned benchmark improvements: clean twins for every scenario, independent fixture authorship, mutation tests, stale/conflicting evidence cases, timing and memory measurements, and multiple agent-run coverage comparisons against the Cloudflare UX/methodology baseline.
