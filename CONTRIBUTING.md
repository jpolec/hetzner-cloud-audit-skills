# Contributing

Contributions are welcome, especially clean-twin fixtures, false-positive reductions, read-only collectors, and cross-layer evidence contracts.

1. Open an issue for material architecture or schema changes.
2. Never include real tokens, hostnames, customer data, internal topology, or production output.
3. Use documentation IP ranges and synthetic names in fixtures.
4. Keep collection separate from conclusions and add a verifier/false-positive test for every rule.
5. Run `ruff check .`, `mypy src`, `pytest`, the demo, build validation, and Gitleaks.
6. Sign off that your contribution is original or compatible with Apache-2.0. Document adapted sources and licenses.

Rules should demonstrate an affected boundary, actual/expected state, evidence, prerequisites, impact, and remediation. Generic checklist warnings belong in hardening notes, not confirmed findings.

