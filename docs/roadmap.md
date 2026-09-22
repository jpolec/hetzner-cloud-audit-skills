# Roadmap

## v0.3 — depth before breadth

The release target is one defensible first run: one read-only project token, zero SSH, and a report suitable for an infrastructure owner.

- Production-shaped, paginated Hetzner collection with per-endpoint coverage and partial-failure reporting.
- Temporal fact envelope, full snapshots, coverage-aware `diff`, and first-observed timestamps.
- Typed attack graph plus `path`, `explain`, and constrained `ask` commands.
- API-only exposure, private lateral-path, backup, protection, ownership, lifecycle, and cost signals.
- JSON/TOML owner policy evaluated separately from observed state.
- GitHub composite action, SARIF, Markdown job artifacts, and safe live-workflow guidance.
- Catalog cost baseline, stopped-resource savings, CPU p95 candidates, and non-overlapping savings totals.

## Next

1. Add clean-twin live-response fixtures for every supported Hetzner endpoint, retry/backoff tests, and recorded pagination limits.
2. Complete Terraform plan/state identity mapping so diff can cite the exact declaring resource and commit.
3. Add constrained read-only Linux, Docker, PostgreSQL, and Redis evidence adapters.
4. Add an independently isolated agent-verifier handoff format and benchmark acceptance/rejection accuracy.
5. Add kube-hetzner/CCM/CSI evidence only after cloud-path semantics are stable.
6. Improve cost evidence with operator monitoring exports, filesystem occupancy, invoice inputs, and workload constraints.

## Later

- AWS, GCP, Azure, and OCI should be provider adapters feeding the shared fact/graph/reasoning engine—not copied prompt repositories.
- A read-only MCP facade remains deferred until authorization, schemas, query limits, and redaction behavior stabilize.
- No automatic provider remediation is planned for the alpha line. Remediation remains a reviewed plan with validation and rollback.
