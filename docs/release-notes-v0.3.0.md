# v0.3.0 release notes

v0.3 narrows the product around one read-only first run: public exposure, trust-boundary paths, temporal changes, and quantified—but explicitly unconfirmed—cost opportunities.

## Highlights

- Full normalized snapshots with timestamped facts, run identity, collector version, and endpoint coverage.
- `hetzner-audit path`, `diff`, `explain`, `ask`, and `cost`.
- Live Hetzner firewall normalization and private-network graph edges.
- Distinct `reachable`, `cloud_path_present`, and `unknown` path results.
- Coverage-aware diff that does not confuse collector failure with resource removal.
- Owner policy in dependency-free TOML or JSON.
- GitHub composite action for protected live audits and offline diff gates.
- Current catalog cost plus non-overlapping monthly/annual potential savings; missing RAM or workload evidence keeps confirmed savings at zero.

## Safety

No provider mutation, implicit SSH, port scan, or automatic remediation was added. Live tokens remain environment-only. Real snapshots contain sensitive topology and should be stored as protected artifacts, not committed to public repositories.

## Known limitations

Linux, Docker, PostgreSQL, Redis, and Terraform runtime adapters are not complete. API-only private paths prove provider reachability, not a listening or authenticated application service. The deterministic verifier remains component separation rather than an independent human or agent reviewer.
