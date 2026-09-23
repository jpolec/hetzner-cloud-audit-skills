# Hetzner Cost and Architecture Audit

- Current catalog estimate: **EUR 220.00/month** (EUR 2640.00/year)
- Potential savings identified: **EUR 90.00/month** (EUR 1080.00/year)
- Expected savings (unused resources, plus rightsizing with full CPU/RAM/disk telemetry): **EUR 40.00/month**
- Measured savings: **EUR 0.00/month** (post-change catalog delta from `hetzner-audit diff`; not invoice-verified)
- All proposed savings require validation; no infrastructure changes were made.

## Recommendations

### HETZ-COST-003 · Validate x86-to-ARM migration

- Asset: `hcloud:server:1`
- Status: `needs_validation` · Risk: `medium` · Confidence: `0.62`
- Estimated saving: **EUR 50.00/month · EUR 600.00/year**
- Current: `synthetic-x86-large` · EUR 100.00/month total
- Candidate: `synthetic-arm-large`
- Required validation: Prove multi-architecture image and native dependency support.; Benchmark representative load and retain rollback.

### HETZ-COST-002 · Validate compute rightsizing

- Asset: `hcloud:server:1`
- Status: `needs_validation` · Risk: `medium` · Confidence: `0.72`
- Estimated saving: **EUR 40.00/month · EUR 480.00/year**
- Current: `synthetic-x86-large` · EUR 100.00/month total
- Candidate: `synthetic-x86-medium`
- Required validation: Collect guest RAM p95 and filesystem occupancy (`--node-metrics`).; Validate I/O peaks, SLO, and migration path.

### HETZ-COST-001 · Validate retirement of a stopped but billed server

- Asset: `hcloud:server:2`
- Status: `needs_validation` · Risk: `medium` · Confidence: `0.90`
- Estimated saving: **EUR 40.00/month · EUR 480.00/year**
- Current: `synthetic-old` · EUR 40.00/month total
- Candidate: `retire after owner, dependency, and restore validation`
- Required validation: Owner confirms the server is not a rollback or cold-standby asset.; Required data and restore points are preserved.

## Traffic

- Overage already incurred this period: EUR 0.00
- No server is above 80% of its included traffic.

## Data gaps

- Hetzner does not expose guest RAM utilization; add `--node-metrics` (see `hetzner-audit metrics`).
- Filesystem occupancy, workload SLOs, and application architecture constraints are not provider metrics.
- Catalog prices can differ from invoices, credits, taxes, and legacy contracts.
