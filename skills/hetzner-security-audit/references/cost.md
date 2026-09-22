# Cost and architecture correlation

Load this module only when the operator asks for cost/FinOps/architecture optimization or supplies utilization and price evidence. Do not add cost noise to a security-only audit.

Use the same rules as the standalone `hetzner-cost-audit` skill: read-only collection, timestamped prices, representative metric windows, explicit data gaps, no resize/delete/detach actions, and independent verification. Hetzner provider metrics cover CPU, disk, and network; guest RAM needs an authorized host or monitoring source.

Keep domain conclusions separate, then bundle compatible changes. A database may yield one architecture recommendation containing a verified resize candidate, private-network remediation, and restore-policy work. Savings may never justify weakening a security, resilience, SLO, RPO, or RTO requirement.

Emit `schemas/architecture-recommendation.schema.json` records. For multi-cloud reuse, normalize facts before analysis; keep Hetzner API paths, prices, products, and billing semantics in the provider adapter.
