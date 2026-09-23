# v0.4.0 release notes

v0.4.0 turns the audit from an inventory into a report an owner can act on. It also fixes how private networks are modeled.

## Fixed: Hetzner private networks are unfiltered

Hetzner Cloud Firewalls do not filter private network traffic ([Hetzner FAQ](https://docs.hetzner.com/cloud/firewalls/faq/)). Earlier versions derived private reachability from firewall rules with private source ranges. Those rules have no effect, so some paths were missed. Every member of a private network now reaches every port on every other member, and only host-firewall evidence can mark such a path as blocked. `HETZ-XLY-002` states this explicitly. **Upgrade from 0.3.x if you rely on lateral-path findings.**

## Highlights

- `hetzner-audit doctor` is a preflight check. It never prints the token, and it covers API access, per-endpoint readability, project scope, optional tools, and whether reports would land in a Git-tracked directory.
- Audit reports open with an **At a glance** page, then **Recommended actions**. Each action is ranked and shows the saving, the evidence level (HIGH, MEDIUM, or LOW, with the reason), the risk of acting, and the concrete next step.
- A **What this audit knows** section shows coverage (cost, utilization, ownership, backups, host evidence) and provenance (snapshot time, net catalog pricing, VAT and traffic excluded, no invoice reconciliation).
- Cost is split into immediately identifiable waste and optimization candidates that need telemetry. The report adds spend concentration, a storage-heavy heuristic, and replacement candidates for deprecated types, including cost delta, successor availability, and an ARM alternative.
- `hetzner-audit map` offers three SVG views, each with summary tiles, recommended actions, and a legend:
  - `--view architecture`: a cloud-architecture diagram with network zone, private network (VPC), location columns, and role tiers;
  - `--view connectivity`: entry points → private network → high-value hosts, with a blast-radius statement;
  - `--view cost`: per-VM catalog cost, status, component bars, CPU p95, and candidates.
- `--theme light|dark` and `--max-actions` options.
- Storage Box hostnames, which embed the account ID, are now redacted alongside emails, reverse DNS, usernames, and SSH key material.

## Safety

The tool is still read-only: GET requests only, no SSH, no port scans, no automatic remediation. Recommended actions are plans for a human.
