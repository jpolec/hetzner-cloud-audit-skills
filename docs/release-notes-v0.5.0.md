# v0.5.0 release notes

v0.5.0 closes the gap between what the collector gathers and what the analyzer reasons about. It also makes CI results honest about what they prove.

## Highlights

- **Firewall quality:** all-ports-open world rules, unattached firewalls and selectors that match nothing, IPv4/IPv6 drift, and duplicate rules.
- **About 30 sensitive services**, including UDP and port ranges: MySQL, RDP, SMB, Kafka, AMQP, Vault, Consul, etcd, kubelet, NodePort, SNMP, and memcached UDP.
- **New resource rules:**
  - Storage Boxes (external reachability, no snapshot plan);
  - OS end of support;
  - load balancers (plain HTTP, missing redirect, unhealthy or single target, idle);
  - certificates (expiring or failing to renew, unused);
  - DNS (records pointing at IPs the project does not own, which is a takeover risk, and private addresses in public zones);
  - placement spread.
- **Label governance:** servers without `environment` or `role` labels are reported, because policy silently skipped them. Add `sensitivity=high` to mark sensitive hosts explicitly.
- **CI honesty:** `--fail-on confirmed|confirmed-high` fails only on confirmed findings. Hypotheses never fail a job and stay at SARIF level `none`.

## Core correctness (from an external architecture review)

- **Semantic exposure diff:** `diff` now subtracts allowed-flow sets (`AFTER_ALLOWED` minus `BEFORE_ALLOWED`) per address family, protocol, and source class. Range widening and IPv6-only openings are caught. A new public IP behind a deny-all firewall is not a regression. The logic is property-tested against brute force.
- **Lateral-path confirmation** needs a listening port that the host firewall admits. Two non-empty but disjoint lists no longer confirm a path.
- **Load balancers in the attack graph**, plus detection of backends reachable directly around the LB.
- **Stateful detection** beyond attached volumes, and the **real metrics window** in cost recommendations, with a telemetry-coverage gate.

## Also new

- SSH key strength and age rules.
- `audit.ignore` owner labels, with suppressions always listed.
- Suggested `hcloud` commands in actions, for a human to review.
- Traffic quota and overage.
- A generated benchmark: 150 projects scored on TP/FP/FN.

## Hardening

- Retry with backoff on 429 and 5xx responses, honoring `Retry-After`; capped pagination and path search; snapshot size limits.
- GitHub Actions pinned to commit SHAs.
- Markdown and Mermaid escaping of provider text, which protects reports and agents from crafted names.
- JSON and SARIF output no longer crash on Cloudflare-bypass findings.
- The Cloudflare range list is dated and checkable (`scripts/check_cloudflare_ranges.py`).

## Coverage honesty

- **Tested on a live project:** firewall, service exposure, Storage Box, and label rules.
- **Fixture-tested only:** load balancer, certificate, and DNS rules, each with a positive case and a clean twin.

The README now lists what the tool is not yet: a host audit, a multi-project or Robot audit, Terraform drift, Kubernetes, compliance mapping, or billing reconciliation.
