# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.8.2] - 2026-09-23

### Fixed

- `diff` lost new ingress from edge proxies: growth classified `edge:<provider>` fell between the world/wide and allow-list lists, so a strict regression could fail CI without showing the flow. New ingress is now partitioned into `new_exposures` (world, wide) and `new_trusted_flows` (allow-lists and edge proxies), with `new_ingress_flows` listing all of it.
- `path` counted leaving the query's source as a pivot. The source is taken as already controlled, so `--from web --to db` needs 0 pivots while `--from internet` needs 1.
- `path` picked the shortest path even when a slightly longer one needed no compromised host. It now minimizes pivots first, then length.
- A fully evidenced path that needs a pivot is `reachable_after_pivot`, not `reachable`.
- The flow-space difference is a sweep over the source axis with merged slabs: memory is linear in the number of rules (measured: 2,500 overlapping rules per side in about 5 s), with an input cap against crafted snapshots.

## [0.8.1] - 2026-09-23

### Security

- `anonymize` now renumbers every provider ID (also small ones and IDs inside text such as volume device paths), keeps label values only when they are generic words (environment `prod`/`staging`/…, `sensitivity`, `stateful`, `audit.ignore` true/false), reduces role labels to generic role words, and replaces label keys that carry a domain or name. A canary test plants an email, a domain, a customer name, and small IDs in every label and ID field.
- The Prometheus client follows redirects only to the same scheme and host, so the bearer token never travels to another host or over HTTP, and caps response size at 32 MiB.

### Documentation

- Release notes no longer describe the maintainer's own infrastructure.

## [0.8.0] - 2026-09-23

Correctness and validation before breadth: this release adds no new provider integrations.

### Added

- Exact flow-space `diff`: ingress and egress as source (or destination) address intervals × port intervals per family and protocol, subtracted exactly and classified afterwards. A /32 widened to /24, a swapped trusted address, or new egress is now a change. `--regression-policy broad|strict` (also an Action input).
- Egress model with Hetzner semantics (no outbound rule = all egress allowed). The summary counts servers that may connect anywhere; `[roles.<role>] internet_egress` in the policy raises `HETZ-EGR-001`.
- Load balancer IP targets: resolved to Cloud servers or Robot dedicated servers, otherwise kept as explicit endpoints.
- Typed attack-path hops (FILTER, FORWARD, ROUTE, PIVOT, RUNTIME); `path` reports whether a target is reachable directly or only after compromising another host, and what is known about the host layer.
- Every finding states whether its rule has been run on a live project or only on fixtures (report and SARIF `ruleMaturity`).
- `hetzner-audit anonymize` and `scripts/corpus_eval.py` for a real-world validation corpus; the headline metric is the false-confirmed rate.
- `--verify-public-buckets` makes the anonymous bucket check opt-in; `--allow-insecure-prometheus` for plain-HTTP Prometheus without a token.

### Changed

- "Verified savings" is now "measured savings": `diff` splits the catalog delta into the effect of your resource changes (both snapshots priced at the earlier catalog) and provider price changes. Neither is an invoice reconciliation.
- Rightsizing evidence names the real observation window instead of "30-day".
- The recommended skill install pins a release tag (`.../tree/v0.8.0`).

### Fixed

- `anonymize` kept wildcard binds and database ports so findings stay identical (found by its own round-trip test).
- The Prometheus token is only ever sent over HTTPS.
- Host bundles, answers files, and snapshots are size-checked before they are read.

### Documentation

- README: no claim that nothing leaves the machine (requests go to the providers you configure), "deterministic verification" in the pipeline diagram, egress and exact diff sections, corpus guide. Architecture, threat model (secrets in CI), and GitHub Action docs updated.

## [0.7.0] - 2026-09-23

v0.6 and v0.7 of the roadmap ship together as one release.

### Added — host evidence and drift

- `hetzner-audit host-bundle`: a reviewed, read-only shell script the owner runs on each server (UFW, nftables, iptables, `ss`, `sshd -T`, Docker inspection through an explicit template, `pg_hba.conf`, Redis bind/ACL). `--host-bundle FILE` (repeatable) merges the output. The tool itself still never connects to a host.
- Flow intersection: public exposure is `confirmed` when the Cloud Firewall, host firewall, and a listener all admit the port, and `rejected` when host evidence refutes it. Private-network reachability is evaluated per server, and Tailscale or Docker-bridge binds do not count as the Hetzner network.
- Host rules:
  - `HETZ-DKR-005`: Docker-published ports that bypass the host firewall;
  - `HETZ-DKR-006`: dangerous capabilities or sensitive host mounts;
  - `HETZ-SSH-001/002/003`: password login, root password login, empty passwords;
  - `HETZ-HOST-001`: no active host firewall;
  - `HETZ-HOST-002`: data services on all interfaces;
  - `HETZ-PG-003`: remote PostgreSQL authentication without TLS, in first-match order.
- Provider action history (last 30 days of `/actions`): `HETZ-CHG-001` protection switched off, `HETZ-CHG-002` firewall removed, `HETZ-CHG-003` reverse DNS changed, `HETZ-CHG-004` rescue, console, password reset, ISO, rebuild. Routine changes are counted in the summary only.
- Terraform drift (`--terraform`, from `terraform show -json` state or saved plan): `HETZ-IAC-002` unmanaged resources, `HETZ-IAC-003` deleted outside Terraform, `HETZ-IAC-004` drifted protection/backups/firewalls/labels, `HETZ-IAC-005` security-relevant pending plan changes. Firewall sources feed `HETZ-IAC-001`.
- Guest telemetry (`hetzner-audit metrics --prometheus URL`, `--node-metrics FILE`): RAM p95, RAM peak, and root filesystem peak gate rightsizing candidates. Savings are reported as theoretical, expected, and verified; `diff` measures verified savings.
- An end-to-end collector test on API-reference-shaped load balancer, certificate, and DNS responses.

### Added — beyond one project

- Multi-project: `snapshot --project NAME --token-env VAR`, then `merge`. `HETZ-XPR-001` flags a firewall that trusts another project's public address; `HETZ-XPR-002` flags production mixed with other environments.
- Hetzner Robot (`--robot`, GET-only webservice client or saved file): `HETZ-ROB-001` no active Robot firewall, `HETZ-ROB-002` sensitive ports admitted (first match, SYN-only, IPv4 and filtered IPv6, TCP and UDP), `HETZ-ROB-003` vSwitch coupled to a Cloud network, `HETZ-ROB-005` IPv6 not filtered. Robot keys go through the SSH key rules.
- Object Storage (`--object-storage`, stdlib SigV4 GET client verified against the AWS test vectors, or saved file): `HETZ-OBJ-001` public ACL, `HETZ-OBJ-002` wildcard bucket policy, `HETZ-OBJ-003` versioning off. One anonymous listing confirms public access.
- Kubernetes correlation (`--k8s`, from `kubectl get nodes,pods,services -A -o json`): `HETZ-K8S-001` NodePorts open to the Internet on nodes, `HETZ-K8S-002` workloads with node-level access; CCM/CSI detection.
- Console checklist (`hetzner-audit checklist`, `--attestations FILE`): `HETZ-ATT-001..007` for 2FA, member roles, Read & Write tokens, Robot login, S3 keys, Storage Box sub-accounts, and recovery contacts.
- Views: the architecture map shows load balancers, Kubernetes, Robot servers, vSwitches, buckets, and host flags. New `--view host` (per-VM layers) and `--view posture` (domain × severity matrix with coverage and evidence sources).
- The audit summary lists every evidence source, a per-server host table (reachable from the Internet and from the private network), and one line per optional source.
- Edge-provider registry: Cloudflare, Fastly, Bunny CDN, AWS CloudFront, Gcore, and Imperva recognized from their published, dated ranges (`scripts/update_provider_ranges.py`, `--check`). `HETZ-NET-006` now names whichever provider the origin bypasses; maps label edge sources with the provider (VIA CF, VIA FASTLY, …).
- Mesh VPNs: Tailscale, Headscale, NetBird, WireGuard, and ZeroTier are recognized by range, UDP port, or interface; their UDP ports never count as exposure.
- "No public ingress" is reported as the good pattern, with tunnel agents (Cloudflare Tunnel, ngrok, frp, Tailscale, NetBird, ZeroTier) named from the host bundle's new `agents` section or container images.
- README example gallery: four synthetic architectures (WireGuard + Fastly; zero ingress with Cloudflare Tunnel + Tailscale; k3s + Robot vSwitch + ZeroTier + Bunny CDN; load balancer + CloudFront + NetBird + Object Storage), reproducible with `scripts/make_gallery.py`.
- `docs/coverage.md`: every recognized component with its evidence source and an honest live/fixture status.
- `doctor` reports optional sources and credentials (values never printed) and warns when any secret sits in `.env`.
- The generated benchmark now scores 18 rules, all at 1.00 precision and recall.

### Fixed

- An adversarial review found about 30 defects before release; each has a regression test. The most important:
  - unreadable or missing host evidence (UFW without root, firewalld jump chains, no `ss`, nft errors, iptables-legacy hosts) could turn findings into `rejected`; unknown now stays `needs_validation`;
  - nftables comments, `ct state new`, interface matches, and protocol matches were misread; UFW IPv6 rules applied to IPv4; custom UFW app profiles were dropped;
  - a `pg_hba` reject line hid later lines it did not cover;
  - a host firewall rule for one private peer rejected lateral-path findings for the whole network;
  - Robot discard rules with flags or narrower matches hid later accepts; ACK-only accepts counted as open;
  - Object Storage settings that could not be read were reported as insecure;
  - merge failed on shared system images and dropped host, Terraform, and checklist evidence;
  - `diff` reported collection failures as verified savings.
- A second external review of the v0.5 code found that provider-level exposure ignored the public interface. Fixed across rules, graph, and diff:
  - a world-open firewall rule on a server without a public address (or without one in that address family) is no longer Internet exposure, no longer an attack-graph edge, and no longer a `diff` regression;
  - an all-ports rule on a firewall that protects no public server is a LOW latent hazard, not a confirmed HIGH finding, so `--fail-on confirmed-high` no longer trips on it;
  - `diff` also lists closed exposures (a removed rule or public IP).
- `HETZ-LB-004` reads the health of label-selector targets.
- Uploaded certificate PEMs are no longer stored in snapshots.
- Hypotheses keep the rule's proposed severity in metadata for views; they stay unscored.

### Changed

- Findings, policies, and coverage ledgers are validated against the JSON Schemas at runtime (standard library only; schemas ship in the wheel). A misspelled policy field is now an error instead of being ignored. Validation found two schema gaps that are fixed: rule IDs with digits (`HETZ-K8S-…`) and account- or Terraform-level findings without an asset (they now cite `account:hetzner` or `terraform:<address>`).
- Verifier method names say "deterministic" instead of "independent", which described more than the code does.
- Hypotheses keep the rule's proposed impact as `metadata.potential_severity`; `--severity` filters on it and reports show "potential HIGH".

### Security

- DNS snapshots keep record values only for A, AAAA, and CNAME. TXT, MX, CAA, and other values (often verification or ACME tokens) are replaced by a record count.
- Size caps for Trivy reports (128 MiB), policies (1 MiB), and coverage ledgers (64 MiB).
- The host script prints no environment variables, no sshd user lists, and no Redis passwords or ACL hashes.
- Object Storage XML is size-capped and rejected when it carries a DTD.

## [0.5.0] - 2026-09-23 (not tagged separately; included in 0.7.0)

### Added

- Firewall quality rules:
  - `HETZ-FW-001`: all ports open to the world, reported once instead of once per service;
  - `HETZ-FW-002`: unattached firewall, or a label selector that matches nothing;
  - `HETZ-FW-003`: IPv4/IPv6 drift;
  - `HETZ-FW-004`: duplicate rules.
- `HETZ-NET-002` now covers about 30 TCP/UDP services and ranges, including MySQL, RDP, SMB, Kafka, AMQP, Vault, Consul, etcd, kubelet, NodePort, SNMP, and memcached UDP.
- Rules for other resource types:
  - Storage Boxes (`HETZ-STO-001/002`);
  - OS end of support (`HETZ-IMG-001`);
  - load balancers (`HETZ-LB-001..005`);
  - certificates (`HETZ-CERT-001/002`);
  - DNS (`HETZ-DNS-001/002`);
  - placement spread (`HETZ-PLC-001`).
- `HETZ-GOV-004` flags servers that policy cannot evaluate because labels are missing. A new `sensitivity` label overrides name-based detection.
- `--fail-on none|confirmed|confirmed-high` for audit commands and the GitHub Action. `needs_validation` never fails a job.
- `scripts/check_cloudflare_ranges.py` and `CLOUDFLARE_RANGES_AS_OF`, which is cited in `HETZ-NET-006` evidence.

- Load balancers in the attack graph (Internet → LB listen port → target destination port, including label-selector targets). `ask` treats LB forwarding as direct exposure. `HETZ-LB-006` flags backends reachable directly.
- `flows.py`: an interval `PortSet` algebra and effective exposure per asset, keyed by (address family, protocol, source class).
- SSH key strength and age (`HETZ-KEY-001/002`). The collector records the algorithm and bits before redacting key material.
- `audit.ignore=true` and `audit.ignore.<RULE-ID>=true` owner labels. Suppressed findings are listed in the report.
- Suggested `hcloud` commands in recommended actions (deletion protection, labels, all-ports rules). They are for a human to review and are never run, and provider names are sanitized for the shell.
- Traffic usage against each server's included quota, overage already incurred, and an action above 80%.
- A generated-project benchmark (`scripts/benchmark_generated.py`): 150 random projects with ground truth, scored on TP/FP/FN per rule, plus a regression test.

### Fixed

- `audit --format json|sarif` crashed when `HETZ-NET-006` was present, because its evidence contained a set.
- `HETZ-DNS-002` no longer treats documentation ranges as private.

- `diff` compares sets of allowed flows instead of edge identities. Widened port ranges and IPv6-only openings are now regressions. A new public IP behind a deny-all firewall no longer is.
- `HETZ-XLY-002` was confirmed when host-firewall and listener evidence merely existed. It now needs a listening port that the host firewall admits, and is rejected otherwise.
- Servers count as stateful through database-like roles, names, or a `stateful` label, not only through attached volumes.
- Firewall assets from the API are no longer evaluated as loose rule sets. Their rules count only as the effective policy of the servers they are applied to.
- Cost recommendations record the real observation window and sample count. Rightsizing is skipped, with a data gap noted, when CPU data covers less than 80% of the requested window.

### Security

- Provider-sourced text is escaped in Markdown and entity-encoded in Mermaid, so crafted names cannot inject links, HTML, or headings into reports read by people or agents.
- Collector requests retry 429 and 5xx responses with jitter and honor `Retry-After`. Pagination is capped at 1,000 pages and attack-path search at 50 paths.
- CI audits the toolchain with OSV before installing the package, so PyPI outages no longer fail builds.
- GitHub Actions in `action.yml` and CI are pinned to commit SHAs.
- Input snapshots are capped at 256 MiB, 200k assets, and 1M edges.

### Changed

- README section 10 separates live-tested from fixture-tested rules and adds a "What it is not (yet)" list.

## [0.4.0] - 2026-09-23

### Added

- `hetzner-audit doctor` checks, without printing the token:
  - the Python version and token presence;
  - API access and per-endpoint readability;
  - project scope counts;
  - optional tools;
  - whether the report directory is Git-tracked, and whether a `.env` file holds the token.

  It exits non-zero on a missing or rejected token or unreadable core endpoints.
- The v0.4 roadmap in `docs/roadmap.md`.
- The audit report opens with an "At a glance" first page:
  - scope counts and locations;
  - confirmed findings and hypotheses that need host or runtime validation, grouped by rule;
  - findings rejected by the verifier;
  - failed endpoints and evidence layers the API cannot see;
  - catalog cost, with potential and confirmed savings.
- `map --format svg` now draws a cloud-architecture diagram in the style of AWS and OCI:
  - a network-zone boundary and the private network (VPC) with its subnets;
  - location columns crossed by role tiers, with service icons;
  - routed Internet and Cloudflare ingress, and Tailscale admin access;
  - a band for resources outside the private network, including Storage Boxes;
  - summary tiles and a legend.

- `map --view connectivity`: a per-VM bus diagram of the private network, highlighting sensitive hosts and each VM's ingress per trust class.
- `map --view cost`: a per-VM cost diagram showing catalog cost per VM, component bars, CPU p95, the best candidate saving, cost split by role, and resources outside servers.
- **Recommended actions**: ranked next steps with saving, evidence level (HIGH, MEDIUM, or LOW, with a reason), risk of acting, and next step. They cover:
  - public exposure and Cloudflare bypass;
  - blast radius on a shared private network;
  - the identity-plane access path;
  - deprecated types, with a replacement candidate, cost delta, same-family availability, and an ARM alternative;
  - unused resources, deletion protection, and backups;
  - storage-heavy servers and telemetry-bound optimizations.
- The report and diagrams show coverage (cost, utilization, ownership, backups, host evidence) and provenance (snapshot time, pricing basis, VAT and traffic excluded, no invoice reconciliation).
- Cost is shown as immediately identifiable waste vs optimization candidates that need telemetry, with top-3 and top-5 spend concentration and a storage-heavy heuristic (volumes above half the compute cost and at least EUR 10/month).
- The cost view gives each VM a status (REVIEW, DEPRECATED, COST, or OK). The connectivity view now shows entry points → network → high-value hosts, with a blast-radius statement, instead of a line per member.
- A `hetzner-audit` brand line on every diagram and README image, which now share one visual style.

### Fixed

- Private networks are now modeled as unfiltered, because Hetzner Cloud Firewalls do not filter private network traffic. Previously, reachability inside a network was derived from firewall rules with private source ranges, which have no effect. As a result, members without such rules looked unreachable. `HETZ-XLY-002` now says so explicitly and recommends a dedicated network or host firewall instead.

### Changed

- Collector errors carry the HTTP status, so 401, 403, 404, and 429 can be told apart.

## [0.3.1] - 2026-09-23

### Added

- `hetzner-audit map` renders the network topology as Markdown with Mermaid, a dependency-free SVG, or JSON. Firewall sources are grouped into Internet, Cloudflare, Tailscale, private-network, and allow-listed classes, and public IP addresses are never printed.
- A README screenshot and an example network map.
- `HETZ-GOV-003` reports servers running a deprecated Hetzner server type.
- Markdown audit and `path` output show asset names instead of numeric provider IDs.
- `HETZ-NET-006` flags web origins open to any address while peer servers accept web traffic only from Cloudflare.
- The package is published on PyPI as `hetzner-audit`, so `uvx hetzner-audit` works without a Git URL.

### Fixed

- A public IP address no longer counts as permitted traffic when a path is traced. `ask` previously reported private-network paths as Internet exposure; it now separates direct exposure from indirect pivots through a publicly reachable host.

### Security

- Snapshots now redact email addresses, reverse-DNS names, Storage Box usernames, and SSH public-key material and comments. Labels and graph-edge evidence are redacted too; previously they bypassed sanitization.

### Changed

- `hetzner-audit map --format svg` defaults to a light theme (grey canvas, white cards, exposure stripe); `--theme dark` keeps the previous look.
- README images use the same light style, and the token guide shows a console-style illustration with fictional data.
- README is restructured around a quick start, a no-token demo, and a safety model.
- Markdown reports merge single-asset findings that differ only by asset into one section. JSON and SARIF keep one finding per asset.
- The Python distribution is renamed from `hetzner-cloud-audit-skills` to `hetzner-audit`, matching the command name.

## [0.3.0] - 2026-09-22

### Added

- Temporal fact and snapshot schemas with collector version, run identity, source, and observation time.
- `snapshot`, coverage-aware `diff`, `path`, `explain`, constrained `ask`, and `cost` commands.
- API response normalization into firewall, public-interface, and private-network graph edges.
- Broad lateral-path, deletion-protection, and ownership rules for live Hetzner evidence.
- JSON/TOML owner policy and an example production trust policy.
- GitHub composite action with protected live-audit and diff-gate documentation.
- Catalog cost baseline, stopped-resource and rightsizing/ARM candidates, and non-overlapping monthly/annual potential savings.
- Maintainer attribution.

### Changed

- Narrowed the first-run product around public exposure, trust-boundary paths, and temporal drift.
- Repositioned cost analysis as experimental cross-domain architecture advice rather than a co-equal generic FinOps scanner.
- Collector failures are recorded per endpoint and cannot masquerade as deleted resources in a diff.
- README now exposes an honest capability matrix and API-only limitations.

## [0.2.0] - 2026-09-22

### Added

- First-class `hetzner-security-audit` and `hetzner-cost-audit` installation paths.
- Canonical `hetzner-audit` CLI with the existing `hetzner-sec` command retained as an alias.
- Concrete security and cost examples plus a synthetic cost recommendation screenshot.

### Changed

- Renamed the project and repository from `hetzner-security-skills` to `hetzner-cloud-audit-skills`.
- Reworked the README around inputs, outputs, measurable user value, safety boundaries, and limitations for both skills.
- Updated package metadata, schemas, SARIF identity, user agent, commands, and repository links.

## [0.1.1] - 2026-09-22

### Added

- Step-by-step read-only Hetzner token setup, masked shell loading, and revocation guidance.
- Pinned `uvx` fallback when an installed agent skill cannot find `hetzner-sec`.
- Read-only `hetzner-sec coverage` stdout command.
- Experimental `hetzner-cost-audit` skill and provider-neutral architecture-recommendation schema.

### Changed

- Unverified findings are unscored instead of receiving premature severity.
- Vulnerability findings require runtime-presence and affected-code-path evidence.
- Public-service exposure requires provider, listener, and host-firewall evidence.
- Evidence inherits collection timestamps and fixture provenance is no longer mislabeled as live API data.
- Finding schema references are self-contained and do not trigger remote resolution.
- Deterministic verification is no longer described as independent agent review.

## [0.1.0] - 2026-09-22

### Added

- GET-only Hetzner Cloud inventory collector and normalized evidence model.
- Typed attack graph, 16 rule IDs, deterministic verifier, and three-state findings.
- JSON, Markdown, and SARIF reports plus additive coverage ledger.
- Agent orchestrator and seven focused SKILL.md modules.
- Synthetic 33-problem benchmark, demo reports, schemas, tests, CI, and threat model.

[Unreleased]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.8.2...HEAD
[0.8.2]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.4.0...v0.7.0
[0.4.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/releases/tag/v0.1.0
