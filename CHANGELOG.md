# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] - 2026-09-23

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

### Fixed

- `audit --format json|sarif` crashed when `HETZ-NET-006` was present, because its evidence contained a set.
- `HETZ-DNS-002` no longer treats documentation ranges as private.

### Security

- Provider-sourced text is escaped in Markdown and entity-encoded in Mermaid, so crafted names cannot inject links, HTML, or headings into reports read by people or agents.
- Collector requests retry 429 and 5xx responses with jitter and honor `Retry-After`. Pagination is capped at 1,000 pages and attack-path search at 50 paths.
- CI audits the toolchain with OSV before installing the package, so PyPI outages no longer fail builds.

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

[Unreleased]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/releases/tag/v0.1.0
