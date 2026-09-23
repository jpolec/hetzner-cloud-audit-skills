# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `hetzner-audit doctor` checks, without printing the token:
  - the Python version and token presence;
  - API access and per-endpoint readability;
  - project scope counts;
  - optional tools;
  - whether the report directory is Git-tracked, and whether a `.env` file holds the token.

  It exits non-zero on a missing or rejected token or unreadable core endpoints.
- The v0.4 roadmap in `docs/roadmap.md`.

### Changed

- Collector errors carry the HTTP status, so 401, 403, 404, and 429 can be told apart.

## [0.3.1] - 2026-09-23

### Added

- `hetzner-audit map` renders the network topology as Markdown with Mermaid, a dependency-free SVG, or JSON. Firewall sources are grouped into Internet, Cloudflare, Tailscale, private-network, and allow-listed classes, and public IP addresses are never printed.
- A README screenshot and example map from a real 18-server Hetzner project, with identifiers replaced.
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
- Maintainer attribution for Jakub Połeć and a discreet QuantJourney affiliation.

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

[Unreleased]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/releases/tag/v0.1.0
