# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `HETZ-GOV-003` reports servers running a deprecated Hetzner server type.
- Markdown audit and `path` output show asset names instead of numeric provider IDs.

### Fixed

- A public IP address no longer counts as permitted traffic when a path is traced. `ask` previously reported private-network paths as Internet exposure; it now separates direct exposure from indirect pivots through a publicly reachable host.

### Changed

- README is restructured around a quick start, a no-token demo, and a safety model.

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

[Unreleased]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/releases/tag/v0.1.0
