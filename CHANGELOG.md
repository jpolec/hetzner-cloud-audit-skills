# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Illustrated, step-by-step read-only token guide covering Console selection, safe shell and CI loading, verification limits, troubleshooting, and revocation.

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

[Unreleased]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jpolec/hetzner-cloud-audit-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jpolec/hetzner-cloud-audit-skills/releases/tag/v0.1.0
