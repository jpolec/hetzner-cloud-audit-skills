# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/jpolec/hetzner-security-skills/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jpolec/hetzner-security-skills/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jpolec/hetzner-security-skills/releases/tag/v0.1.0
