# v0.1.1 release notes

This prerelease hardens the evidence contract after an end-to-end test from a freshly installed Codex skill.

## Highlights

- Exact Hetzner Console steps for creating a project-bound **Read** token, masked shell loading, multi-project handling, and revocation.
- Pinned `uvx` execution path when the skill is installed but the CLI is not on `PATH`.
- Scanner signals remain `needs_validation` until runtime presence and the affected code path are evidenced.
- Provider firewall rules require listener and host-firewall evidence before public exposure is confirmed.
- Unverified and rejected records are unscored; severity remains separate from uncertainty.
- Evidence timestamps and source provenance are preserved.
- `hetzner-sec coverage` emits the ledger to stdout without writing a file.
- Schemas validate locally without resolving `example.invalid`.
- Experimental `hetzner-cost-audit` skill and cross-cloud architecture-recommendation schema.

The cost skill is methodology-only in this release. It does not yet collect utilization or claim production savings. v0.1.1 remains alpha and is not production-ready.
