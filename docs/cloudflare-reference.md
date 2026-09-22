# Cloudflare security-audit-skill reference analysis

Reference reviewed: [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), including its README, `SKILL.md`, reconnaissance, hunting, attack-class, validation/reporting guidance, schemas, and deterministic validators. It is MIT licensed. No Cloudflare source code is copied into this repository.

## What its architecture does

Cloudflare's workflow starts by mapping architecture, entry surfaces, principals, trust boundaries, source-visible controls, and validation capability. It turns that map into deterministic coverage units rather than asking agents to “find bugs” without accounting. Isolated hunters own bounded units, return structured checks, and expose new gaps to coverage critics. Candidates are deduplicated by stable fingerprint/root cause.

A fresh agent then tries to disprove every candidate. The system distinguishes `confirmed`, `needs_validation`, and `rejected`; uncertainty is not encoded into severity. Schema validation rejects malformed records. A further independent pass checks final record claims before prose is derived. Prior ledgers and findings make later runs additive: unchanged confirmations are revalidated, changed areas regain priority, unresolved and deferred work remains visible, and exact rejected claims are not rediscovered without changed evidence.

The method reserves “finding” for a demonstrated trust-boundary failure. A missing secondary control is a hardening note when another observed layer actually stops the attack.

## Concepts reused

- reconnaissance before hunting;
- explicit principals, assets, entry surfaces, trust boundaries, and controls;
- deterministic coverage ledger and coverage-gap review;
- coverage-led assignments rather than free-form prompts;
- write and role separation between collectors/hunters/verifiers/reporters;
- stable candidate fingerprints and root-cause deduplication;
- a verifier that did not discover the candidate;
- `confirmed`, `needs_validation`, and `rejected` states;
- confidence separate from severity;
- strict machine-readable evidence and finding schemas;
- final report derived from validated records;
- prior-run ledgers as inputs to current coverage;
- defense-in-depth notes separated from demonstrated boundary failures.

## Concepts modified for infrastructure

Source locations become evidence locators across API responses, network edges, host commands, runtime inspection, database catalogs, scanner JSON, and IaC paths. The coverage identity is `(asset, layer, attack class)` in v0.1 and will grow to include evidence freshness and collector capability. “Local reproduction” becomes independent graph traversal and control evaluation; live probing is not required and is prohibited by default.

The deterministic CLI verifier is a separate component, not an independent agent. It confirms only complete rule contracts. Agent-discovered or materially interpretive candidates require a fresh agent/human reviewer; absent that, the skill keeps them as `needs_validation`. This limitation is disclosed rather than blurred.

Infrastructure state changes independently of Git commits, so prior findings are never carried solely because repository source is unchanged. Evidence time, provider inventory identity, and runtime collection coverage must still be re-established.

## Concepts not directly relevant

Language-specific attack classes, source-to-sink traces, native memory safety, HTTP parser differentials, browser behavior, and source-build sandbox artifact promotion are not core Hetzner infrastructure concerns. Repository/application review may delegate such work to dedicated source-security tooling. This project instead treats repository text as untrusted architectural evidence and avoids executing target-controlled code.

## Hetzner-specific additions

- live read-only discovery of Hetzner assets and attachments;
- public/private topology and directed reachability reconstruction;
- Terraform/IaC expectation versus provider-state drift;
- provider firewall + host firewall + Docker publication + service bind correlation;
- PostgreSQL HBA/auth/role context and Redis protected-mode/ACL context;
- cross-environment lateral paths over Hetzner private networks;
- container/host escape context attached to reachable workloads;
- external CVE signals reprioritized using actual exposure;
- database backup/recovery evidence linked to production state.

## Formal UX benchmark

Public release is blocked unless the installable top-level skill is comparable to Cloudflare's baseline in SKILL clarity, agent-neutral language, workflow discipline, evidence quality, independent verification, structured output, and installation simplicity. The Hetzner skill must exceed that baseline for infrastructure discovery, topology, drift, reachability, cross-layer database/runtime context, and attack paths.

The intended experience is:

```sh
npx skills add https://github.com/jpolec/hetzner-security-skills \
  --skill hetzner-security-audit
```

Then ask the agent: `audit my Hetzner infrastructure`. The orchestrator loads only relevant modules.

Cloudflare is a reference architecture, not a dependency, and neither project implies affiliation with the other.
