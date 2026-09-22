# Policy catalog

Policies document evidence contracts for implemented rules. Runtime logic lives in `src/hetzner_security/analyzers/rules.py`; `catalog.json` is the reviewable inventory used by tests and documentation. A policy is not a confirmed finding until its verifier contract succeeds.

The category directories explain planned and implemented coverage. v0.1 deliberately does not encode every conventional hardening preference as a finding.

