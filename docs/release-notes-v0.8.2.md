# v0.8.2 release notes

Correctness fixes for the diff and attack paths, from a fourth external review.

- **Diff shows every new ingress flow.** New flows from edge proxies (Cloudflare, Fastly, …) are listed under trusted flows; a strict regression can no longer fail CI without naming the flow.
- **Pivots are counted from the attacker's position.** The source of a `path` query is taken as already controlled; paths needing fewer compromised hosts win over shorter ones; a fully evidenced path that needs a pivot is `reachable_after_pivot`.
- **The exact diff scales.** A source-axis sweep keeps memory linear in the number of rules (2,500 heavily overlapping rules per side in about 5 seconds), with an input cap against crafted snapshots.

Real-world validation is still the main gap: the corpus in the repository is empty, and rules marked "fixtures only" have not been run against real accounts.
