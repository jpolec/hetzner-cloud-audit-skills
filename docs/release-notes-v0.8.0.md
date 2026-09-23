# v0.8.0 release notes

v0.8.0 is about correctness and measurement, not new integrations. It follows three external reviews of v0.7.

## Highlights

- **Exact diff.** Exposure is now the exact set of (source address, port) pairs the firewalls admit, per family and protocol, for ingress and egress. Widening an allow-list from /32 to /24, swapping one trusted address for another, or opening Internet egress is a change; `--regression-policy strict` fails the job on it, `broad` keeps failing only on new world or wide exposure.
- **Egress.** Hetzner Cloud Firewalls allow all outbound traffic until a firewall has an outbound rule. The report now counts servers that can connect anywhere (on the maintainer's project: all of them, databases and vault included), and the policy can forbid it per role.
- **Hybrid load balancers.** IP targets resolve to Cloud or Robot dedicated servers, or stay visible as endpoints.
- **Typed attack paths.** `path` tells direct exposure apart from reachability after compromising another host.
- **Honest labels.** Every finding says whether its rule has been run on a live project or only on fixtures. "Verified savings" became "measured savings", split into the effect of your change and provider price changes.
- **Validation corpus.** `hetzner-audit anonymize` and `scripts/corpus_eval.py` let anyone contribute a labeled, anonymized project; the metric that matters is the false-confirmed rate.

## Security hardening

- The Prometheus token is only sent over HTTPS; the anonymous bucket check is opt-in (`--verify-public-buckets`); inputs are size-checked before reading.

## Still true

- Rules marked "fixtures only" have not been run against real accounts. The corpus is empty in the repository until independent projects are contributed.
