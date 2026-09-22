# v0.2.0 release notes

The project is now `hetzner-cloud-audit-skills`: one independent repository with two clear entry points.

## Security

Install `hetzner-security-audit` to correlate Hetzner state, network topology, host and container controls, PostgreSQL, Redis, IaC expectations, and scanner signals. Results retain evidence, attack paths, confidence, and one of three verification states.

## Cost

Install `hetzner-cost-audit` to evaluate rightsizing, idle and unattached resources, retention, architecture migrations, and scheduling. A recommendation must show its observation window, price basis, estimated saving, risk, prerequisites, validation, rollback, and security/reliability impact.

## Compatibility

`hetzner-audit` is the canonical CLI. `hetzner-sec` remains available as an alias. GitHub redirects the former repository URL, but new installations should use `https://github.com/jpolec/hetzner-cloud-audit-skills`.

The release remains alpha. The cost skill is evidence methodology plus a schema and synthetic example; automated production billing and utilization collectors are not yet complete.
