# v0.8.1 release notes

A security patch for v0.8.0.

- **`anonymize` is safe to share from.** Every provider ID is renumbered (including small IDs and IDs inside text such as volume device paths). Label values survive only when they are generic words (`prod`, `staging`, `high`, `true`, …); role labels keep only generic role words; label keys that carry a domain or a name are replaced. A canary test covers emails, domains, customer names, and small IDs in every label and ID field.
- **Prometheus token hardening.** Redirects are followed only to the same scheme and host, so the bearer token cannot leak to another host or over HTTP; responses are capped at 32 MiB.

Everything else is as in [v0.8.0](release-notes-v0.8.0.md).
