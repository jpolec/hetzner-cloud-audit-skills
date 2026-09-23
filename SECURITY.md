# Security policy

## Supported versions

The latest release (v0.7.x) receives best-effort security fixes while the project is in alpha. Older versions are not patched; upgrade instead.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability that could expose credentials, infrastructure, or users. Until a dedicated private security contact is configured, use GitHub's private vulnerability reporting feature on the repository. Include the affected version, trust boundary, minimum safe reproduction, impact, and suggested fix. Do not test against infrastructure you do not own or have explicit authorization to assess.

## Operator responsibility

Use a read-only Hetzner token, keep SSH disabled unless required, inspect reports before sharing, and treat topology as sensitive. This tool does not authorize scanning or access.
