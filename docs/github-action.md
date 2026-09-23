# GitHub Action

The repository includes a composite action for offline PR analysis and protected live audits. The action never embeds or requests a token as an input. For live collection, expose `HCLOUD_TOKEN` only through a repository or environment secret.

## Safe live audit

Run live collection only on `schedule` or `workflow_dispatch`. Do not expose the token to workflows executing untrusted fork code.

```yaml
name: Hetzner audit

on:
  workflow_dispatch:
  schedule:
    - cron: "17 4 * * *"

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    environment: hetzner-read-only
    steps:
      - uses: actions/checkout@v7
      - uses: jpolec/hetzner-cloud-audit-skills@v0.4.0
        env:
          HCLOUD_TOKEN: ${{ secrets.HCLOUD_TOKEN }}
        with:
          mode: audit
          policy: policies/infrastructure.toml
          format: sarif
          output: hetzner-audit.sarif
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: hetzner-audit.sarif
```

## Diff gate

Store snapshots as protected workflow artifacts or in an access-controlled evidence store. Do not commit real topology snapshots to a public repository.

```yaml
- uses: jpolec/hetzner-cloud-audit-skills@v0.4.0
  with:
    mode: diff
    baseline: evidence/previous.json
    input: evidence/current.json
    format: markdown
    output: infrastructure-diff.md
    fail-on-regression: true
```

For pull requests, prefer offline Terraform/fixture evidence. GitHub does not pass repository secrets to ordinary fork workflows, and the audit must not weaken that boundary.

## Failing the job

`fail-on` (audit mode) decides when the job fails:

| Value | Job fails when |
|---|---|
| `none` (default) | never; the report and SARIF are artifacts only |
| `confirmed` | any confirmed finding exists |
| `confirmed-high` | a confirmed finding is high or critical |

`needs_validation` findings never fail the job. They are hypotheses the Hetzner API cannot prove, such as a firewall rule without an observed listener. In SARIF they appear with level `none`, so code scanning shows them without raising alerts. A green job therefore means "nothing *confirmed* at this threshold". It does not mean the infrastructure is secure: host firewalls, listeners, and service configuration are not observed without host evidence.

