# Read-only Hetzner token setup

Use a separate, short-lived audit token for each Hetzner Cloud project. Do not reuse an application, Terraform, or administrator token.

## Create the token

1. Sign in to the [Hetzner Console](https://console.hetzner.com/) and open the project to audit.
2. Open **Security** in the left menu and select **API tokens**.
3. Select **Generate API token**.
4. Use a recognizable description such as `security-audit-2026-09`.
5. Select **Read**, not **Read & Write**.
6. Copy the value into a password manager before closing the dialog. Hetzner does not show the full token again.

Hetzner's [official token guide](https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/) states that `Read` permits only `GET`; `Read & Write` additionally permits `POST`, `PUT`, and `DELETE`. Its [API guide](https://docs.hetzner.com/cloud/api/getting-started/using-api/) states that tokens are bound to the project in which they were created.

## Load it without shell-history exposure

For Bash or Zsh:

```sh
printf 'Hetzner read-only token: '
IFS= read -rs HCLOUD_TOKEN
printf '\n'
export HCLOUD_TOKEN
```

Run the audit, then remove the variable from the current shell:

```sh
hetzner-audit inventory --format json --output inventory.json --read-only --no-ssh
hetzner-audit audit --format json --output findings.json --read-only --no-ssh
unset HCLOUD_TOKEN
```

Environment variables are inherited by child processes. Run only trusted tools in that shell, do not enable shell tracing, and never ask an agent to print the variable. Prefer a password manager or CI secret store for repeated use.

## Multiple projects

A token cannot inventory another project. Audit projects separately and keep outputs explicitly labeled with the project and evidence timestamp. Do not merge snapshots as if they were collected under one authorization boundary.

## CI

Store the value as a masked repository or environment secret named `HCLOUD_TOKEN`. Pass it only to the audit step, do not expose it to pull requests from forks, and do not upload raw inventory as a public artifact. Prefer a dedicated audit project/member boundary where organizational policy permits it.

## Verify and revoke

The tool safely verifies token validity using read requests, but it cannot prove the permission class without attempting a write. It will never perform such a test. Confirm **Read** in Hetzner Console.

After a one-off audit, return to **Security → API tokens** and revoke the token. Revoke immediately if it appears in terminal output, chat, logs, repository history, or an untrusted process environment. Create a replacement rather than trying to recover the old secret.
