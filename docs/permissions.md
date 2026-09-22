# Permissions and safe operation

Use a dedicated Hetzner Cloud API token with the **Read** permission. In the Hetzner Console, open the target project and select **Security → API tokens → Generate API token → Read**. Hetzner documents that this permission allows only `GET` requests. Tokens are project-bound and their full value is shown only once.

Set the token in the environment as `HCLOUD_TOKEN`; never place it in a command argument, prompt, repository, `.env` file, CI log, or report. The live collector performs paginated `GET` requests for inventory endpoints and exposes no create/update/delete interface. It never attempts a write to prove that a token is read-only; verify the selected permission in Console.

SSH is disabled by default. Enabling a host audit requires separate operator authorization, explicit hosts/users/keys, and the read-only command list in the Linux skill. External scanners are never run implicitly; their existing JSON can be ingested.

`--dry-run` makes no API request. Offline fixture use requires no credentials:

```sh
hetzner-sec audit --input snapshot.json --read-only --no-ssh
```

See [token setup](token-setup.md) for masked shell input, multi-project use, CI guidance, rotation, and revocation.
