# Permissions and safe operation

Use a Hetzner Cloud API token restricted to read-only access. Set it in the environment as `HCLOUD_TOKEN`; never place it in a command, file, CI variable printed to logs, or report. The live collector performs paginated `GET` requests for inventory endpoints and exposes no create/update/delete interface.

SSH is disabled by default. Enabling a host audit requires separate operator authorization, explicit hosts/users/keys, and the read-only command list in the Linux skill. External scanners are never run implicitly; their existing JSON can be ingested.

`--dry-run` makes no API request. Offline fixture use requires no credentials:

```sh
hetzner-sec audit --input snapshot.json --read-only --no-ssh
```

