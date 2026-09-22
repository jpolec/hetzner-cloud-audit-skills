# Cloud audit module

Use for Hetzner servers, types, images, locations, networks/routes, firewalls, IPs, load balancers, volumes, snapshots/backups, SSH keys, labels, placement groups, DNS, and certificates.

Required permission: an authorized project token, preferably read-only, supplied only as `HCLOUD_TOKEN`. Allowed provider actions are API `GET` operations. Never log the token. Provider changes, power actions, console access, deletes, or firewall edits are prohibited.

Run `hetzner-sec inventory --format json --read-only --no-ssh`. Record successful and failed endpoints, then normalize IDs, public interfaces, labels, firewall attachments, network membership, protection, DNS, and backup state. Emit facts only. Missing evidence is `unknown`, not `false`. Before using absence as evidence, verify asset identity, pagination completeness, firewall attachment, endpoint coverage, and collection errors.

