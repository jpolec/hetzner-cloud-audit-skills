---
name: hetzner-cloud-audit
description: Collect and assess authorized Hetzner Cloud assets in read-only mode as part of a Hetzner security audit.
---

# Hetzner Cloud Audit

Use for Hetzner servers, types, images, locations, networks/routes, firewalls, IPs, load balancers, volumes, snapshots/backups, SSH keys, labels, placement groups, and certificates.

Required permission: authorized project token, preferably read-only, supplied only as `HCLOUD_TOKEN`. Allowed actions are API `GET` operations. Never log the token. Provider changes, power actions, console access, deletes, or firewall edits are prohibited.

Workflow: run `hetzner-sec inventory --format json --read-only --no-ssh`; record successful and failed endpoints; normalize IDs, public interfaces, labels, firewall attachments, network membership, protection and backup state; emit facts only. Compare labels and observed state to explicit expectations only after collection. Missing evidence is `unknown`, not `false`.

Expected output: assets, edges, evidence timestamps, endpoint coverage, and candidate inputs. Verify asset identity, firewall attachment, pagination completeness, and collection errors before using absence as evidence.

