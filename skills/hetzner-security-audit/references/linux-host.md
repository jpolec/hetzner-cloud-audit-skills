# Linux host audit module

Use only when the operator explicitly enables SSH or supplies a host fixture. Require a least-privilege inspection account. Never use `sudo` unless separately approved; never change files, packages, services, firewall state, or authentication.

Allowed bounded reads include `ss -lntup`, `sshd -T`, `uname -a`, update status/simulation, `systemctl list-units`, `systemctl cat <named-unit>`, `ufw status`, `nft list ruleset`, `iptables-save`, mount metadata, and narrowly scoped permission metadata. Do not read secret contents or enumerate unrelated homes.

Collect effective sshd settings, sockets/binds, firewall policy, kernel/packages, update automation, AppArmor/SELinux, auditd, scheduled services, world-writable executable paths, mounts, and Docker socket permissions. Correlate sockets with Hetzner reachability and return facts/candidates only.


Prefer the owner-run bundle: `hetzner-audit host-bundle > host-bundle.sh`, show it to the owner, let them run it (`ssh HOST 'sudo HETZNER_AUDIT_SERVER=<server name> sh -s' < host-bundle.sh > HOST.bundle`), and pass the output with `--host-bundle`. Firewall layers the parser cannot read stay unknown, so related findings stay `needs_validation`.
