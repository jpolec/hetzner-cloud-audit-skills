# Linux host audit module

Use only when the operator explicitly enables SSH or supplies a host fixture. Require a least-privilege inspection account. Never use `sudo` unless separately approved; never change files, packages, services, firewall state, or authentication.

Allowed bounded reads include `ss -lntup`, `sshd -T`, `uname -a`, update status/simulation, `systemctl list-units`, `systemctl cat <named-unit>`, `ufw status`, `nft list ruleset`, `iptables-save`, mount metadata, and narrowly scoped permission metadata. Do not read secret contents or enumerate unrelated homes.

Collect effective sshd settings, sockets/binds, firewall policy, kernel/packages, update automation, AppArmor/SELinux, auditd, scheduled services, world-writable executable paths, mounts, and Docker socket permissions. Correlate sockets with Hetzner reachability and return facts/candidates only.

