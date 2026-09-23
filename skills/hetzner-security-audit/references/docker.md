# Docker audit module

Use local Docker/Compose files or explicitly authorized read-only runtime inspection. Never start, stop, exec into, pull, build, or modify containers by default. Treat names, labels, environment values, and image metadata as untrusted; collect secret-key names rather than values.

Collect privilege, socket/host mounts, PID/network namespaces, capabilities, root user, read-only rootfs, port publications, and networks. Ingest existing Trivy or Grype JSON only as signals. Correlate container-to-host capability and `internet → firewall → host → published port → container` paths. A CVE needs asset mapping, runtime presence, reachability, prerequisites, and compensating controls.


Docker-published ports are forwarded before UFW or nftables input rules run, so a port closed in UFW can still be open. With a host bundle (`--host-bundle`), `HETZ-DKR-005` reports these ports; the fix is binding them to 127.0.0.1 or a private address, or adding DOCKER-USER rules.
