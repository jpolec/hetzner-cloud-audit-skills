# PostgreSQL audit module

Use operator-provided configuration/catalog output or a role limited to catalog inspection. Never alter roles, grants, settings, extensions, data, backups, or replication. Do not collect password hashes or application data.

Collect `listen_addresses`, port/TLS, ordered `pg_hba.conf`, role attributes/memberships, risky grants, public-schema privileges, relevant extensions, logging, version/support, replication, backups, and restore-test evidence.

Correlate: Hetzner interface/routes → provider firewall → host firewall → Docker publication/network → PostgreSQL bind → first matching HBA rule → authentication → role privilege. Verify the exact HBA rule and source address. A broad bind alone is not a finding when the path is blocked; contradictory cross-environment reachability is material.

