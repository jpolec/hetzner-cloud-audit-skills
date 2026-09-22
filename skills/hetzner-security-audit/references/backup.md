# Backup and restore module

Read metadata only. Never create, restore, delete, download, mount, or modify a backup or snapshot. Gather provider metadata, application backup declarations, retention, encryption/access policy, and owner-provided restore-test evidence.

Distinguish provider snapshots from application-consistent database recovery. Missing provider evidence is not proof that no backup exists. Keep absence-based candidates `needs_validation` unless all applicable mechanisms were collected. Assess blast radius, credential separation, retention, replication, and the most recent successful restore exercise.

