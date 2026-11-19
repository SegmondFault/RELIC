# RELIC backup tooling

Everything related to RELIC backups lives here.

| Path | Purpose |
| --- | --- |
| [`docs/backups.md`](docs/backups.md) | Technical backup, restore, retention and security design. |
| [`docs/backup-handoff.md`](docs/backup-handoff.md) | Step-by-step handoff for the VPS/backup-host owner. |
| [`scripts/backup-relic.sh`](scripts/backup-relic.sh) | Root-only encrypted backup job. |
| [`scripts/restore-relic.sh`](scripts/restore-relic.sh) | Decrypt and restore a run. |
| [`scripts/verify-relic-backup.sh`](scripts/verify-relic-backup.sh) | Restore into a scratch database and verify it. |
| [`scripts/backup-host-setup.sh`](scripts/backup-host-setup.sh) | Prepare the restricted backup-host account. |
| [`scripts/backup-host-retention.sh`](scripts/backup-host-retention.sh) | Archive completed runs and apply retention. |
| [`scripts/backup.env.example`](scripts/backup.env.example) | Configuration template for `/etc/relic/backup.env`. |
| [`scripts/sql/verify-relic-db.sql`](scripts/sql/verify-relic-db.sql) | Database invariants checked after restore. |
| [`systemd/`](systemd/) | systemd service and timer units for the VPS and backup host. |

Start with the operator checklist in
[`docs/backup-handoff.md`](docs/backup-handoff.md).

Do not commit backup artifacts, age identities, SSH private keys, real
hostnames or server addresses. The documentation uses placeholders for
deployment-specific values.
