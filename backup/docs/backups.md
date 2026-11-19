# RELIC backups

This document describes the technical backup and restore design. The
step-by-step operator handoff is in [`backup-handoff.md`](backup-handoff.md).

## What a complete RELIC backup contains

A PostgreSQL dump alone is not a complete RELIC backup. A restorable RELIC
deployment needs:

1. **PostgreSQL** — the `relic` database and the cluster roles/globals.
2. **FIDBF objects** — files referenced by the relative `catalogue.fidbf`
   `storage_path` values.
3. **Provenance/BSim objects** — files referenced by the absolute
   `catalogue.provenance.storage_path` values.
4. **System signing keys** — the integrity and MMR private keys plus any
   passphrase files.
5. **Configuration** — PostgreSQL configuration and RELIC service configuration.
6. **A run manifest** — PostgreSQL version, database size, repository commit,
   migration list, age recipients, file checksums and timestamp.

The default paths on the RELIC VPS are:

```text
Database:              relic
FIDBF objects:         /srv/relic-objects
Provenance/BSim:       /srv/relic-data
System keys:           /var/lib/relic/keys
PostgreSQL config:     /etc/postgresql/15/main
Repository checkout:   /srv/relic
Backup staging:        /var/backups/relic
```

These are environment settings, not hard-coded assumptions. Keep the restored
object paths identical to the source paths unless the database paths have been
deliberately remapped.

## Backup design

The backup path is:

```text
VPS root systemd timer
  -> backup/scripts/backup-relic.sh
  -> pg_dump / pg_dumpall as postgres, streamed through age
  -> tar + zstd for objects, keys and config, streamed through age
  -> SHA-256 checksums and manifest
  -> rsync over SSH
  -> backup host incoming directory
  -> backup-host-retention.sh
  -> backup host archive directory
```

The upload account on the backup host is restricted with `rrsync -wo` to the
incoming directory. It can upload but cannot read or delete archived backups.
Retention runs separately on the backup host.

### Encryption

Every artifact is encrypted with `age` before it leaves the VPS. The VPS only
holds the public recipient. The private age identity:

- is generated on a trusted workstation;
- is stored offline in at least two locations;
- must never be placed on the VPS;
- must never be placed on the backup host;
- must never be committed to Git.

Multiple recipients are supported. If two people need independent restore
ability, configure both public recipients. Losing every copy of every private
identity makes the backups unreadable.

### Authentication

The VPS pushes with a dedicated Ed25519 SSH key. The public half is installed
on the backup host with a restricted `authorized_keys` entry. The host key must
be verified out of band and pinned in `known_hosts`; never use
`StrictHostKeyChecking=no` for production backups.

## Recovery objectives

The first version is a nightly logical backup:

| Objective | Current target |
| --- | --- |
| Recovery point objective (RPO) | Up to 24 hours |
| Recovery time objective (RTO) | Under 1 hour for the current sub-gigabyte data set |

This is appropriate for the current POC. If losing up to a day of submissions
becomes unacceptable, add PostgreSQL WAL archiving / pgBackRest PITR later. The
current cluster has `wal_level = replica` and `archive_mode = off`; enabling
PITR requires a reviewed PostgreSQL configuration change.

## Retention

Default local staging retention:

- keep completed local runs for 7 days;
- keep failed or unuploaded runs until an operator inspects them.

Default backup-host retention:

- 30 daily runs;
- one run per month for 12 months;
- incomplete runs stay in `incoming` and are reported.

The retention script never decrypts backups. It verifies ciphertext checksums,
the manifest checksum and the `COMPLETE` marker before archiving a run.

## Backup run layout

Each run is identified by a UTC timestamp such as `20261117T023000Z`.

```text
<run_id>-db.dump.age
<run_id>-globals.sql.age
<run_id>-fidbf-objects.tar.zst.age
<run_id>-provenance-objects.tar.zst.age
<run_id>-keys.tar.zst.age
<run_id>-config.tar.zst.age
<run_id>-manifest.json
<run_id>-SHA256SUMS
<run_id>-COMPLETE
```

The `COMPLETE` marker is uploaded last. A run without it is treated as
incomplete by the backup host and is not archived.

The manifest records:

- `run_id`, creation time and hostname;
- database name, PostgreSQL version and database size;
- `/srv/relic` Git commit and whether the checkout was dirty;
- the migration filenames present in the checkout;
- age recipients;
- every artifact name, size and SHA-256.

## Configuration

Copy [`backup/scripts/backup.env.example`](../scripts/backup.env.example) to
`/etc/relic/backup.env` as root, mode `0600`, and fill in the values.

The important settings are:

```bash
RELIC_DATABASE=relic
RELIC_PG_RUNAS=postgres
RELIC_BACKUP_STAGING=/var/backups/relic
RELIC_BACKUP_LOCAL_RETAIN_DAYS=7
RELIC_REPO_DIR=/srv/relic
RELIC_FIDBF_ROOT=/srv/relic-objects
RELIC_PROVENANCE_ROOT=/srv/relic-data
RELIC_KEYS_DIR=/var/lib/relic/keys
RELIC_PG_CONFIG_DIR=/etc/postgresql/15/main
RELIC_BACKUP_AGE_RECIPIENTS="age1..."
RELIC_BACKUP_REMOTE="relic-backup@backup-host:."
RELIC_BACKUP_SSH_KEY=/root/.ssh/relic_backup_ed25519
RELIC_BACKUP_SSH_PORT=22
RELIC_BACKUP_KNOWN_HOSTS=/root/.ssh/known_hosts
```

`RELIC_PG_RUNAS=postgres` uses `/usr/sbin/runuser` so `pg_dump` and
`pg_dumpall --globals-only` run with the PostgreSQL superuser's privileges.
An ordinary login such as `jp` can connect to `relic`, but cannot dump globals
or read `/var/lib/relic/keys`; the backup must run as root.

For a restricted `rrsync` account, use a remote path relative to the rrsync
base, usually `relic-backup@backup-host:.`. For a normal SSH account, use the
actual incoming directory:

```bash
RELIC_BACKUP_REMOTE="relic-backup@backup-host:/srv/backups/relic/incoming"
```

## Installation

### VPS

```bash
apt-get update
apt-get install -y age rsync zstd
```

`zstd`, `pg_dump`, `pg_dumpall`, `psql`, `tar`, `flock` and `runuser` are
normally already present on the RELIC VPS. The backup script checks all
dependencies and fails closed if anything is missing.

Create the configuration:

```bash
install -d -m 0755 /etc/relic
install -m 0600 /srv/relic/backup/scripts/backup.env.example /etc/relic/backup.env
editor /etc/relic/backup.env
```

Add the verified backup-host key to `/root/.ssh/known_hosts`, then install the
systemd units:

```bash
install -m 0644 /srv/relic/backup/systemd/relic-backup.service /etc/systemd/system/
install -m 0644 /srv/relic/backup/systemd/relic-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now relic-backup.timer
```

### Backup host

Run `backup/scripts/backup-host-setup.sh` as root on the backup host. It creates the
restricted account, incoming directory, archive directory and authorized key.
It also installs `backup/scripts/backup-host-retention.sh` when `--retention-script`
is supplied.

Then install the retention units on the backup host:

```bash
install -m 0644 /path/to/relic/backup/systemd/relic-backup-retention.service /etc/systemd/system/
install -m 0644 /path/to/relic/backup/systemd/relic-backup-retention.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now relic-backup-retention.timer
```

If the backup host is not systemd-based, schedule
`/usr/local/sbin/relic-backup-retention` with its native scheduler.

## Running a backup

Validate first:

```bash
/srv/relic/backup/scripts/backup-relic.sh --check
```

A database-only trial that stays local:

```bash
/srv/relic/backup/scripts/backup-relic.sh --db-only --no-upload
```

A database-only trial with upload:

```bash
/srv/relic/backup/scripts/backup-relic.sh --db-only
```

The first full backup:

```bash
/srv/relic/backup/scripts/backup-relic.sh
```

Useful options:

| Option | Meaning |
| --- | --- |
| `--check` | Validate dependencies, paths, database access, age recipient, staging space and remote configuration without writing a backup. |
| `--db-only` | Back up PostgreSQL and globals only. |
| `--skip-objects` | Skip the two object roots. |
| `--skip-keys` | Skip `/var/lib/relic/keys`. |
| `--skip-config` | Skip PostgreSQL/RELIC configuration. |
| `--no-upload` | Keep the encrypted run in staging and do not upload. |

A failed run leaves its local staging directory in place for inspection. It is
not removed by retention because it has no `UPLOADED` marker.

## Verification

The database verification SQL is
[`backup/scripts/sql/verify-relic-db.sql`](../scripts/sql/verify-relic-db.sql). It
checks:

- the database is present;
- the integrity chain has exactly one genesis and no broken `prev_hash` links;
- MMR checkpoints point at existing integrity rows;
- identity sequences are ahead of the maximum stored IDs.

When the BSim vector tables exist, `restore-relic.sh` also checks:

- vectors are linked to existing BSim objects;
- the stored source digest still matches the BSim object digest;
- feature counts, hash counts and vector norms match the stored features.

For a restore drill, use `verify-relic-backup.sh` on a trusted machine with the
age identity:

```bash
./backup/scripts/verify-relic-backup.sh \
  --run-dir /path/to/downloaded/<run_id> \
  --age-identity /offline/relic-backup-age.key \
  --pg-host localhost --pg-port 5432 --pg-user postgres
```

This creates a unique scratch database, restores the dump, runs the checks and
drops the scratch database. The age identity is not present on the VPS or
backup host.

## Restore

`restore-relic.sh` defaults to a database-only restore into `relic_restore`.
Assets must be requested explicitly:

```bash
./backup/scripts/restore-relic.sh \
  --run-dir /path/to/<run_id> \
  --age-identity /offline/relic-backup-age.key \
  --db-name relic \
  --db-owner relic_owner \
  --restore-globals \
  --restore-objects \
  --restore-keys \
  --restore-config \
  --force
```

Important safeguards:

- `--force` is required to replace an existing database or non-empty object,
  key or configuration destination.
- `--restore-config` always requires `--force`.
- `--preserve-owner` should only be used after the roles have been restored
  from the globals dump.
- The globals restore skips the built-in `postgres` role because every cluster
  already has it. Restore globals on a fresh cluster, or make sure the RELIC
  application roles do not already exist.
- Object restoration expects the database's absolute provenance paths to exist
  under the restored provenance root. Keep the original paths or deliberately
  remap them and update the database.
- The decrypted temporary directory is removed on exit unless `--keep-temp` is
  set.

After a full restore:

1. Verify the system key files against the public keys in
   `catalogue.user_public` for the system identities.
2. Restore or reinstall the RELIC service units.
3. Start PostgreSQL and the API.
4. Start or run the integrity/MMR workers only after the chain has been
   inspected.
5. Do not run a reconciliation worker that would create new evidence merely to
   make a restore look complete.

## Security notes

- The age private key is the only way to decrypt backups. Losing it is
  unrecoverable. Keep two offline copies.
- The VPS administrator can read the live database and system keys. Encryption
  protects backups in transit and at rest, not the live VPS from its
  administrator.
- The backup host account is write-only. Do not give it a shell or read access
  to the archive.
- Keep retention on the backup host. A compromised VPS must not be able to
  delete backup history.
- Do not commit backups, age identities, SSH private keys, real hostnames or
  server addresses to this repository.
- Rotate any password that has been shared outside a password manager. Use SSH
  keys for the VPS and the backup host.

## Limitations and future work

- Nightly logical dumps have a 24-hour RPO.
- `pg_dump` is a logical snapshot. It is portable and easy to verify, but it is
  not point-in-time recovery.
- The current object stores are backed up as full encrypted archives. The
  current data set is small enough for a daily full archive. If the BSim object
  store grows substantially, switch to an incremental object backup while
  keeping the same manifest and restore interface.
- BSim vector tables are derived data. They are included in the current dump
  for simplicity. Once the BSim vector importer and reindex path are reliable,
  the derived tables can be excluded from dumps and rebuilt after restore.
- A production deployment should add monitoring for backup failures, archive
  disk usage and restore-drill age. A backup is not proven until a restore has
  been tested.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `missing required commands` | Install `age`, `rsync`, `zstd` and the PostgreSQL client matching the server. |
| `pg_dump major version ... does not match` | Install the client package matching PostgreSQL 15. |
| `cannot query PostgreSQL server version` | Check `RELIC_PG_RUNAS`, peer authentication and the database name. |
| `age recipient rejected a test encryption` | Check the public recipient in `RELIC_BACKUP_AGE_RECIPIENTS`; do not put a private key there. |
| `local backup destination is not writable` | Check the local test destination; production should use an SSH remote. |
| rsync authentication fails | Check the dedicated key, pinned `known_hosts`, the `from=` restriction and the backup host’s `authorized_keys`. |
| Run stays in `incoming` | The `COMPLETE` marker is missing or the checksum/manifest verification failed. Inspect the journal and the run files. |
| Restore says a checksum failed | The run is corrupt or was modified in transit. Do not archive or restore it; restore an earlier run. |
| `--scratch refuses to use the live database name` | Choose a scratch name or omit `--scratch` for a deliberate live restore. |
