# RELIC backup handoff

This is the operator checklist for the person who owns the RELIC VPS and the
backup host. The project owner maintains the scripts and reviews the evidence;
the VPS/backup-host owner performs the root-level installation.

Do not commit real hostnames, IP addresses, SSH public keys, age identities or
passwords to the RELIC repository. Keep filled-in copies private.

Before starting, the project owner must commit and push these scripts. On the
VPS, update the root-owned checkout:

```bash
/srv/relic/scripts/update-server.sh
```

That updater refuses to run as a non-root user or when the checkout has
uncommitted changes.

## What is being backed up

A complete run contains:

- `relic` PostgreSQL database;
- PostgreSQL cluster roles/globals;
- FIDBF objects;
- provenance/BSim objects;
- RELIC system signing keys and passphrase files;
- PostgreSQL and RELIC configuration;
- a JSON manifest and SHA-256 checksums.

A database dump on its own is **not** a complete RELIC backup.

The default paths are:

```text
Database:              relic
FIDBF objects:         /srv/relic-objects
Provenance/BSim:       /srv/relic-data
System keys:           /var/lib/relic/keys
PostgreSQL config:     /etc/postgresql/15/main
Repository checkout:   /srv/relic
Backup staging:        /var/backups/relic
```

The account used for backups must be **root**. A normal login such as `jp` can
connect to the database, but cannot dump cluster globals or read
`/var/lib/relic/keys`.

## 1. Generate the age keypair

Install `age` on a trusted workstation (for example
`apt-get install -y age`), then run this on that workstation, not on the VPS
and not on the backup host:

```bash
age-keygen -o relic-backup-age.key
age-keygen -y relic-backup-age.key
```

Store the private key offline in at least two secure locations. Give the VPS
only the public recipient (`age1...`). The private key must never be copied to
the VPS or the backup host.

If a second person needs independent restore ability, generate a second
identity the same way and add both public recipients to the VPS configuration.

## 2. Generate the SSH transport key on the VPS

As root on the VPS:

```bash
ssh-keygen -t ed25519 -a 100 -N '' \
  -C 'relic-backup@vps' \
  -f /root/.ssh/relic_backup_ed25519
```

Keep the private key at `/root/.ssh/relic_backup_ed25519` with mode `0600`.
Send only the `.pub` file to the backup-host owner if that is a different
person.

## 3. Prepare the backup host

Run this as root on the backup host. The backup host must be Linux with SSH and
rsync, or provide equivalent `rrsync` support. Copy
`backup/scripts/backup-host-setup.sh` and `backup/scripts/backup-host-retention.sh` to the
backup host, or run them from a mounted copy of the repository.

```bash
./backup/scripts/backup-host-setup.sh \
  --public-key-file /path/to/relic_backup_ed25519.pub \
  --vps-ip <VPS_IP> \
  --base /srv/backups/relic \
  --retention-script ./backup/scripts/backup-host-retention.sh
```

The setup script:

- creates a restricted `relic-backup` account;
- creates `/srv/backups/relic/incoming` and `/srv/backups/relic/archive`;
- installs an `authorized_keys` entry restricted to
  `rrsync -wo /srv/backups/relic/incoming`;
- restricts the key to the VPS source address;
- installs the retention script when requested;
- prints the SSH host-key fingerprints.

The VPS account can upload but cannot read or delete the archive. Retention
runs on the backup host.

### Verify the host key

Send the fingerprint printed by the setup script through a channel other than
the VPS. On the VPS, compare it before adding the host to `known_hosts`:

```bash
ssh-keyscan -p 22 -t ed25519 <BACKUP_HOST> > /tmp/relic-backup-host.key
ssh-keygen -lf /tmp/relic-backup-host.key
# Compare the fingerprint with the backup host owner, then:
cat /tmp/relic-backup-host.key >> /root/.ssh/known_hosts
```

Do not use `StrictHostKeyChecking=no` for production backups.

## 4. Install the backup dependencies on the VPS

```bash
apt-get update
apt-get install -y age rsync zstd
```

`zstd`, `pg_dump`, `pg_dumpall`, `psql`, `tar`, `flock` and `runuser` are
normally already installed. The backup script fails closed if a dependency is
missing.

## 5. Create `/etc/relic/backup.env`

```bash
install -d -m 0755 /etc/relic
install -m 0600 /srv/relic/backup/scripts/backup.env.example /etc/relic/backup.env
editor /etc/relic/backup.env
```

Fill in at least:

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
RELIC_BACKUP_SSH_KEY=/root/.ssh/relic_backup_ed25519
RELIC_BACKUP_SSH_PORT=22
RELIC_BACKUP_KNOWN_HOSTS=/root/.ssh/known_hosts

# Restricted rrsync account: the path is relative to the rrsync base.
RELIC_BACKUP_REMOTE="relic-backup@<BACKUP_HOST>:."

# Normal SSH account alternative:
# RELIC_BACKUP_REMOTE="relic-backup@<BACKUP_HOST>:/srv/backups/relic/incoming"
```

Do not put an age private key or a password in this file.

## 6. Test the upload path

From the VPS as root:

```bash
rsync -a \
  -e "ssh -i /root/.ssh/relic_backup_ed25519 -p 22 -o BatchMode=yes -o StrictHostKeyChecking=yes" \
  /etc/hostname "relic-backup@<BACKUP_HOST>:."
```

With an `rrsync`-restricted account, the remote path is relative to the
configured rrsync directory. The file should appear in the backup host's
`incoming` directory. Remove the test file on the backup host after checking
it.

## 7. Install the systemd units on the VPS

```bash
install -m 0644 /srv/relic/backup/systemd/relic-backup.service /etc/systemd/system/
install -m 0644 /srv/relic/backup/systemd/relic-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now relic-backup.timer
systemctl list-timers relic-backup.timer
```

The timer runs daily at 02:30 UTC with a small randomized delay. It is
`Persistent=true`, so a missed run is attempted after the VPS comes back.

## 8. Validate and run the first backups

Run the read-only validation:

```bash
/srv/relic/backup/scripts/backup-relic.sh --check
```

Run a local database-only trial:

```bash
/srv/relic/backup/scripts/backup-relic.sh --db-only --no-upload
```

Inspect the reported staging directory and the manifest. Then run a
database-only upload:

```bash
/srv/relic/backup/scripts/backup-relic.sh --db-only
```

Finally run the full backup:

```bash
/srv/relic/backup/scripts/backup-relic.sh
```

The full run includes both object roots, the system keys and the configuration.

## 9. Install retention on the backup host

If the backup host uses systemd:

```bash
install -m 0644 /path/to/relic/backup/systemd/relic-backup-retention.service /etc/systemd/system/
install -m 0644 /path/to/relic/backup/systemd/relic-backup-retention.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now relic-backup-retention.timer
systemctl list-timers relic-backup-retention.timer
```

If it does not use systemd, schedule:

```text
/usr/local/sbin/relic-backup-retention
```

once per day from its native scheduler.

The retention defaults are:

- 30 daily runs;
- one run per month for 12 months;
- incomplete runs remain in `incoming` and are reported.

## 10. Restore drill

A backup is not working until it has been restored. Run this on a trusted
machine with the age private identity, not on the VPS.

1. Download one archived run directory from the backup host.
2. Verify the ciphertext and restore the database into a scratch database:

```bash
./backup/scripts/verify-relic-backup.sh \
  --run-dir /path/to/<run_id> \
  --age-identity /offline/relic-backup-age.key
```

3. For a full asset restore drill, use a scratch PostgreSQL host and separate
   destination roots:

```bash
./backup/scripts/restore-relic.sh \
  --run-dir /path/to/<run_id> \
  --age-identity /offline/relic-backup-age.key \
  --db-name relic_restore_drill \
  --restore-objects \
  --fidbf-root /srv/restore/relic-objects \
  --provenance-root /srv/restore/relic-data \
  --restore-keys \
  --keys-dir /srv/restore/relic-keys \
  --restore-config \
  --config-root /srv/restore/root \
  --force
```

A real disaster restore uses the production paths and the live database name,
for example:

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
  --preserve-owner \
  --force
```

Review `backup/docs/backups.md` before a live restore. After restoring:

- verify the key files against the system public keys in
  `catalogue.user_public`;
- restore/reinstall the RELIC service units;
- start PostgreSQL and the API;
- inspect the integrity chain and MMR checkpoints before starting workers;
- do not run a reconciliation worker merely to make the restore look complete.

## 11. What to send back as acceptance evidence

Please provide:

1. The output of `backup-relic.sh --check`.
2. The full path and size of the first completed run.
3. The run's manifest and `SHA256SUMS` (or a checksum of them).
4. The output of `systemctl list-timers relic-backup.timer`.
5. The backup host's `incoming`/`archive` listing for the run.
6. The output of a successful `verify-relic-backup.sh` restore drill.
7. Confirmation of where the age private key is stored offline.
8. Confirmation that retention is installed and scheduled.

Do not send the age private key, SSH private key or VPS password.

## Current VPS notes

- Debian 12 with PostgreSQL 15.
- `/srv/relic` is a clean checkout at the project's `main` branch.
- The RELIC database is `relic`.
- The object stores currently live at `/srv/relic-objects` and
  `/srv/relic-data`.
- System keys are under `/var/lib/relic/keys`, root-only.
- Confirm `age` and `rsync` are installed; they were missing when this handoff
  was prepared.
- Confirm whether a RELIC backup timer already exists; none existed at handoff
  time.
- A normal login can inspect the database, but the backup job must run as root
  because it needs cluster globals and the root-only key directory.

## Troubleshooting

| Problem | Check |
| --- | --- |
| `Permission denied (publickey,password)` | The VPS key is not in the backup host's `authorized_keys`, or `from=` does not match the VPS address. |
| `Host key verification failed` | Refresh the pinned host key after verifying its fingerprint with the backup host owner. |
| `rsync: command not found` on the backup host | Install `rsync`; the setup script expects `rrsync` to be available. |
| `age recipient rejected a test encryption` | The public recipient is malformed or the private key was pasted by mistake. |
| `RELIC_KEYS_DIR is not readable` | The script is not running as root, or the path is wrong. |
| Full backup succeeds but `incoming` is not archived | The `COMPLETE` marker is missing, or checksum/manifest verification failed. Check the backup host's journal. |
| `pg_dump major version` mismatch | Install the PostgreSQL 15 client package. |
| `--scratch refuses to use the live database name` | Use a scratch database name for verification. |
| Restore cannot find an object | The restored object root differs from the database's stored absolute provenance path. Keep the original paths or deliberately remap them. |

## Security checklist

- [ ] Age private key is offline, in two secure locations, and not on the VPS.
- [ ] Age public recipient is in `/etc/relic/backup.env`.
- [ ] SSH transport key is dedicated, mode 0600, and restricted on the backup host.
- [ ] Backup host key fingerprint was verified out of band before pinning.
- [ ] The VPS upload key is restricted to `rrsync -wo` and cannot delete backups.
- [ ] Retention runs on the backup host, not through the VPS upload account.
- [ ] `/etc/relic/backup.env` is mode 0600.
- [ ] The VPS account password was rotated after any password-based setup.
- [ ] No real hostnames, addresses, keys or passwords are committed to Git.
