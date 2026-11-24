# Deployment: one server, PostgreSQL on the host, API in Docker

```
internet ──443──▶ Caddy ──internal network──▶ API ──Unix socket──▶ PostgreSQL (host, 127.0.0.1 only)
                                               │  ▲                ▲
                          writes /var/lib/relic/staging            │ Unix socket, peer auth
                          reads  /srv/relic-objects (read-only)    │
                                                                   │
              relic-admit, relic-checkpoint-mmr, relic-verify, ────┘
              relic-ingest-fidbf, relic-chain-bsim (host)
```

- PostgreSQL keeps listening on `127.0.0.1` only. No database port is opened
  to Docker or the network: the API reaches PostgreSQL through its Unix
  socket, which `docker-compose.yml` mounts read-only into the container.
- The API's Docker network is `internal`: the container can talk to Caddy and
  the socket, nothing else. A compromised API cannot reach the internet.
- The Rust tools run on the host as the operator's user (e.g. `ns`) and log in
  by peer authentication: no worker or auditor password exists to be stolen.
- `pg_hba.conf` refuses every RELIC login over TCP, so a stolen password is
  useless from anywhere but the socket.
- The API never holds the integrity key. FIDBF, BSim and provenance
  submissions (each takes an integrity-chain entry) are staged by the API and
  admitted by `relic-admit` on the host, which verifies every signature.

`scripts/test-infrastructure.sh` builds exactly this layout in a temporary
directory and checks it end to end (see the end of this page).

## 1. PostgreSQL (host)

`postgresql.conf`: keep the defaults this layout relies on.

```
listen_addresses = 'localhost'                     # never '*'
unix_socket_directories = '/var/run/postgresql'    # Debian default
password_encryption = scram-sha-256
```

`pg_hba.conf`: put these lines **above** the distribution's
`local all all peer` line (the first matching line wins). Leave the
distribution's lines for `postgres` as they are.

```
# TYPE  DATABASE  USER                                  ADDRESS  METHOD
local   relic     relic_worker,relic_auditor                     peer map=relic
local   relic     relic_app                                      scram-sha-256
host    all       relic_app,relic_worker,relic_auditor  all      reject
```

`pg_ident.conf`: which OS users may act as the worker and auditor roles.

```
# MAPNAME  SYSTEM-USERNAME  PG-USERNAME
relic      ns               relic_worker
relic      ns               relic_auditor
```

To separate duties, create dedicated OS users (e.g. `relic-worker`,
`relic-verify`) and map each only to its role.

Apply with `sudo systemctl reload postgresql`.

## 2. Roles

Migration 008 creates `relic_worker` and `relic_auditor` without login rights.
With peer authentication they need no password:

```sql
ALTER ROLE relic_worker LOGIN;
ALTER ROLE relic_auditor LOGIN;
ALTER ROLE relic_app LOGIN PASSWORD '<long random password>';
```

## 3. API (`database/api/.env`)

```
RELIC_HOST=<public host name>
RELIC_DATABASE_URL=postgresql://relic_app:<password>@/relic?host=/var/run/postgresql
RELIC_JWT_SECRET=<at least 32 random characters>
```

URL-encode the password if it contains `@`, `/`, `:` or `%`. If the socket is
elsewhere, set `RELIC_PG_SOCKET_DIR` for `docker compose`; the container
always sees it at `/var/run/postgresql`. Then:

```bash
cd /srv/relic/database/api && docker compose up -d --build
```

## 4. Rust tools on the host

Connection string (key-value form, socket, no password):

```bash
export RELIC_DATABASE_URL='host=/var/run/postgresql dbname=relic user=relic_worker'
target/release/relic-ingest-fidbf --manifest signed.json --fidbf-object object.fidbf \
    --integrity-system-user-id "$INTEGRITY_UID" --integrity-key /var/lib/relic/keys/integrity_ed25519
target/release/relic-checkpoint-mmr --system-user-id "$MMR_UID" --key /var/lib/relic/keys/mmr_ed25519
```

`relic-verify` uses `user=relic_auditor`; see `docs/workers.md` for cron.

### System keys

The integrity and MMR private keys live in `/var/lib/relic/keys`, where the
backup (`backup/`, `RELIC_KEYS_DIR`) expects them. Only the user that runs the
workers may read them; the backup runs as root and reads them regardless:

```bash
sudo install -d -m 0700 -o ns -g ns /var/lib/relic/keys
sudo install -m 0600 -o ns -g ns integrity_ed25519 mmr_ed25519 /var/lib/relic/keys/
```

With a dedicated worker user (see section 1), give the directory to that user
instead of `ns`. The API never reads these keys, and the directory is not
mounted into any container.

### Hourly MMR checkpoint (systemd timer)

An integrity entry gets an inclusion proof only once a signed checkpoint
covers it; until then `GET /v1/integrity/{id}/proof` answers `409`. So
`relic-checkpoint-mmr` runs every hour. It is safe to run often: when the
latest checkpoint already covers the whole chain it verifies it and exits
without inserting anything, and a run can never overlap the previous one
(one `oneshot` unit). Every run rebuilds the chain from genesis, which is cheap
at today's size; revisit the interval if the chain grows into millions of rows.

`/etc/relic/mmr.env` (mode 0600, owner `ns`):

```
RELIC_DATABASE_URL=host=/var/run/postgresql dbname=relic user=relic_worker
RELIC_MMR_SYSTEM_USER_ID=<MMR system account>
RELIC_MMR_KEY=/var/lib/relic/keys/mmr_ed25519
# RELIC_MMR_KEY_PASSPHRASE_FILE=/var/lib/relic/keys/mmr_ed25519.pass   (only if the key has a passphrase)
```

`/etc/systemd/system/relic-checkpoint-mmr.service`:

```ini
[Unit]
Description=RELIC MMR checkpoint (one run)
After=postgresql.service

[Service]
Type=oneshot
User=ns
EnvironmentFile=/etc/relic/mmr.env
ExecStart=/srv/relic/target/release/relic-checkpoint-mmr
TimeoutStartSec=30min
NoNewPrivileges=true
ProtectSystem=strict
PrivateTmp=true
```

`/etc/systemd/system/relic-checkpoint-mmr.timer`:

```ini
[Unit]
Description=Hourly RELIC MMR checkpoint

[Timer]
OnCalendar=hourly
AccuracySec=1m
# Run once at boot if the machine was off at the scheduled time.
Persistent=true
Unit=relic-checkpoint-mmr.service

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl start relic-checkpoint-mmr.service    # first run now; prints the checkpoint as JSON
sudo systemctl enable --now relic-checkpoint-mmr.timer
systemctl list-timers relic-checkpoint-mmr.timer     # next and last run
journalctl -u relic-checkpoint-mmr -n 50
```

A failed run leaves the unit in the `failed` state and the previous checkpoint
untouched, so the next run simply tries again. To check that checkpoints are
fresh, run this as `relic_auditor` from the hourly `relic-verify` cron job or
any monitoring that can run SQL:

```sql
-- No row: no checkpoint yet. uncovered_entries grows as entries are admitted
-- and falls back to 0 after each run; alert if it stays above 0 for ~2 hours.
SELECT (SELECT count(*) FROM catalogue.integrity) - c.leaf_count AS uncovered_entries,
       now() - c.created_at AS age
FROM catalogue.mmr_checkpoint c
ORDER BY c.mmr_checkpoint_id DESC LIMIT 1;
```

`age` is the age of the newest checkpoint, so it also grows when nothing new
was admitted. Read it together with `uncovered_entries`: an old checkpoint is a
problem only if `uncovered_entries` is not 0.

### Pinning the MMR public key

An inclusion proof shows that an entry is in a checkpoint **signed by the key
you give the verifier**. If a client takes that key from the same API that
serves the proof, whoever controls the API can serve its own key, checkpoint
and proof together, and everything verifies. The key must come from somewhere
the API does not control: the operator publishes a *pin* once, and verifiers
keep it.

The pin is the MMR system account's user id and its Ed25519 public key (64
lowercase hex characters, the form `relic-verify-proof --public-key` takes).

Operator, once, when the key is created. On the host, derive the pin from the
key file (add `-P "$(cat <passphrase file>)"` if the key has a passphrase):

```bash
ssh-keygen -y -f /var/lib/relic/keys/mmr_ed25519 \
    | awk '{print $2}' | base64 -d | tail -c 32 | od -An -v -tx1 | tr -d ' \n'; echo
```

Then check that it is the key the database knows for the MMR account. Both
commands must print the same 64 characters (the worker also refuses to run
with a key that does not match its registered account):

```bash
curl -s -H "Authorization: Bearer $TOKEN" "$API/v1/users/$MMR_UID" | jq -r .public_key
```

Each installation generates its own key during its initial setup, so the pin
belongs to that installation's operator. Give `MMR user id + public key`
directly to each partner that verifies proofs, by a channel other than the
API, and publish it where they can find it independently of the API (the
operator's own site, or [`mmr-public-key.md`](mmr-public-key.md) in this
repository if you want to record it here, via a pull request that a second
person checks against the server). That file also says how to hand it over
and how to replace a key. A change of the published pin is a security event,
not routine news.

Verifier: always pass the pinned value, never one read from the API:

```bash
PIN=<64 hex characters from the operator>
relic-verify-proof --proof proof.json --checkpoint checkpoint.json \
    --public-key "$PIN" --chain-hash "$CHAIN_HASH"
```

If the key ever has to change, create a new MMR system account and key,
publish the new pin **before** its first checkpoint, and keep the old pin:
checkpoints signed by the old key stay verifiable with it. This has not been
rehearsed end to end, and key custody and rotation as a whole remain an open
decision in [`integrity-mmr.md`](integrity-mmr.md#decisions-still-open).

## 5. Object storage and `relic-admit`

The API stages uploaded FIDBF objects in `/var/lib/relic/staging` (its only
writable mount) and serves admitted ones from `/srv/relic-objects` (mounted
read-only). `relic-admit` reads the staging directory and writes the store.
**Give staging a filesystem of its own.** The API caps staging at 4 GiB,
but a compromised API ignores its own cap; on a separate, fixed-size
filesystem it can fill only that, never the disk PostgreSQL writes to. A
loop-mounted image needs no repartitioning:

```bash
sudo install -d -m 0700 /var/lib/relic
sudo fallocate -l 5G /var/lib/relic/staging.img          # a little above the 4 GiB cap
sudo mkfs.ext4 -q -m 0 /var/lib/relic/staging.img
sudo install -d /var/lib/relic/staging
echo '/var/lib/relic/staging.img /var/lib/relic/staging ext4 loop,nodev,nosuid,noexec 0 2' \
    | sudo tee -a /etc/fstab
sudo mount /var/lib/relic/staging
findmnt /var/lib/relic/staging      # must show its own ext4 filesystem, not /
```

The container runs as uid 10001; give it the staging directory with the
worker's group, so the worker can read and remove what it staged:

```bash
sudo chown 10001:ns /var/lib/relic/staging && sudo chmod 2770 /var/lib/relic/staging  # setgid: files get group ns
sudo install -d -o ns -g ns -m 0755 /srv/relic-objects          # the API only reads it
```

(With a dedicated worker user, use its group and owner instead of `ns`.) If
either directory lives elsewhere, set `RELIC_STAGING_DIR` and
`RELIC_FIDBF_ROOT` for `docker compose`; the container always sees them at
these paths. The backup (`RELIC_FIDBF_ROOT` there too) covers the store; the
staging area holds only uploads not yet admitted.

`relic-admit` runs as a service. `/etc/relic/admit.env` (mode 0600, owner
`ns`):

```
RELIC_DATABASE_URL=host=/var/run/postgresql dbname=relic user=relic_worker
RELIC_INTEGRITY_SYSTEM_USER_ID=<integrity system account>
RELIC_INTEGRITY_KEY=/var/lib/relic/keys/integrity_ed25519
```

`/etc/systemd/system/relic-admit.service`:

```ini
[Unit]
Description=RELIC admission of staged FIDBF, BSim and provenance submissions
After=postgresql.service

[Service]
User=ns
EnvironmentFile=/etc/relic/admit.env
ExecStart=/srv/relic/target/release/relic-admit --poll-seconds 5
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/relic/staging /srv/relic-objects
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`sudo systemctl enable --now relic-admit`. It handles one submission at a
time, prints one line per outcome (`journalctl -u relic-admit`), retries a
transient failure up to five times, and removes staged uploads abandoned for
more than 24 hours. It refuses to start unless its integrity account exists,
is an active system account and matches its key. A rejected submission's
reason, shown to the submitter, never includes PostgreSQL's detail (which
can name other rows); the worker's log keeps it.

Upload and download limits (the API's `.env`; defaults shown):

| Setting | Default | Effect |
|---|---|---|
| `RELIC_MAX_OBJECT_BYTES` | 64 MiB | one upload; Caddy enforces the same |
| `RELIC_MAX_STAGING_BYTES` | 4 GiB | all staged uploads, the incoming one included (`507`) |
| `RELIC_MAX_UPLOADS_PER_ANALYST` | 2 | uploads in progress per Analyst (`429`) |
| `RELIC_MAX_UPLOADS_TOTAL` | 8 | uploads in progress overall (`503`) |
| `RELIC_UPLOAD_BYTES_PER_ANALYST_PER_DAY` | 1 GiB | bytes one Analyst may upload in 24 h (`429`) |
| `RELIC_DOWNLOAD_RATE_LIMIT_PER_HOUR` | 120 | FIDBF downloads per account (`429`) |

Caddy drops a client that takes more than 10 s to send its headers or more
than `RELIC_READ_BODY_TIMEOUT` (default 5 minutes, set for `docker compose`)
to send its body, so slow clients cannot hold the API's connections; raise
it if Analysts upload large objects over slow links. The in-process limits
assume one API worker process, like the rate limits.

## 6. Check it

On the server (or any machine with Docker and the PostgreSQL server
binaries), without touching the production database:

```bash
RELIC_TEST_PG_BIN=/usr/lib/postgresql/<version>/bin scripts/test-infrastructure.sh
```

It starts its own PostgreSQL with the configuration above on port 55440 (only
in a temporary directory), runs the production compose file as project
`relic-infra-test` with Caddy on `127.0.0.1:18443` and a local CA, and checks:
loopback-only listening; every RELIC login refused over TCP; peer and
password logins over the socket; the API container without internet, without
TCP to PostgreSQL and with read-only socket and object-store mounts; TLS and security headers
through Caddy; registration and the two-Moderator flow; FIDBF admission as
`relic_worker` (and its refusal as `relic_app`); signed claims; a FIDBF
upload, BSim object and provenance seal through Caddy, admitted by
`relic-admit`, and the FIDBF downloaded back byte for byte; a full staging
area refusing an upload, a stalled upload dropped by Caddy, and the
per-account download limit; an MMR
checkpoint; and `relic-verify` passing, then catching a forged row. Everything
is removed afterwards (`RELIC_TEST_KEEP=1` keeps it for inspection).
