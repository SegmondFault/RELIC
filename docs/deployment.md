# Deployment: one server, PostgreSQL on the host, API in Docker

```
internet ──443──▶ Caddy ──internal network──▶ API ──Unix socket──▶ PostgreSQL (host, 127.0.0.1 only)
                                                                   ▲
                       relic-ingest-fidbf, relic-checkpoint-mmr,   │ Unix socket, peer auth
                       relic-chain-bsim, relic-verify (host) ──────┘
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
    --integrity-system-user-id "$INTEGRITY_UID" --integrity-key /etc/relic/integrity_ed25519
target/release/relic-checkpoint-mmr --system-user-id "$MMR_UID" --key /etc/relic/mmr_ed25519
```

`relic-verify` uses `user=relic_auditor`; see `docs/workers.md` for cron.
Keep the system keys readable only by the user that runs the workers.

## 5. Check it

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
TCP to PostgreSQL and with a read-only socket mount; TLS and security headers
through Caddy; registration and the two-Moderator flow; FIDBF admission as
`relic_worker` (and its refusal as `relic_app`); signed claims; an MMR
checkpoint; and `relic-verify` passing, then catching a forged row. Everything
is removed afterwards (`RELIC_TEST_KEEP=1` keeps it for inspection).
