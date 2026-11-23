#!/usr/bin/env bash
# End-to-end test of the production topology on this machine:
#
#   PostgreSQL on the host  - listens on 127.0.0.1 only; pg_hba/pg_ident exactly
#                             as docs/deployment.md (RELIC logins never over TCP)
#   API + Caddy in Docker   - database/api/docker-compose.yml unchanged except
#                             test overrides (local CA, port, test secrets)
#   Rust tools on the host  - relic-ingest-fidbf, relic-checkpoint-mmr and
#                             relic-verify over the Unix socket with peer auth
#
# It registers accounts and makes signed claims through Caddy, admits a FIDBF,
# checkpoints the MMR, runs relic-verify, and checks that every forbidden path
# is refused. Everything runs in a temporary directory and is removed on exit.
#
# Needs: docker compose, PostgreSQL server binaries (RELIC_TEST_PG_BIN, default
# /usr/lib/postgresql/17/bin), cargo, ssh-keygen, curl, python3, openssl, ss.
# RELIC_TEST_KEEP=1 keeps the database, containers and files for inspection.

set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pg_bin="${RELIC_TEST_PG_BIN:-/usr/lib/postgresql/17/bin}"
pg_port="${RELIC_TEST_PG_PORT:-55440}"
https_port="${RELIC_TEST_HTTPS_PORT:-18443}"
project="relic-infra-test"
me="$(id -un)"
work="$(mktemp -d)"
sock="$work/socket"
# The API's staging directory and the FIDBF object store. Production gives
# the staging directory to the container's user with the worker's group
# (docs/deployment.md); here the container (uid 10001) only needs to write.
staging="$work/staging"
store="$work/objects"
data="$work/data"
target="$repo/target/debug"
api="https://localhost:${https_port}/v1"
app_password="$(openssl rand -hex 24)"
pass=0
fail=0

compose() {
    RELIC_HOST=localhost RELIC_PG_SOCKET_DIR="$sock" RELIC_STAGING_DIR="$staging" \
        RELIC_FIDBF_ROOT="$store" docker compose -p "$project" \
        --env-file "$work/compose.env" \
        -f "$repo/database/api/docker-compose.yml" -f "$work/override.yml" "$@"
}

cleanup() {
    if [[ -n "${RELIC_TEST_KEEP:-}" ]]; then
        printf '\nKept for inspection: %s (compose project %s). Remove with:\n' "$work" "$project"
        printf '  RELIC_HOST=x docker compose -p %s down -v; %s/pg_ctl -D %s stop; rm -rf %s\n' \
            "$project" "$pg_bin" "$data" "$work"
        return
    fi
    compose down -v --remove-orphans >/dev/null 2>&1
    "$pg_bin/pg_ctl" -D "$data" -m immediate stop >/dev/null 2>&1
    rm -rf "$work"
}
trap cleanup EXIT

check() { # name expected actual (an empty expected value is a test bug, never a pass)
    if [[ -n "$2" && "$2" == "$3" ]]; then
        printf 'PASS  %s\n' "$1"; ((pass++))
    else
        printf 'FAIL  %s\n      expected: %s\n      got:      %s\n' "$1" "$2" "$3"; ((fail++))
    fi
}
refused() { # name command...: passes if the command fails
    if "${@:2}" >/dev/null 2>&1; then check "$1" refused allowed; else check "$1" refused refused; fi
}
step() { printf '\n== %s\n' "$1"; }
die() { printf 'ABORT %s\n' "$1" >&2; exit 1; }
field() { python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
owner_sql() { "$pg_bin/psql" -XqAt "host=$sock port=$pg_port dbname=relic user=postgres" -v ON_ERROR_STOP=1 -c "SET ROLE relic_owner" "$@"; }
key_hex() { awk '{print $2}' "$1.pub" | base64 -d | tail -c 32 | xxd -p -c 64; }
curl_api() { curl -sS --cacert "$work/root.crt" "$@"; }

# ---------------------------------------------------------------------------
step "Build the Rust tools"
cargo build -q --manifest-path "$repo/Cargo.toml" \
    -p relic-ingest -p relic-mmr-worker -p relic-verify || die "cargo build failed"

# ---------------------------------------------------------------------------
step "PostgreSQL on the host: 127.0.0.1 only, RELIC logins only via the socket"
"$pg_bin/initdb" -D "$data" -U postgres --auth=reject >/dev/null || die "initdb failed"
mkdir -p "$sock" && chmod 0755 "$sock"
cat >> "$data/postgresql.conf" <<EOF
listen_addresses = '127.0.0.1'
port = $pg_port
unix_socket_directories = '$sock'
password_encryption = scram-sha-256
EOF
# Exactly the RELIC lines of docs/deployment.md. The one test-only difference:
# the operator (this user) is mapped to postgres instead of being OS user postgres.
cat > "$data/pg_hba.conf" <<'EOF'
# TYPE  DATABASE  USER                                  ADDRESS  METHOD
local   all       postgres                                       peer map=relic
local   relic     relic_worker,relic_auditor                     peer map=relic
local   relic     relic_app                                      scram-sha-256
host    all       relic_app,relic_worker,relic_auditor  all      reject
EOF
cat > "$data/pg_ident.conf" <<EOF
# MAPNAME  SYSTEM-USERNAME  PG-USERNAME
relic      $me              postgres
relic      $me              relic_worker
relic      $me              relic_auditor
EOF
"$pg_bin/pg_ctl" -D "$data" -l "$work/postgres.log" -w start >/dev/null || die "postgres did not start"

RELIC_TEST_APP_PASSWORD="$app_password" \
    "$repo/database/tests/setup-disposable-db.sh" "postgresql://postgres@${sock//\//%2F}:$pg_port" \
    >/dev/null || die "schema setup failed"
check "schema v1 + access policy + migrations applied" "relic" \
    "$(owner_sql -c "SELECT current_database()" | tail -1)"

listening="$(ss -Hltn "sport = :$pg_port" | awk '{print $4}' | sort -u | tr '\n' ' ')"
check "PostgreSQL listens on loopback only" "127.0.0.1:$pg_port " "$listening"

# ---------------------------------------------------------------------------
step "Database logins over TCP and the socket"
tcp() { "$pg_bin/psql" -XqAt "host=127.0.0.1 port=$pg_port dbname=relic user=$1 password=$2" -c "SELECT 1"; }
unix() { "$pg_bin/psql" -XqAt "host=$sock port=$pg_port dbname=relic user=$1 ${2:+password=$2}" -c "SELECT 1"; }
refused "relic_worker over TCP (even with its password)" tcp relic_worker relic-test-only
refused "relic_auditor over TCP (even with its password)" tcp relic_auditor relic-test-only
refused "relic_app over TCP (even with its password)" tcp relic_app "$app_password"
refused "relic_app over the socket with a wrong password" unix relic_app wrong-password
check "relic_app over the socket with its password" 1 "$(unix relic_app "$app_password" 2>&1)"
check "relic_worker over the socket by peer (no password)" 1 "$(unix relic_worker 2>&1)"
check "relic_auditor over the socket by peer (no password)" 1 "$(unix relic_auditor 2>&1)"
refused "relic_auditor cannot write" "$pg_bin/psql" -XqAt -v ON_ERROR_STOP=1 \
    "host=$sock port=$pg_port dbname=relic user=relic_auditor" \
    -c "CREATE TEMP TABLE t (x int); INSERT INTO catalogue.flag DEFAULT VALUES"

# ---------------------------------------------------------------------------
step "API and Caddy in Docker (production compose file)"
python3 - "$repo/database/api/Caddyfile" "$work/Caddyfile" <<'PY'
import re, sys
text = open(sys.argv[1]).read()
# Test-only: a local CA instead of ACME; everything else as in production.
text, n = re.subn(r"cert_issuer acme \{\$ACME_CA\} \{\s*profile \{\$ACME_PROFILE\}\s*\}", "local_certs", text)
assert n == 1, "Caddyfile ACME block not found"
open(sys.argv[2], "w").write(text)
PY
: > "$work/compose.env"
mkdir -p "$staging" "$store"
chmod 2777 "$staging"
cat > "$work/override.yml" <<EOF
services:
  api:
    env_file: !reset []
    environment:
      RELIC_HOST: localhost
      RELIC_DATABASE_URL: "postgresql://relic_app:${app_password}@/relic?host=/var/run/postgresql&port=${pg_port}"
      RELIC_JWT_SECRET: "$(openssl rand -hex 32)"
      # Production limits (10 logins/min, 5 registrations/h per IP) would stop
      # a scripted run that logs in a dozen times from one address.
      RELIC_AUTH_RATE_LIMIT_PER_MINUTE: "120"
      RELIC_REGISTRATION_RATE_LIMIT_PER_HOUR: "100"
      # Small enough to reach in a test: 3 MiB of staging, 3 downloads/h.
      RELIC_MAX_STAGING_BYTES: "3145728"
      RELIC_DOWNLOAD_RATE_LIMIT_PER_HOUR: "3"
  caddy:
    environment:
      RELIC_READ_BODY_TIMEOUT: 5s
    ports: !override
      - "127.0.0.1:${https_port}:443"
    volumes: !override
      - $work/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
EOF
compose up -d --build --wait >"$work/compose.log" 2>&1 || { tail -20 "$work/compose.log"; die "compose up failed"; }
for _ in $(seq 1 30); do
    compose cp caddy:/data/caddy/pki/authorities/local/root.crt "$work/root.crt" >/dev/null 2>&1 \
        && curl -s -o /dev/null --cacert "$work/root.crt" "https://localhost:${https_port}/healthz" && break
    sleep 1
done
check "API healthy through Caddy (TLS verified)" 200 \
    "$(curl_api -o /dev/null -w '%{http_code}' "https://localhost:${https_port}/healthz")"
headers="$(curl_api -sI "https://localhost:${https_port}/healthz")"
check "HSTS header set" 1 "$(grep -ci '^strict-transport-security' <<<"$headers")"
check "no Server header" 0 "$(grep -ci '^server:' <<<"$headers")"
published="$(compose port api 8000 2>/dev/null)"
check "API port 8000 not published on the host" unpublished \
    "$([[ -z "$published" || "$published" == ":0" ]] && echo unpublished || echo "$published")"

container_probe() { # python snippet run inside the API container; prints a result word
    compose exec -T api python -c "$1" 2>/dev/null | tail -1
}
egress() { # service -> open|blocked (TCP to a public address)
    compose exec -T "$1" sh -c 'nc -z -w 3 1.1.1.1 443 2>/dev/null || python -c "
import socket; socket.create_connection((\"1.1.1.1\", 443), timeout=3)" 2>/dev/null' \
        >/dev/null 2>&1 && echo open || echo blocked
}
check "control: Caddy reaches the internet" open "$(egress caddy)"
check "API container: no route to the internet" blocked "$(egress api)"
gateway="$(docker network inspect "${project}_internal" -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')"
check "API container: no TCP to the host's PostgreSQL" blocked "$(container_probe "
import socket
try: socket.create_connection(('${gateway:-172.17.0.1}', ${pg_port}), timeout=3); print('open')
except OSError: print('blocked')")"
check "API container: socket directory is read-only" read-only "$(container_probe "
try: open('/var/run/postgresql/x', 'w'); print('writable')
except OSError: print('read-only')")"
check "API container: object store is read-only" read-only "$(container_probe "
try: open('/srv/relic-objects/x', 'w'); print('writable')
except OSError: print('read-only')")"

# ---------------------------------------------------------------------------
step "Accounts through Caddy: operator bootstrap, registration, two-Moderator flow"
sign="$target/relic-sign-challenge"
for k in mod1 mod2 analyst viewer integrity mmr; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$work/$k"; done
for k in mod1 mod2; do
    owner_sql -c "WITH a AS (INSERT INTO catalogue.user_public (public_key, role)
                   VALUES (decode('$(key_hex "$work/$k")', 'hex'), 'moderator') RETURNING user_id)
                  INSERT INTO catalogue.user_private (user_id, name, email)
                  SELECT user_id, '$k', '$k@example.org' FROM a" >/dev/null
done
for k in integrity mmr; do
    owner_sql -c "INSERT INTO catalogue.user_public (public_key, owner_type)
                  VALUES (decode('$(key_hex "$work/$k")', 'hex'), 'system')" >/dev/null
done
system_id() { owner_sql -c "SELECT user_id FROM catalogue.user_public WHERE public_key = decode('$(key_hex "$work/$1")', 'hex')" | tail -1; }

login() { # key -> bearer token
    curl_api -X POST "$api/auth/challenge" -H 'content-type: application/json' -d '{"purpose":"login"}' > "$work/ch.json"
    "$sign" login --challenge "$work/ch.json" --key "$1" > "$work/login.json"
    curl_api -X POST "$api/auth/login" -H 'content-type: application/json' -d @"$work/login.json" | field access_token
}
register() { # key role -> request id
    curl_api -X POST "$api/auth/challenge" -H 'content-type: application/json' -d '{"purpose":"registration"}' > "$work/ch.json"
    "$sign" register --challenge "$work/ch.json" --key "$1" --role "$2" --name "Test $2" --email "$2@example.org" > "$work/reg.json"
    curl_api -X POST "$api/accounts" -H 'content-type: application/json' -d @"$work/reg.json" | field registration_request_id
}
approve() { # request moderator_key -> response body
    local token moderator
    token="$(login "$2")"
    moderator="$(curl_api "$api/me" -H "authorization: Bearer $token" | field user_id)"
    curl_api "$api/registrations/$1" -H "authorization: Bearer $token" > "$work/request.json"
    "$sign" decide-registration --request "$work/request.json" --moderator-id "$moderator" \
        --decision approved --key "$2" > "$work/decision.json" 2>/dev/null
    curl_api -X POST "$api/registrations/$1/decision" -H "authorization: Bearer $token" \
        -H 'content-type: application/json' -d @"$work/decision.json"
}
check "analyst registration approved by one Moderator" approved \
    "$(approve "$(register "$work/analyst" analyst)" "$work/mod1" | field decision)"
check "viewer registration approved" approved \
    "$(approve "$(register "$work/viewer" viewer)" "$work/mod1" | field decision)"
ssh-keygen -q -t ed25519 -N '' -C mod3 -f "$work/mod3"
mod_request="$(register "$work/mod3" moderator)"
check "new Moderator: first approval waits for a second" awaiting_second_approval \
    "$(approve "$mod_request" "$work/mod1" | field status)"
check "new Moderator: second Moderator approves" approved \
    "$(approve "$mod_request" "$work/mod2" | field decision)"

analyst_token="$(login "$work/analyst")"
analyst_id="$(curl_api "$api/me" -H "authorization: Bearer $analyst_token" | field user_id)"
check "analyst logs in through Caddy" analyst \
    "$(curl_api "$api/me" -H "authorization: Bearer $analyst_token" | field role)"

# ---------------------------------------------------------------------------
step "FIDBF admission on the host as relic_worker (socket, peer auth)"
head -c 4096 /dev/urandom > "$work/object.fidbf"
ids="$(python3 - "$work" "$analyst_id" <<'PY'
import hashlib, json, sys, uuid
work, analyst = sys.argv[1], sys.argv[2]
data = open(f"{work}/object.fidbf", "rb").read()
ids = {k: str(uuid.uuid4()) for k in ("source", "batch", "binary", "fidbf", "f1")}
manifest = {
    "analyst_user_id": analyst,
    "source": {"source_id": ids["source"], "name": "infra test", "source_type": "FIDBF",
               "reference": None, "snapshot_version": "v1",
               "retrieved_at": "2026-11-23T10:00:00Z", "is_ecological": True},
    "batch": {"batch_id": ids["batch"]},
    "binary": {"binary_id": ids["binary"], "content_sha256": hashlib.sha256(b"bin").hexdigest(),
               "content_md5": hashlib.md5(b"bin").hexdigest(), "size_bytes": 3,
               "original_filename": "a.out", "format": "ELF", "architecture": "x86_64",
               "bit_width": 64, "endianness": "little", "platform": "linux", "abi": None,
               "object_type": None, "entry_point": "4198400", "image_base": "4194304",
               "build_id": None, "is_stripped": False, "compiler": "gcc", "version": None},
    "fidbf": {"fidbf_id": ids["fidbf"], "storage_path": "objects/infra-test.fidbf",
              "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest()},
    "functions": [{"function_id": ids["f1"], "name": "main", "full_hash": "0123456789abcdef",
                   "specific_hash": "fedcba9876543210", "file_offset": 64,
                   "virtual_address": "4198400", "size_bytes": 32, "section_name": ".text",
                   "symbol_name": "main", "mangled_name": None, "demangled_name": None}],
}
json.dump(manifest, open(f"{work}/manifest.json", "w"))
print(" ".join(ids[k] for k in ("source", "binary", "fidbf", "f1")))
PY
)"
read -r source_id binary_id fidbf_id function_id <<<"$ids"
"$target/relic-sign-fidbf" --manifest "$work/manifest.json" --fidbf-object "$work/object.fidbf" \
    --analyst-key "$work/analyst" --output "$work/signed.json" 2>/dev/null
worker_url="host=$sock port=$pg_port dbname=relic user=relic_worker"
"$target/relic-ingest-fidbf" --database-url "$worker_url" --manifest "$work/signed.json" \
    --fidbf-object "$work/object.fidbf" --integrity-system-user-id "$(system_id integrity)" \
    --integrity-key "$work/integrity" > "$work/ingest.json" 2>"$work/ingest.err"
check "relic-ingest-fidbf admits as relic_worker" 0 "$?"
check "FIDBF readable through Caddy with the analyst's signature" \
    "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["analyst_signatures"]["fidbf"])' "$work/signed.json")" \
    "$(curl_api "$api/fidbf/$fidbf_id" -H "authorization: Bearer $analyst_token" | field signature)"
# A second, validly signed admission with fresh IDs: only the login differs.
python3 - "$work/manifest.json" "$work/manifest-app.json" <<'PY2'
import json, sys, uuid
m = json.load(open(sys.argv[1]))
for part, key in (("source", "source_id"), ("batch", "batch_id"), ("binary", "binary_id"), ("fidbf", "fidbf_id")):
    m[part][key] = str(uuid.uuid4())
for function in m["functions"]:
    function["function_id"] = str(uuid.uuid4())
json.dump(m, open(sys.argv[2], "w"))
PY2
"$target/relic-sign-fidbf" --manifest "$work/manifest-app.json" --fidbf-object "$work/object.fidbf" \
    --analyst-key "$work/analyst" --output "$work/signed-app.json" 2>/dev/null
"$target/relic-ingest-fidbf" \
    --database-url "host=$sock port=$pg_port dbname=relic user=relic_app password=$app_password" \
    --manifest "$work/signed-app.json" --fidbf-object "$work/object.fidbf" \
    --integrity-system-user-id "$(system_id integrity)" --integrity-key "$work/integrity" \
    > /dev/null 2> "$work/ingest-app.err"
check "relic-ingest-fidbf as relic_app is refused by the database" 1 \
    "$(grep -c 'permission denied' "$work/ingest-app.err")"

# ---------------------------------------------------------------------------
step "Signed Analyst claims through Caddy"
post() { # path body-file token -> http code
    curl_api -o "$work/out.json" -w '%{http_code}' -X POST "$api/$1" \
        -H "authorization: Bearer $3" -H 'content-type: application/json' -d @"$2"
}
"$sign" assert-license --analyst-id "$analyst_id" --target-type source --target-id "$source_id" \
    --spdx "GPL-2.0-only WITH Classpath-exception-2.0" --basis declared --confidence 1.0000 \
    --key "$work/analyst" > "$work/license.json" 2>/dev/null
check "licence assertion accepted" 201 "$(post license-assertions "$work/license.json" "$analyst_token")"
check "identical retry returns the stored assertion" 200 "$(post license-assertions "$work/license.json" "$analyst_token")"
printf '{"tool": "capa", "rules": ["aes"]}\n' > "$work/evidence.json"
"$sign" classify --analyst-id "$analyst_id" --target-type function --target-id "$function_id" \
    --label crypto/aes --confidence 0.9000 --evidence "$work/evidence.json" \
    --key "$work/analyst" > "$work/classification.json" 2>/dev/null
check "classification accepted with verbatim evidence" 201 "$(post classifications "$work/classification.json" "$analyst_token")"
viewer_token="$(login "$work/viewer")"
check "a Viewer cannot assert a licence" 403 "$(post license-assertions "$work/license.json" "$viewer_token")"

# ---------------------------------------------------------------------------
step "FIDBF, BSim and provenance through Caddy, admitted on the host by relic-admit"
head -c 2097152 /dev/urandom > "$work/object2.fidbf"   # 2 MiB: above the 1 MB general limit
python3 - "$work/manifest.json" "$work/manifest-api.json" "$work/object2.fidbf" <<'PY3'
import hashlib, json, sys, uuid
m = json.load(open(sys.argv[1]))
data = open(sys.argv[3], "rb").read()
for part, key in (("source", "source_id"), ("batch", "batch_id"), ("binary", "binary_id"), ("fidbf", "fidbf_id")):
    m[part][key] = str(uuid.uuid4())
for function in m["functions"]:
    function["function_id"] = str(uuid.uuid4())
m["fidbf"].update(sha256=hashlib.sha256(data).hexdigest(), md5=hashlib.md5(data).hexdigest())
json.dump(m, open(sys.argv[2], "w"))
PY3
"$target/relic-sign-fidbf" --manifest "$work/manifest-api.json" --fidbf-object "$work/object2.fidbf" \
    --analyst-key "$work/analyst" --output "$work/signed-api.json" --canonical-storage-path 2>/dev/null
object_sha="$(sha256sum "$work/object2.fidbf" | cut -d' ' -f1)"
api_fidbf="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["fidbf"]["fidbf_id"])' "$work/signed-api.json")"
api_source="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source"]["source_id"])' "$work/signed-api.json")"
api_function="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["functions"][0]["function_id"])' "$work/signed-api.json")"
api_binary="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["binary"]["binary_id"])' "$work/signed-api.json")"
check "FIDBF object (2 MiB) uploaded through Caddy" 201 \
    "$(curl_api -o /dev/null -w '%{http_code}' -X PUT "$api/fidbf-objects/$object_sha" \
        -H "authorization: Bearer $analyst_token" --data-binary @"$work/object2.fidbf")"
check "a 2 MiB body is refused on an ordinary route" 413 \
    "$(curl_api -o /dev/null -w '%{http_code}' -X POST "$api/license-assertions" \
        -H "authorization: Bearer $analyst_token" -H 'content-type: application/json' \
        --data-binary @"$work/object2.fidbf")"
head -c 2097152 /dev/urandom > "$work/object3.fidbf"
check "staging full: a second 2 MiB upload is refused (507)" 507 \
    "$(curl_api -o /dev/null -w '%{http_code}' -X PUT \
        "$api/fidbf-objects/$(sha256sum "$work/object3.fidbf" | cut -d' ' -f1)" \
        -H "authorization: Bearer $analyst_token" --data-binary @"$work/object3.fidbf")"
slow_upload() { # prints how many seconds Caddy took to drop a stalled upload
    python3 - "$work/root.crt" "$https_port" "$analyst_token" <<'PY'
import socket, ssl, sys, time
context = ssl.create_default_context(cafile=sys.argv[1])
raw = socket.create_connection(("127.0.0.1", int(sys.argv[2])), timeout=30)
conn = context.wrap_socket(raw, server_hostname="localhost")
conn.sendall((f"PUT /v1/fidbf-objects/{'a' * 64} HTTP/1.1\r\nHost: localhost\r\n"
              f"Authorization: Bearer {sys.argv[3]}\r\nContent-Length: 1000000\r\n\r\n").encode()
             + b"x" * 100)
start = time.monotonic()
try:
    while conn.recv(4096):
        pass
except OSError:
    pass
print(round(time.monotonic() - start))
PY
}
waited="$(slow_upload)"
check "a stalled upload is dropped by Caddy's body timeout" yes \
    "$( [[ "$waited" -ge 3 && "$waited" -le 15 ]] && echo yes || echo "no (${waited}s)")"
check "FIDBF manifest staged (202)" 202 "$(post fidbf "$work/signed-api.json" "$analyst_token")"
printf '{"features": [0.25, 0.5], "tool": "bsim"}' > "$work/bsim.json"
printf '[{"function_id": "%s", "binary_id": "%s"}]' "$api_function" "$api_binary" > "$work/links.json"
printf '{"class_uid": 5020, "unmapped": {"relic": {"recipe": "make"}}}' > "$work/seal.json"
admit() {
    "$target/relic-admit" --database-url "$worker_url" --once \
        --integrity-system-user-id "$(system_id integrity)" --integrity-key "$work/integrity" \
        --staging-dir "$staging" --fidbf-root "$store" >> "$work/admit.log" 2>&1
}
admit
check "relic-admit admits the FIDBF as relic_worker" 0 "$?"
submission() { curl_api "$api/submissions/$1" -H "authorization: Bearer $analyst_token" | field status; }
check "FIDBF submission admitted" admitted "$(submission "$api_fidbf")"
check "FIDBF downloads through Caddy, byte for byte" "$object_sha" \
    "$(curl_api "$api/fidbf/$api_fidbf/download" -H "authorization: Bearer $analyst_token" | sha256sum | cut -d' ' -f1)"
check "staged upload removed after admission" 0 "$(find "$staging" -type f | wc -l)"
download() { curl_api -o /dev/null -w '%{http_code}' "$api/fidbf/$api_fidbf/download" -H "authorization: Bearer $1"; }
check "downloads are limited per account (3/h here)" "200 200 429" \
    "$(download "$analyst_token") $(download "$analyst_token") $(download "$analyst_token")"
check "the limit is the account's, not the address's" 200 "$(download "$viewer_token")"
"$sign" sign-bsim --analyst-id "$analyst_id" --source-id "$api_source" --object "$work/bsim.json" \
    --functions "$work/links.json" --key "$work/analyst" > "$work/bsim-body.json" 2>/dev/null
check "BSim object staged (202)" 202 "$(post bsim "$work/bsim-body.json" "$analyst_token")"
bsim_id="$(field bsim_id < "$work/bsim-body.json")"
"$sign" sign-provenance --analyst-id "$analyst_id" --source-id "$api_source" --bsim-id "$bsim_id" \
    --schema-name ocsf --object "$work/seal.json" --key "$work/analyst" > "$work/seal-body.json" 2>/dev/null
check "provenance seal staged (202)" 202 "$(post provenance "$work/seal-body.json" "$analyst_token")"
admit
check "BSim object admitted" admitted "$(submission "$bsim_id")"
check "provenance seal admitted" admitted "$(submission "$(field provenance_id < "$work/seal-body.json")")"

# ---------------------------------------------------------------------------
step "MMR checkpoint on the host as relic_worker"
"$target/relic-checkpoint-mmr" --database-url "$worker_url" --system-user-id "$(system_id mmr)" \
    --key "$work/mmr" > "$work/mmr.json" 2>"$work/mmr.err"
check "relic-checkpoint-mmr signs a checkpoint" True "$(field inserted < "$work/mmr.json" 2>/dev/null)"
check "latest checkpoint covers the whole chain, read through Caddy" \
    "$(owner_sql -c "SELECT count(*) FROM catalogue.integrity" | tail -1)" \
    "$(curl_api "$api/mmr-checkpoints/latest" -H "authorization: Bearer $analyst_token" | field leaf_count)"

# ---------------------------------------------------------------------------
step "relic-verify on the host as relic_auditor"
auditor_url="postgresql://relic_auditor@${sock//\//%2F}:${pg_port}/relic"
"$target/relic-verify" --database-url "$auditor_url" > "$work/verify.txt" 2>&1
check "relic-verify: everything verifies (exit 0)" 0 "$?"
check "relic-verify: verdict" "VERIFIED: 0 failure(s), 0 warning(s)" "$(tail -1 "$work/verify.txt")"
owner_sql -c "INSERT INTO catalogue.flag (viewer_request_id, note, signature, target_type, target_id)
              SELECT user_id, 'forged', decode(repeat('07', 64), 'hex'), 'binary', '$binary_id'
                FROM catalogue.user_public WHERE role = 'viewer'" >/dev/null
"$target/relic-verify" --database-url "$auditor_url" --quiet > "$work/verify.txt" 2>&1
check "relic-verify: a forged row is reported (exit 1)" 1 "$?"
check "relic-verify: names the forged flag" 1 "$(grep -c '^FAIL flag' "$work/verify.txt")"

printf '\npassed=%d failed=%d\n' "$pass" "$fail"
(( fail == 0 ))
