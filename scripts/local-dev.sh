#!/usr/bin/env bash
# Local development stack for the RELIC API: a throwaway PostgreSQL container
# with the full schema and migrations, and the API running from source.
#
#   scripts/local-dev.sh up                         start Postgres, (re)build the database
#   scripts/local-dev.sh bootstrap-moderator <key.pub> <name> <email>
#                                                   create the first Moderator (operator step)
#   scripts/local-dev.sh pending                    list pending registration requests
#   scripts/local-dev.sh approve|reject <request_id> <moderator_id> <moderator_key>
#                                                   log in as the Moderator, sign and submit the
#                                                   decision through the running API
#   scripts/local-dev.sh api                        run the API on http://127.0.0.1:8000 (foreground)
#   scripts/local-dev.sh psql                       open psql on the dev database as superuser
#   scripts/local-dev.sh down                       remove the Postgres container and its data
#
# Development only. Nothing here is safe for a real server: fixed passwords,
# plaintext loopback connections and /docs enabled.

set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
container="${RELIC_DEV_CONTAINER:-relic-dev-pg}"
pg_port="${RELIC_DEV_PG_PORT:-55433}"
api_port="${RELIC_DEV_API_PORT:-8000}"
app_password="relic-dev-only"
super_uri="postgresql://postgres:postgres@127.0.0.1:${pg_port}"
venv="${repo_dir}/.venv"

psql_super() {
    psql --no-psqlrc -X -v ON_ERROR_STOP=1 -q "$super_uri/relic" "$@"
}

psql_owner() {
    PGOPTIONS="-c role=relic_owner" psql_super "$@"
}

require_uuid() {
    [[ "$1" =~ ^[0-9a-fA-F-]{36}$ ]] || { echo "not a UUID: $1" >&2; exit 2; }
}

cmd_up() {
    if ! docker inspect "$container" >/dev/null 2>&1; then
        docker run -d --name "$container" \
            -e POSTGRES_PASSWORD=postgres \
            -p "127.0.0.1:${pg_port}:5432" \
            postgres:17-alpine >/dev/null
    else
        docker start "$container" >/dev/null
    fi
    for _ in $(seq 1 60); do
        if pg_isready -q -h 127.0.0.1 -p "$pg_port" -U postgres 2>/dev/null \
           && psql --no-psqlrc -X -q "$super_uri/postgres" -c 'SELECT 1' >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done
    RELIC_TEST_APP_PASSWORD="$app_password" \
        "$repo_dir/database/tests/setup-disposable-db.sh" "$super_uri"
    echo "PostgreSQL: $super_uri/relic (container $container)"
}

cmd_bootstrap_moderator() {
    (( $# == 3 )) || { echo "usage: $0 bootstrap-moderator <key.pub> <name> <email>" >&2; exit 2; }
    local pub="$1" name="$2" email="$3" key_hex
    [[ "$(awk '{print $1}' "$pub")" == "ssh-ed25519" ]] \
        || { echo "$pub is not an ssh-ed25519 public key" >&2; exit 2; }
    # OpenSSH wire format ends with u32 length (32) || 32 key bytes.
    key_hex="$(awk '{print $2}' "$pub" | base64 -d | tail -c 32 | xxd -p -c 64)"
    psql_owner -tA -v key="$key_hex" -v name="$name" -v email="$email" <<'SQL'
WITH account AS (
    INSERT INTO catalogue.user_public (public_key, role, owner_type)
    VALUES (decode(:'key', 'hex'), 'moderator', 'human')
    RETURNING user_id
)
INSERT INTO catalogue.user_private (user_id, name, email)
SELECT user_id, :'name', :'email' FROM account
RETURNING user_id;
SQL
}

cmd_pending() {
    psql_super <<'SQL'
SELECT registration_request_id, requested_role, name, organisation, email,
       encode(public_key, 'hex') AS public_key, requested_at
  FROM catalogue.registration_request
 WHERE decision IS NULL
 ORDER BY requested_at;
SQL
}

cmd_decide() {
    local decision="$1"; shift
    (( $# == 3 )) || {
        echo "usage: $0 ${decision%d} <request_id> <moderator_id> <moderator_key>" >&2; exit 2;
    }
    local request_id="$1" moderator_id="$2" key="$3"
    require_uuid "$request_id"; require_uuid "$moderator_id"
    local api="http://127.0.0.1:${api_port}/v1"
    local signer="$repo_dir/target/debug/relic-sign-challenge"
    [[ -x "$signer" ]] || cargo build -q -p relic-ingest --bin relic-sign-challenge
    local work; work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" RETURN

    curl -sS --fail-with-body -X POST "$api/auth/challenge" -H 'content-type: application/json' \
        -d "{\"purpose\":\"login\",\"user_id\":\"$moderator_id\"}" > "$work/challenge.json"
    "$signer" login --challenge "$work/challenge.json" --key "$key" \
        --user-id "$moderator_id" > "$work/login.json"
    local token
    token="$(curl -sS --fail-with-body -X POST "$api/auth/login" \
        -H 'content-type: application/json' -d @"$work/login.json" \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["access_token"])')"
    curl -sS --fail-with-body "$api/registrations/$request_id" \
        -H "authorization: Bearer $token" > "$work/request.json"
    "$signer" decide-registration --request "$work/request.json" --moderator-id "$moderator_id" \
        --decision "$decision" --key "$key" > "$work/decision.json"
    curl -sS --fail-with-body -X POST "$api/registrations/$request_id/decision" \
        -H "authorization: Bearer $token" -H 'content-type: application/json' \
        -d @"$work/decision.json"
    echo
}

cmd_api() {
    if [[ ! -x "$venv/bin/uvicorn" ]]; then
        python3 -m venv "$venv"
        "$venv/bin/pip" install -q -r "$repo_dir/database/api/requirements-dev.txt"
    fi
    export RELIC_HOST="localhost:${api_port}"
    export RELIC_DATABASE_URL="postgresql://relic_app:${app_password}@127.0.0.1:${pg_port}/relic"
    export RELIC_JWT_SECRET="${RELIC_JWT_SECRET:-$(openssl rand -hex 32)}"
    export RELIC_INSECURE_DEV_MODE=true
    export RELIC_REGISTRATION_RATE_LIMIT_PER_HOUR="${RELIC_REGISTRATION_RATE_LIMIT_PER_HOUR:-100}"
    export RELIC_AUTH_RATE_LIMIT_PER_MINUTE="${RELIC_AUTH_RATE_LIMIT_PER_MINUTE:-60}"
    echo "API: http://127.0.0.1:${api_port}  docs: http://127.0.0.1:${api_port}/docs  audience: https://${RELIC_HOST}"
    # Run from database/ so the package imports as `api` and the deployment
    # .env in database/api is not picked up.
    cd "$repo_dir/database"
    exec "$venv/bin/uvicorn" --factory api.main:create_app \
        --host 127.0.0.1 --port "$api_port" --no-server-header
}

cmd_down() {
    docker rm -f "$container" >/dev/null 2>&1 || true
    echo "Removed $container."
}

case "${1:-}" in
    up) cmd_up ;;
    bootstrap-moderator) shift; cmd_bootstrap_moderator "$@" ;;
    pending) cmd_pending ;;
    approve) shift; cmd_decide approved "$@" ;;
    reject) shift; cmd_decide rejected "$@" ;;
    api) cmd_api ;;
    psql) shift; psql --no-psqlrc "$super_uri/relic" "$@" ;;
    down) cmd_down ;;
    *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
