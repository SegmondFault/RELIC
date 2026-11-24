#!/usr/bin/env bash
# Local development stack for the RELIC API: a throwaway PostgreSQL container
# with the full schema and migrations, and the API running from source.
#
#   scripts/local-dev.sh up                         start Postgres, (re)build the database
#   scripts/local-dev.sh bootstrap-moderator <key.pub> <name> <email>
#                                                   create the first Moderator (operator step)
#   scripts/local-dev.sh pending                    list pending registration requests
#   scripts/local-dev.sh approve|reject <request_id> <moderator_key>
#                                                   log in as the Moderator (by key), sign and
#                                                   submit the decision through the running API
#   scripts/local-dev.sh revoke <target_type> <target_id> <requester_key> <reason>
#       (an Analyst's key for a catalogue entry, a Moderator's for an account)
#                                                   log in as the Analyst, sign and submit a
#                                                   revocation request
#   scripts/local-dev.sh approve-revocation|reject-revocation <revocation_id> <moderator_key>
#                                                   sign and submit a revocation decision
#   scripts/local-dev.sh flag <target_type> <target_id> <viewer_key> <note>
#                                                   log in as the Viewer, sign and submit a flag
#   scripts/local-dev.sh respond-flag <flag_id> <analyst_key> <note>
#                                                   sign and submit an Analyst's response
#   scripts/local-dev.sh verify                     re-verify every signature and the chain
#                                                   (relic-verify as relic_auditor)
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
    RELIC_TEST_APP_PASSWORD="$app_password" RELIC_TEST_WORKER_PASSWORD="$app_password" \
        RELIC_TEST_AUDITOR_PASSWORD="$app_password" \
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

signer="$repo_dir/target/debug/relic-sign-challenge"
api="http://127.0.0.1:${api_port}/v1"

json_field() {
    python3 -c 'import json, sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

# Log in by key through the running API; sets $token and $user_id.
login_as() {
    local key="$1" work="$2"
    [[ -x "$signer" ]] || cargo build -q -p relic-ingest --bin relic-sign-challenge
    curl -sS --fail-with-body -X POST "$api/auth/challenge" -H 'content-type: application/json' \
        -d '{"purpose":"login"}' > "$work/challenge.json"
    "$signer" login --challenge "$work/challenge.json" --key "$key" > "$work/login.json"
    token="$(curl -sS --fail-with-body -X POST "$api/auth/login" \
        -H 'content-type: application/json' -d @"$work/login.json" | json_field access_token)"
    user_id="$(curl -sS --fail-with-body "$api/me" -H "authorization: Bearer $token" \
        | json_field user_id)"
}

# Read route for a revocation target type; empty if it has none yet.
target_route() {
    case "$1" in
        user) echo users ;; source) echo sources ;; batch) echo batches ;;
        binary) echo binaries ;; function) echo functions ;; fidbf) echo fidbf ;;
        bsim) echo bsim ;; provenance) echo provenance ;;
        license_assertion) echo license-assertions ;; classification) echo classifications ;;
        flag) echo flags ;; flag_response) echo flag-responses ;;
        *) echo "" ;;
    esac
}

# cmd_decide <registration|revocation> <approved|rejected> <id> <moderator_key>
cmd_decide() {
    local kind="$1" decision="$2"; shift 2
    local verb="${decision%d}"
    [[ "$kind" == revocation ]] && verb="$verb-revocation"
    (( $# == 2 )) || { echo "usage: $0 $verb <${kind}_id> <moderator_key>" >&2; exit 2; }
    local id="$1" key="$2" token user_id
    require_uuid "$id"
    local work; work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" RETURN

    login_as "$key" "$work"
    curl -sS --fail-with-body "$api/${kind}s/$id" \
        -H "authorization: Bearer $token" > "$work/request.json"
    local review=()
    if [[ "$kind" == revocation ]]; then
        # The signer verifies the request with the requester's registered key
        # and shows the target before signing.
        local analyst_id target_type target_id route
        analyst_id="$(json_field analyst_id < "$work/request.json")"
        target_type="$(json_field target_type < "$work/request.json")"
        target_id="$(json_field target_id < "$work/request.json")"
        curl -sS --fail-with-body "$api/users/$analyst_id" \
            -H "authorization: Bearer $token" > "$work/requester.json"
        review+=(--requester "$work/requester.json")
        route="$(target_route "$target_type")"
        if [[ -n "$route" ]]; then
            curl -sS --fail-with-body "$api/$route/$target_id" \
                -H "authorization: Bearer $token" > "$work/target.json"
            review+=(--target "$work/target.json")
        fi
    fi
    "$signer" "decide-$kind" --request "$work/request.json" "${review[@]}" \
        --moderator-id "$user_id" --decision "$decision" --key "$key" > "$work/decision.json"
    curl -sS --fail-with-body -X POST "$api/${kind}s/$id/decision" \
        -H "authorization: Bearer $token" -H 'content-type: application/json' \
        -d @"$work/decision.json"
    echo
}

cmd_revoke() {
    (( $# == 4 )) || {
        echo "usage: $0 revoke <target_type> <target_id> <requester_key> <reason>" >&2; exit 2;
    }
    local target_type="$1" target_id="$2" key="$3" reason="$4" token user_id
    require_uuid "$target_id"
    local work; work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" RETURN

    login_as "$key" "$work"
    "$signer" request-revocation --requester-id "$user_id" --target-type "$target_type" \
        --target-id "$target_id" --reason "$reason" --key "$key" > "$work/revocation.json"
    curl -sS --fail-with-body -X POST "$api/revocations" \
        -H "authorization: Bearer $token" -H 'content-type: application/json' \
        -d @"$work/revocation.json"
    echo
}

cmd_flag() {
    (( $# == 4 )) || {
        echo "usage: $0 flag <target_type> <target_id> <viewer_key> <note>" >&2; exit 2;
    }
    local target_type="$1" target_id="$2" key="$3" note="$4" token user_id
    require_uuid "$target_id"
    local work; work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" RETURN

    login_as "$key" "$work"
    "$signer" flag --viewer-id "$user_id" --target-type "$target_type" \
        --target-id "$target_id" --note "$note" --key "$key" > "$work/flag.json"
    curl -sS --fail-with-body -X POST "$api/flags" \
        -H "authorization: Bearer $token" -H 'content-type: application/json' \
        -d @"$work/flag.json"
    echo
}

cmd_respond_flag() {
    (( $# == 3 )) || { echo "usage: $0 respond-flag <flag_id> <analyst_key> <note>" >&2; exit 2; }
    local flag_id="$1" key="$2" note="$3" token user_id
    require_uuid "$flag_id"
    local work; work="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '$work'" RETURN

    login_as "$key" "$work"
    curl -sS --fail-with-body "$api/flags/$flag_id" \
        -H "authorization: Bearer $token" > "$work/flag.json"
    "$signer" respond-flag --flag "$work/flag.json" --analyst-id "$user_id" \
        --note "$note" --key "$key" > "$work/response.json"
    curl -sS --fail-with-body -X POST "$api/flags/$flag_id/responses" \
        -H "authorization: Bearer $token" -H 'content-type: application/json' \
        -d @"$work/response.json"
    echo
}

cmd_verify() {
    local verifier="$repo_dir/target/debug/relic-verify"
    [[ -x "$verifier" ]] || cargo build -q -p relic-verify
    "$verifier" --database-url \
        "postgresql://relic_auditor:${app_password}@127.0.0.1:${pg_port}/relic" "$@"
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
    approve) shift; cmd_decide registration approved "$@" ;;
    reject) shift; cmd_decide registration rejected "$@" ;;
    revoke) shift; cmd_revoke "$@" ;;
    approve-revocation) shift; cmd_decide revocation approved "$@" ;;
    reject-revocation) shift; cmd_decide revocation rejected "$@" ;;
    flag) shift; cmd_flag "$@" ;;
    respond-flag) shift; cmd_respond_flag "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    api) cmd_api ;;
    psql) shift; psql --no-psqlrc "$super_uri/relic" "$@" ;;
    down) cmd_down ;;
    *) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
