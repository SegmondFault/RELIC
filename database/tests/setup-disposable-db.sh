#!/usr/bin/env bash
# Build a disposable RELIC database for tests: roles, schema v1, access
# policy, then every migration that applies on top of the consolidated schema.
#
# Usage: setup-disposable-db.sh <superuser connection URI without database>
#   e.g. setup-disposable-db.sh postgresql://postgres:postgres@127.0.0.1:55432
#
# Never point this at a real server: it drops and recreates the `relic`
# database and resets the relic_app and relic_worker passwords to
# RELIC_TEST_APP_PASSWORD and RELIC_TEST_WORKER_PASSWORD.

set -euo pipefail

if (( $# != 1 )); then
    echo "usage: $0 <superuser-uri>" >&2
    exit 2
fi

superuser_uri="$1"
app_password="${RELIC_TEST_APP_PASSWORD:-relic-test-only}"
worker_password="${RELIC_TEST_WORKER_PASSWORD:-relic-test-only}"
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

psql_super() {
    psql --no-psqlrc -X -v ON_ERROR_STOP=1 -q "$@"
}

psql_super "$superuser_uri/postgres" <<SQL
DROP DATABASE IF EXISTS relic WITH (FORCE);
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'relic_owner') THEN
        CREATE ROLE relic_owner NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'relic_app') THEN
        CREATE ROLE relic_app LOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'relic_worker') THEN
        CREATE ROLE relic_worker LOGIN;
    END IF;
END
\$\$;
ALTER ROLE relic_app PASSWORD '$app_password';
ALTER ROLE relic_worker LOGIN PASSWORD '$worker_password';
CREATE DATABASE relic OWNER relic_owner;
SQL

PGOPTIONS="-c role=relic_owner" psql_super "$superuser_uri/relic" \
    -f "$repo_dir/database/relic-schema-v1.sql"
psql_super "$superuser_uri/relic" -f "$repo_dir/database/relic-access-v1.sql"

# Migrations 002-007 are already folded into relic-schema-v1.sql.
for migration in "$repo_dir"/database/migrations/0{08..99}-*.sql; do
    [[ -f "$migration" ]] || continue
    psql_super "$superuser_uri/relic" -f "$migration"
done

echo "Disposable RELIC database ready."
