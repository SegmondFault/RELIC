#!/usr/bin/env bash
#
# Restore a RELIC backup run.
#
# The default action restores the database into relic_restore and verifies it.
# Use --scratch for a throwaway verification database. Object, key and
# configuration restoration must be requested explicitly.
#
# The age identity is needed to decrypt. It must never be stored on the VPS or
# on the backup host.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

RUN_DIR=
AGE_IDENTITY=${RELIC_AGE_IDENTITY:-}
PLAINTEXT=0
DB_NAME=relic_restore
PG_RUNAS=${RELIC_PG_RUNAS-postgres}
PG_HOST=${RELIC_PG_HOST:-}
PG_PORT=${RELIC_PG_PORT:-}
PG_USER=${RELIC_PG_USER:-}
DB_OWNER=${RELIC_DB_OWNER:-}
RESTORE_GLOBALS=0
RESTORE_OBJECTS=0
RESTORE_KEYS=0
RESTORE_CONFIG=0
FIDBF_ROOT=${RELIC_FIDBF_ROOT:-/srv/relic-objects}
PROVENANCE_ROOT=${RELIC_PROVENANCE_ROOT:-/srv/relic-data}
KEYS_DIR=${RELIC_KEYS_DIR:-/var/lib/relic/keys}
CONFIG_ROOT=/
FORCE=0
SCRATCH=0
KEEP_TEMP=0
SKIP_VERIFY=0
PRESERVE_OWNER=0
DB_NAME_SET=0

usage() {
    cat <<'EOF'
Usage: restore-relic.sh --run-dir DIR [options]

Required:
  --run-dir DIR            Directory containing one run's files.
  --age-identity FILE      age private identity (unless --plaintext).

Database:
  --db-name NAME           Target database (default: relic_restore).
  --db-owner ROLE          Owner for a newly created target database.
  --scratch                Use a unique scratch database, verify it, then drop it.
  --pg-runas USER          OS user for psql/pg_restore (default: postgres;
                           use an empty value for direct connections).
  --pg-host HOST           PostgreSQL host.
  --pg-port PORT           PostgreSQL port.
  --pg-user USER           PostgreSQL user.
  --restore-globals        Restore the globals SQL file first.
  --preserve-owner         Keep dump ownership (requires restored roles).
  --force                  Drop/replace an existing target database and allow
                           non-empty object, key or config destinations.

Assets:
  --restore-objects        Restore FIDBF and provenance object archives.
  --fidbf-root DIR         Default /srv/relic-objects.
  --provenance-root DIR    Default /srv/relic-data.
  --restore-keys           Restore the system key archive.
  --keys-dir DIR           Default /var/lib/relic/keys.
  --restore-config         Restore PostgreSQL/RELIC configuration under /.
  --config-root DIR        Destination root for config (default /).

Other:
  --plaintext              The run directory is already decrypted.
  --skip-verify            Do not run the SQL verification.
  --keep-temp              Keep the decrypted temporary directory.
  --help                   Show this help.

Examples:
  # Verify a backup without touching live data.
  restore-relic.sh --run-dir /srv/backups/relic/archive/20261117T023000Z \
      --age-identity /offline/relic-backup-age.key --scratch

  # Full disaster restore on a replacement host.
  restore-relic.sh --run-dir ./20261117T023000Z \
      --age-identity /offline/relic-backup-age.key \
      --db-name relic --restore-globals --restore-objects \
      --restore-keys --restore-config --force
EOF
}

while (($#)); do
    case "$1" in
        --run-dir) RUN_DIR=${2:-}; shift 2 ;;
        --age-identity) AGE_IDENTITY=${2:-}; shift 2 ;;
        --plaintext) PLAINTEXT=1; shift ;;
        --db-name) DB_NAME=${2:-}; DB_NAME_SET=1; shift 2 ;;
        --db-owner) DB_OWNER=${2:-}; shift 2 ;;
        --scratch) SCRATCH=1; shift ;;
        --pg-runas) PG_RUNAS=${2:-}; shift 2 ;;
        --pg-host) PG_HOST=${2:-}; shift 2 ;;
        --pg-port) PG_PORT=${2:-}; shift 2 ;;
        --pg-user) PG_USER=${2:-}; shift 2 ;;
        --restore-globals) RESTORE_GLOBALS=1; shift ;;
        --preserve-owner) PRESERVE_OWNER=1; shift ;;
        --restore-objects) RESTORE_OBJECTS=1; shift ;;
        --fidbf-root) FIDBF_ROOT=${2:-}; shift 2 ;;
        --provenance-root) PROVENANCE_ROOT=${2:-}; shift 2 ;;
        --restore-keys) RESTORE_KEYS=1; shift ;;
        --keys-dir) KEYS_DIR=${2:-}; shift 2 ;;
        --restore-config) RESTORE_CONFIG=1; shift ;;
        --config-root) CONFIG_ROOT=${2:-}; shift 2 ;;
        --force) FORCE=1; shift ;;
        --skip-verify) SKIP_VERIFY=1; shift ;;
        --keep-temp) KEEP_TEMP=1; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

log() {
    printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" >&2
}

die() {
    log "ERROR: $*"
    exit 1
}

[[ -n "$RUN_DIR" ]] || die "--run-dir is required"
[[ -d "$RUN_DIR" ]] || die "run directory does not exist: $RUN_DIR"

[[ "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || die "invalid database name: $DB_NAME"
case "$DB_NAME" in
    postgres|template0|template1)
        die "refusing to use reserved PostgreSQL database name: $DB_NAME"
        ;;
esac

if (( SCRATCH )); then
    if (( RESTORE_GLOBALS || RESTORE_OBJECTS || RESTORE_KEYS || RESTORE_CONFIG )); then
        die "--scratch cannot be combined with --restore-globals, --restore-objects, --restore-keys or --restore-config"
    fi
    if [[ "$DB_NAME" == "relic" ]]; then
        die "--scratch refuses to use the live database name; choose a scratch name"
    fi
    if (( DB_NAME_SET == 0 )); then
        DB_NAME="relic_verify_$(date -u +%Y%m%dT%H%M%SZ)"
    fi
fi

if (( RESTORE_KEYS || RESTORE_OBJECTS || RESTORE_CONFIG )) && (( EUID != 0 )); then
    die "restoring keys, objects or configuration requires root"
fi

if (( RESTORE_CONFIG )) && (( FORCE == 0 )); then
    die "--restore-config requires --force because it writes under $CONFIG_ROOT"
fi

MISSING=()
need() { command -v "$1" >/dev/null 2>&1 || MISSING+=("$1"); }
need sha256sum
need tar
need zstd
need install
need psql
need pg_restore
need createdb
need dropdb
need find
need awk
need stat
need grep
need mktemp
need sort
need tr
if (( PLAINTEXT == 0 )); then
    need age
fi
if ((${#MISSING[@]})); then
    die "missing required commands: ${MISSING[*]}"
fi

AGE_BIN=$(command -v age 2>/dev/null || true)
PSQL_BIN=$(command -v psql)
PG_RESTORE_BIN=$(command -v pg_restore)
CREATEDB_BIN=$(command -v createdb)
DROPDB_BIN=$(command -v dropdb)

if (( PLAINTEXT == 0 )); then
    [[ -n "$AGE_IDENTITY" ]] || die "--age-identity is required unless --plaintext"
    [[ -r "$AGE_IDENTITY" ]] || die "age identity is not readable: $AGE_IDENTITY"
    identity_mode=$(stat -c %a "$AGE_IDENTITY")
    if (( (8#$identity_mode & 077) != 0 )); then
        log "WARNING: age identity permissions are open: $AGE_IDENTITY"
    fi
fi

MANIFEST=$(find "$RUN_DIR" -maxdepth 1 -type f -name '*-manifest.json' -print -quit)
[[ -n "$MANIFEST" ]] || die "no *-manifest.json found in $RUN_DIR"
RUN_ID=$(basename "$MANIFEST")
RUN_ID=${RUN_ID%-manifest.json}
CHECKSUMS="$RUN_DIR/$RUN_ID-SHA256SUMS"
COMPLETE="$RUN_DIR/$RUN_ID-COMPLETE"

[[ -f "$CHECKSUMS" ]] || die "checksum file is missing: $CHECKSUMS"
[[ -f "$COMPLETE" ]] || die "COMPLETE marker is missing: $COMPLETE"

log "verifying encrypted run $RUN_ID"
(
    cd "$RUN_DIR"
    sha256sum -c "$RUN_ID-SHA256SUMS"
) >/dev/null || die "backup checksum verification failed"

manifest_expected=$(awk -F= '$1 == "manifest_sha256" {print $2; exit}' "$COMPLETE")
manifest_actual=$(sha256sum "$MANIFEST" | awk '{print $1}')
[[ -n "$manifest_expected" && "$manifest_expected" == "$manifest_actual" ]] \
    || die "manifest checksum in COMPLETE marker does not match"

WORK_DIR=$RUN_DIR
CLEAN_WORK_DIR=0

cleanup() {
    if [[ -n "${GLOBALS_TMP:-}" ]]; then
        rm -f -- "$GLOBALS_TMP"
    fi
    if (( CLEAN_WORK_DIR )) && (( KEEP_TEMP == 0 )); then
        rm -rf -- "$WORK_DIR"
    fi
}
trap cleanup EXIT

if (( PLAINTEXT == 0 )); then
    WORK_DIR=$(mktemp -d /tmp/relic-restore.XXXXXX)
    CLEAN_WORK_DIR=1
    log "decrypting run into a temporary directory"
    shopt -s nullglob
    encrypted_files=("$RUN_DIR"/*.age)
    shopt -u nullglob
    ((${#encrypted_files[@]})) || die "no .age files found in $RUN_DIR"
    for encrypted in "${encrypted_files[@]}"; do
        output="$WORK_DIR/$(basename "${encrypted%.age}")"
        "$AGE_BIN" -d -i "$AGE_IDENTITY" -o "$output" "$encrypted"
    done
fi

DB_DUMP="$WORK_DIR/$RUN_ID-db.dump"
GLOBALS="$WORK_DIR/$RUN_ID-globals.sql"
GLOBALS_RESTORE="$GLOBALS"
GLOBALS_TMP=
FIDBF_ARCHIVE="$WORK_DIR/$RUN_ID-fidbf-objects.tar.zst"
PROVENANCE_ARCHIVE="$WORK_DIR/$RUN_ID-provenance-objects.tar.zst"
KEYS_ARCHIVE="$WORK_DIR/$RUN_ID-keys.tar.zst"
CONFIG_ARCHIVE="$WORK_DIR/$RUN_ID-config.tar.zst"

[[ -f "$DB_DUMP" ]] || die "database dump is missing: $DB_DUMP"
if (( RESTORE_GLOBALS )); then
    [[ -f "$GLOBALS" ]] || die "globals dump is missing: $GLOBALS"
    # Every PostgreSQL cluster already has the built-in postgres role. Keep the
    # role definitions for RELIC's application roles, but do not try to create
    # or rewrite the cluster's own postgres role.
    GLOBALS_RESTORE=$(mktemp /tmp/relic-globals.XXXXXX)
    GLOBALS_TMP=$GLOBALS_RESTORE
    grep -v -E '^CREATE ROLE postgres;[[:space:]]*$|^ALTER ROLE postgres ' "$GLOBALS" > "$GLOBALS_RESTORE" || true
    log "prepared globals for restore (skipping the built-in postgres role)"
fi
if (( RESTORE_OBJECTS )); then
    [[ -f "$FIDBF_ARCHIVE" ]] || die "FIDBF object archive is missing: $FIDBF_ARCHIVE"
    [[ -f "$PROVENANCE_ARCHIVE" ]] || die "provenance object archive is missing: $PROVENANCE_ARCHIVE"
fi
if (( RESTORE_KEYS )); then
    [[ -f "$KEYS_ARCHIVE" ]] || die "key archive is missing: $KEYS_ARCHIVE"
fi
if (( RESTORE_CONFIG )); then
    [[ -f "$CONFIG_ARCHIVE" ]] || die "config archive is missing: $CONFIG_ARCHIVE"
fi

PG_CONN_ARGS=()
[[ -n "$PG_HOST" ]] && PG_CONN_ARGS+=(--host "$PG_HOST")
[[ -n "$PG_PORT" ]] && PG_CONN_ARGS+=(--port "$PG_PORT")
[[ -n "$PG_USER" ]] && PG_CONN_ARGS+=(--username "$PG_USER")

PG_RUNAS_CMD=()
if [[ -n "$PG_RUNAS" ]]; then
    if [[ -x /usr/sbin/runuser ]]; then
        PG_RUNAS_CMD=(/usr/sbin/runuser -u "$PG_RUNAS" --)
    elif command -v runuser >/dev/null 2>&1; then
        PG_RUNAS_CMD=(runuser -u "$PG_RUNAS" --)
    elif command -v sudo >/dev/null 2>&1; then
        PG_RUNAS_CMD=(sudo -u "$PG_RUNAS" --)
    else
        die "cannot run PostgreSQL commands as $PG_RUNAS; set --pg-runas '' for a direct connection"
    fi
fi

run_pg() {
    if ((${#PG_RUNAS_CMD[@]})); then
        "${PG_RUNAS_CMD[@]}" "$@"
    else
        "$@"
    fi
}

db_query() {
    local query=$1
    local database=${2:-$DB_NAME}
    run_pg "$PSQL_BIN" "${PG_CONN_ARGS[@]}" --no-psqlrc --no-password \
        --dbname="$database" -Atqc "$query"
}

database_exists() {
    local result
    result=$(db_query "select 1 from pg_database where datname = '$DB_NAME'" postgres 2>/dev/null || true)
    [[ "$result" == "1" ]]
}

if (( RESTORE_GLOBALS )); then
    log "restoring PostgreSQL globals"
    run_pg "$PSQL_BIN" "${PG_CONN_ARGS[@]}" --no-psqlrc --no-password \
        --dbname=postgres -v ON_ERROR_STOP=1 -f "$GLOBALS_RESTORE"
fi

if database_exists; then
    if (( FORCE == 0 )); then
        die "target database already exists: $DB_NAME (use --force to replace it)"
    fi
    log "dropping existing target database $DB_NAME"
    run_pg "$DROPDB_BIN" "${PG_CONN_ARGS[@]}" --force --if-exists "$DB_NAME"
fi

log "creating target database $DB_NAME"
CREATEDB_ARGS=()
if [[ -n "$DB_OWNER" ]]; then
    CREATEDB_ARGS+=(--owner="$DB_OWNER")
fi
run_pg "$CREATEDB_BIN" "${PG_CONN_ARGS[@]}" "${CREATEDB_ARGS[@]}" "$DB_NAME"

log "restoring database $DB_NAME"
PG_RESTORE_ARGS=(--exit-on-error --single-transaction --dbname="$DB_NAME")
if (( PRESERVE_OWNER == 0 )); then
    PG_RESTORE_ARGS+=(--no-owner --no-privileges)
fi
run_pg "$PG_RESTORE_BIN" "${PG_CONN_ARGS[@]}" "${PG_RESTORE_ARGS[@]}" "$DB_DUMP"

restore_archive() {
    local archive=$1
    local destination=$2
    local label=$3
    local mode=$4

    if [[ -e "$destination" ]] && [[ -n "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]] && (( FORCE == 0 )); then
        die "$label destination is non-empty: $destination (use --force)"
    fi
    if [[ ! -d "$destination" ]]; then
        install -d -m "$mode" "$destination"
    fi
    log "restoring $label into $destination"
    tar --zstd -xf "$archive" -C "$destination"
}

if (( RESTORE_OBJECTS )); then
    restore_archive "$FIDBF_ARCHIVE" "$FIDBF_ROOT" "FIDBF objects" 0755
    restore_archive "$PROVENANCE_ARCHIVE" "$PROVENANCE_ROOT" "provenance objects" 0755
fi

if (( RESTORE_KEYS )); then
    restore_archive "$KEYS_ARCHIVE" "$KEYS_DIR" "system keys" 0700
    chmod -R go-rwx "$KEYS_DIR"
fi

if (( RESTORE_CONFIG )); then
    if [[ ! -d "$CONFIG_ROOT" ]]; then
        install -d -m 0755 "$CONFIG_ROOT"
    fi
    log "restoring configuration under $CONFIG_ROOT"
    tar --zstd -xf "$CONFIG_ARCHIVE" -C "$CONFIG_ROOT"
fi

if (( SKIP_VERIFY == 0 )); then
    log "verifying restored database"
    run_pg "$PSQL_BIN" "${PG_CONN_ARGS[@]}" --no-psqlrc --no-password \
        --dbname="$DB_NAME" -v ON_ERROR_STOP=1 \
        -f "$SCRIPT_DIR/sql/verify-relic-db.sql"

    vector_tables=$(db_query "select (to_regclass('catalogue.bsim_vector') is not null and to_regclass('catalogue.bsim_feature') is not null)")
    if [[ "$vector_tables" == "t" ]]; then
        bad=$(db_query "
            select count(*)
              from (
                select v.bsim_id
                  from catalogue.bsim_vector v
                  left join catalogue.bsim b using (bsim_id)
                  left join catalogue.bsim_feature f using (bsim_id)
                 group by v.bsim_id, v.source_sha256, b.sha256,
                          v.feature_count, v.hash_count, v.norm
                having b.bsim_id is null
                    or v.source_sha256 <> b.sha256
                    or count(f.feature_hash) <> v.feature_count
                    or coalesce(sum(f.tf), 0) <> v.hash_count
                    or abs(v.norm - sqrt(coalesce(sum(f.coefficient * f.coefficient), 0))) > 1e-9
              ) bad
        ")
        [[ "$bad" == "0" ]] || die "BSim vector audit failed: $bad inconsistent vector(s)"
        log "BSim vector audit passed"
    else
        log "BSim vector tables not present in this backup; vector audit skipped"
    fi

    if (( RESTORE_OBJECTS )); then
        missing=0
        while IFS= read -r path; do
            [[ -z "$path" ]] && continue
            if [[ ! -f "$FIDBF_ROOT/$path" ]]; then
                log "missing FIDBF object: $FIDBF_ROOT/$path"
                missing=$((missing + 1))
            fi
        done < <(db_query "select storage_path from catalogue.fidbf where storage_path is not null order by created_at")
        while IFS= read -r path; do
            [[ -z "$path" ]] && continue
            if [[ ! -f "$path" ]]; then
                log "missing provenance object: $path"
                missing=$((missing + 1))
            fi
        done < <(db_query "select storage_path from catalogue.provenance where storage_path is not null order by created_at")
        if (( missing > 0 )); then
            die "$missing referenced object(s) are missing after restore"
        fi
        log "all referenced object paths exist"
    fi
fi

if (( SCRATCH )); then
    log "dropping scratch database $DB_NAME"
    run_pg "$DROPDB_BIN" "${PG_CONN_ARGS[@]}" --force --if-exists "$DB_NAME"
fi

log "restore completed"
log "database: $DB_NAME"
if (( RESTORE_OBJECTS )); then
    log "FIDBF objects: $FIDBF_ROOT"
    log "provenance objects: $PROVENANCE_ROOT"
fi
if (( RESTORE_KEYS )); then
    log "keys: $KEYS_DIR"
fi
