#!/usr/bin/env bash
#
# Encrypted RELIC backup.
#
# The script runs as root, dumps PostgreSQL as the postgres operating-system
# user, encrypts every artifact with age, writes a manifest and checksums, and
# uploads the completed run with rsync.
#
# Configuration is read from /etc/relic/backup.env unless RELIC_BACKUP_CONFIG
# points elsewhere. See backup/scripts/backup.env.example and backup/docs/backups.md.

set -Eeuo pipefail

CONFIG_FILE=${RELIC_BACKUP_CONFIG:-/etc/relic/backup.env}

# ---------------------------------------------------------------------------
# Defaults. The configuration file may override any of these.
# ---------------------------------------------------------------------------

RELIC_DATABASE=${RELIC_DATABASE:-relic}
RELIC_PG_RUNAS=${RELIC_PG_RUNAS-postgres}
RELIC_PG_HOST=${RELIC_PG_HOST:-}
RELIC_PG_PORT=${RELIC_PG_PORT:-}
RELIC_PG_USER=${RELIC_PG_USER:-}
RELIC_BACKUP_STAGING=${RELIC_BACKUP_STAGING:-/var/backups/relic}
RELIC_BACKUP_LOCAL_RETAIN_DAYS=${RELIC_BACKUP_LOCAL_RETAIN_DAYS:-7}
RELIC_REPO_DIR=${RELIC_REPO_DIR:-/srv/relic}
RELIC_FIDBF_ROOT=${RELIC_FIDBF_ROOT:-/srv/relic-objects}
RELIC_PROVENANCE_ROOT=${RELIC_PROVENANCE_ROOT:-/srv/relic-data}
RELIC_KEYS_DIR=${RELIC_KEYS_DIR:-/var/lib/relic/keys}
RELIC_PG_CONFIG_DIR=${RELIC_PG_CONFIG_DIR:-/etc/postgresql/15/main}
RELIC_BACKUP_AGE_RECIPIENTS=${RELIC_BACKUP_AGE_RECIPIENTS:-}
RELIC_BACKUP_REMOTE=${RELIC_BACKUP_REMOTE:-}
RELIC_BACKUP_SSH_KEY=${RELIC_BACKUP_SSH_KEY:-/root/.ssh/relic_backup_ed25519}
RELIC_BACKUP_SSH_PORT=${RELIC_BACKUP_SSH_PORT:-22}
RELIC_BACKUP_KNOWN_HOSTS=${RELIC_BACKUP_KNOWN_HOSTS:-/root/.ssh/known_hosts}
RELIC_BACKUP_ALLOW_NONROOT=${RELIC_BACKUP_ALLOW_NONROOT:-0}

if [[ -r "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# Re-apply defaults for values the configuration file left empty.
RELIC_DATABASE=${RELIC_DATABASE:-relic}
RELIC_PG_RUNAS=${RELIC_PG_RUNAS-postgres}
RELIC_BACKUP_STAGING=${RELIC_BACKUP_STAGING:-/var/backups/relic}
RELIC_BACKUP_LOCAL_RETAIN_DAYS=${RELIC_BACKUP_LOCAL_RETAIN_DAYS:-7}
RELIC_REPO_DIR=${RELIC_REPO_DIR:-/srv/relic}
RELIC_FIDBF_ROOT=${RELIC_FIDBF_ROOT:-/srv/relic-objects}
RELIC_PROVENANCE_ROOT=${RELIC_PROVENANCE_ROOT:-/srv/relic-data}
RELIC_KEYS_DIR=${RELIC_KEYS_DIR:-/var/lib/relic/keys}
RELIC_PG_CONFIG_DIR=${RELIC_PG_CONFIG_DIR:-/etc/postgresql/15/main}
RELIC_BACKUP_SSH_KEY=${RELIC_BACKUP_SSH_KEY:-/root/.ssh/relic_backup_ed25519}
RELIC_BACKUP_SSH_PORT=${RELIC_BACKUP_SSH_PORT:-22}
RELIC_BACKUP_KNOWN_HOSTS=${RELIC_BACKUP_KNOWN_HOSTS:-/root/.ssh/known_hosts}
RELIC_BACKUP_ALLOW_NONROOT=${RELIC_BACKUP_ALLOW_NONROOT:-0}

# ---------------------------------------------------------------------------
# Command-line options
# ---------------------------------------------------------------------------

CHECK_ONLY=0
DO_OBJECTS=1
DO_KEYS=1
DO_CONFIG=1
DO_UPLOAD=1

usage() {
    cat <<'EOF'
Usage: backup-relic.sh [options]

Options:
  --check           Validate dependencies, paths, database access, age recipient
                    and staging space without writing a backup.
  --db-only         Back up PostgreSQL and globals only.
  --skip-objects    Do not back up /srv/relic-objects or /srv/relic-data.
  --skip-keys       Do not back up /var/lib/relic/keys.
  --skip-config     Do not back up PostgreSQL and RELIC configuration.
  --no-upload       Keep the encrypted run locally; do not run rsync.
  --help            Show this help.

Environment:
  RELIC_BACKUP_CONFIG   Configuration file (default: /etc/relic/backup.env).
  See backup/scripts/backup.env.example.
EOF
}

while (($#)); do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --db-only) DO_OBJECTS=0; DO_KEYS=0; DO_CONFIG=0 ;;
        --skip-objects) DO_OBJECTS=0 ;;
        --skip-keys) DO_KEYS=0 ;;
        --skip-config) DO_CONFIG=0 ;;
        --no-upload) DO_UPLOAD=0 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# Logging and error handling
# ---------------------------------------------------------------------------

LOGGER_CMD=$(command -v logger 2>/dev/null || true)
LOG_TAG=relic-backup

log() {
    local message
    message=$(printf '%s' "$*")
    printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$message" >&2
    if [[ -n "$LOGGER_CMD" ]]; then
        "$LOGGER_CMD" -t "$LOG_TAG" -- "$message" 2>/dev/null || true
    fi
}

warn() {
    log "WARNING: $*"
}

die() {
    log "ERROR: $*"
    exit 1
}

on_error() {
    local status=$?
    log "ERROR: backup failed (exit $status) while running: $BASH_COMMAND"
    exit "$status"
}

trap on_error ERR

TEMP_DIRS=()
cleanup_temp() {
    local dir
    for dir in "${TEMP_DIRS[@]:-}"; do
        if [[ -n "$dir" ]]; then
            rm -rf -- "$dir"
        fi
    done
    return 0
}
trap cleanup_temp EXIT

# ---------------------------------------------------------------------------
# Root and dependency checks
# ---------------------------------------------------------------------------

umask 077

if (( EUID != 0 )); then
    if [[ "$RELIC_BACKUP_ALLOW_NONROOT" == "1" ]]; then
        warn "running as non-root because RELIC_BACKUP_ALLOW_NONROOT=1"
        warn "this mode is for local testing only; keys and root-only paths may be unreadable"
    else
        die "this script must run as root (set RELIC_BACKUP_ALLOW_NONROOT=1 only for local testing)"
    fi
fi

if [[ -e "$CONFIG_FILE" ]]; then
    config_mode=$(stat -c %a "$CONFIG_FILE" 2>/dev/null || echo 600)
    if (( (8#$config_mode & 077) != 0 )); then
        warn "configuration file permissions are open: $CONFIG_FILE (expected 0600)"
    fi
fi

MISSING=()
need_command() {
    command -v "$1" >/dev/null 2>&1 || MISSING+=("$1")
}

need_command age
need_command pg_dump
need_command pg_dumpall
need_command psql
need_command tar
need_command zstd
need_command sha256sum
need_command stat
need_command du
need_command df
need_command find
need_command flock
need_command hostname
need_command date
need_command mktemp
need_command awk
need_command sort
need_command tr
if (( DO_UPLOAD )); then
    need_command rsync
fi

if ((${#MISSING[@]})); then
    die "missing required commands: ${MISSING[*]}"
fi

AGE_BIN=$(command -v age)
PG_DUMP_BIN=$(command -v pg_dump)
PG_DUMPALL_BIN=$(command -v pg_dumpall)
PSQL_BIN=$(command -v psql)
RSYNC_BIN=""
if (( DO_UPLOAD )); then
    RSYNC_BIN=$(command -v rsync)
fi

# ---------------------------------------------------------------------------
# PostgreSQL execution and connection handling
# ---------------------------------------------------------------------------

PG_CONN_ARGS=()
[[ -n "$RELIC_PG_HOST" ]] && PG_CONN_ARGS+=(--host "$RELIC_PG_HOST")
[[ -n "$RELIC_PG_PORT" ]] && PG_CONN_ARGS+=(--port "$RELIC_PG_PORT")
[[ -n "$RELIC_PG_USER" ]] && PG_CONN_ARGS+=(--username "$RELIC_PG_USER")

PG_RUNAS_CMD=()
if [[ -n "$RELIC_PG_RUNAS" ]]; then
    if [[ -x /usr/sbin/runuser ]]; then
        PG_RUNAS_CMD=(/usr/sbin/runuser -u "$RELIC_PG_RUNAS" --)
    elif command -v runuser >/dev/null 2>&1; then
        PG_RUNAS_CMD=(runuser -u "$RELIC_PG_RUNAS" --)
    elif command -v sudo >/dev/null 2>&1; then
        PG_RUNAS_CMD=(sudo -u "$RELIC_PG_RUNAS" --)
    else
        die "cannot run PostgreSQL commands as $RELIC_PG_RUNAS: install runuser or sudo, or set RELIC_PG_RUNAS="
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
    run_pg "$PSQL_BIN" "${PG_CONN_ARGS[@]}" --no-psqlrc --no-password \
        --dbname="$RELIC_DATABASE" -Atqc "$query"
}

# ---------------------------------------------------------------------------
# age recipients and validation
# ---------------------------------------------------------------------------

AGE_RECIPIENTS=()
for recipient in ${RELIC_BACKUP_AGE_RECIPIENTS//,/ }; do
    [[ -n "$recipient" ]] && AGE_RECIPIENTS+=("$recipient")
done

AGE_ARGS=()
for recipient in "${AGE_RECIPIENTS[@]}"; do
    AGE_ARGS+=(-r "$recipient")
done

if ((${#AGE_ARGS[@]} == 0)); then
    die "RELIC_BACKUP_AGE_RECIPIENTS is empty; configure at least one age public recipient"
fi

if ! printf 'relic-backup-recipient-check\n' | "$AGE_BIN" "${AGE_ARGS[@]}" >/dev/null 2>&1; then
    die "the configured age recipient(s) rejected a test encryption"
fi

# ---------------------------------------------------------------------------
# Paths, sizes and staging
# ---------------------------------------------------------------------------

path_kb() {
    local path=$1
    local kb
    if [[ -e "$path" ]]; then
        kb=$(du -sk "$path" 2>/dev/null | awk 'NR == 1 {print $1}')
        printf '%s\n' "${kb:-0}"
    else
        printf '0\n'
    fi
}

object_kb=0
if (( DO_OBJECTS )); then
    [[ -d "$RELIC_FIDBF_ROOT" ]] || die "FIDBF object root does not exist: $RELIC_FIDBF_ROOT"
    [[ -d "$RELIC_PROVENANCE_ROOT" ]] || die "provenance object root does not exist: $RELIC_PROVENANCE_ROOT"
    object_kb=$(( $(path_kb "$RELIC_FIDBF_ROOT") + $(path_kb "$RELIC_PROVENANCE_ROOT") ))
fi

if (( DO_KEYS )); then
    [[ -d "$RELIC_KEYS_DIR" ]] || die "key directory does not exist: $RELIC_KEYS_DIR"
    [[ -r "$RELIC_KEYS_DIR" ]] || die "key directory is not readable: $RELIC_KEYS_DIR"
fi

if (( DO_CONFIG )); then
    [[ -d "$RELIC_PG_CONFIG_DIR" ]] || die "PostgreSQL configuration directory does not exist: $RELIC_PG_CONFIG_DIR"
fi

DB_VERSION=$(db_query "show server_version") || die "cannot query PostgreSQL server version for database $RELIC_DATABASE"
DB_SIZE_BYTES=$(db_query "select pg_database_size(current_database())") || DB_SIZE_BYTES=0
DB_SIZE_KB=$(( (DB_SIZE_BYTES + 1023) / 1024 ))

PG_DUMP_VERSION=$("$PG_DUMP_BIN" --version | awk '{print $3}')
SERVER_MAJOR=${DB_VERSION%%.*}
PG_DUMP_MAJOR=${PG_DUMP_VERSION%%.*}
if [[ "$SERVER_MAJOR" != "$PG_DUMP_MAJOR" ]]; then
    die "pg_dump major version $PG_DUMP_MAJOR does not match server major version $SERVER_MAJOR"
fi

space_path=$RELIC_BACKUP_STAGING
if [[ ! -e "$space_path" ]]; then
    space_path=$(dirname "$space_path")
fi
AVAILABLE_KB=$(df -Pk "$space_path" 2>/dev/null | awk 'NR == 2 {print $4}')
[[ -n "$AVAILABLE_KB" ]] || AVAILABLE_KB=0
REQUIRED_KB=$(( object_kb + DB_SIZE_KB + 262144 ))
if (( AVAILABLE_KB < REQUIRED_KB )); then
    die "insufficient staging space at $space_path: need at least ${REQUIRED_KB} KiB, have ${AVAILABLE_KB} KiB"
fi

# ---------------------------------------------------------------------------
# Offsite destination
# ---------------------------------------------------------------------------

remote_is_local() {
    [[ -n "$RELIC_BACKUP_REMOTE" && "$RELIC_BACKUP_REMOTE" == /* ]]
}

SSH_CMD=()
RSYNC_RSH=
if (( DO_UPLOAD )); then
    [[ -n "$RELIC_BACKUP_REMOTE" ]] || die "RELIC_BACKUP_REMOTE is empty; use --no-upload for a local trial"

    if remote_is_local; then
        if [[ -e "$RELIC_BACKUP_REMOTE" && ! -w "$RELIC_BACKUP_REMOTE" ]]; then
            die "local backup destination is not writable: $RELIC_BACKUP_REMOTE"
        fi
    else
        command -v ssh >/dev/null 2>&1 || die "ssh is required for a remote rsync destination"
        [[ -r "$RELIC_BACKUP_SSH_KEY" ]] || die "SSH key is missing or unreadable: $RELIC_BACKUP_SSH_KEY"
        key_mode=$(stat -c %a "$RELIC_BACKUP_SSH_KEY")
        if (( (8#$key_mode & 077) != 0 )); then
            die "SSH key permissions are too open: $RELIC_BACKUP_SSH_KEY (expected 0600 or 0400)"
        fi
        [[ -r "$RELIC_BACKUP_KNOWN_HOSTS" ]] || die "known_hosts is missing: $RELIC_BACKUP_KNOWN_HOSTS"
        [[ "$RELIC_BACKUP_SSH_PORT" =~ ^[0-9]+$ ]] || die "RELIC_BACKUP_SSH_PORT must be numeric"

        SSH_CMD=(ssh -i "$RELIC_BACKUP_SSH_KEY" -p "$RELIC_BACKUP_SSH_PORT"
            -o BatchMode=yes
            -o IdentitiesOnly=yes
            -o StrictHostKeyChecking=yes
            -o "UserKnownHostsFile=$RELIC_BACKUP_KNOWN_HOSTS")
        RSYNC_RSH="${SSH_CMD[*]}"
    fi
fi

# ---------------------------------------------------------------------------
# Summary / check mode
# ---------------------------------------------------------------------------

if (( CHECK_ONLY )); then
    log "root check: $([[ $EUID -eq 0 ]] && echo yes || echo 'no (testing override)')"
    log "database: $RELIC_DATABASE ($DB_VERSION, $DB_SIZE_BYTES bytes)"
    if (( DO_OBJECTS )); then
        log "FIDBF objects: $RELIC_FIDBF_ROOT ($(path_kb "$RELIC_FIDBF_ROOT") KiB)"
        log "provenance objects: $RELIC_PROVENANCE_ROOT ($(path_kb "$RELIC_PROVENANCE_ROOT") KiB)"
    else
        log "objects: skipped"
    fi
    if (( DO_KEYS )); then
        log "keys: $RELIC_KEYS_DIR ($(path_kb "$RELIC_KEYS_DIR") KiB)"
    else
        log "keys: skipped"
    fi
    if (( DO_CONFIG )); then
        log "PostgreSQL config: $RELIC_PG_CONFIG_DIR"
    else
        log "config: skipped"
    fi
    log "staging: $RELIC_BACKUP_STAGING (available ${AVAILABLE_KB} KiB, projected need ${REQUIRED_KB} KiB)"
    log "age recipients: ${#AGE_RECIPIENTS[@]} (test encryption succeeded)"
    if (( DO_UPLOAD )); then
        if remote_is_local; then
            log "local backup destination: $RELIC_BACKUP_REMOTE"
        else
            log "rsync destination: $RELIC_BACKUP_REMOTE"
            log "SSH key: $RELIC_BACKUP_SSH_KEY"
            log "known_hosts: $RELIC_BACKUP_KNOWN_HOSTS"
            warn "SSH connectivity is not exercised by --check; the first real upload tests it"
        fi
    else
        log "upload: disabled (--no-upload)"
    fi
    log "check completed successfully"
    exit 0
fi

# ---------------------------------------------------------------------------
# Staging lock and run directory
# ---------------------------------------------------------------------------

install -d -m 0700 -o root -g root "$RELIC_BACKUP_STAGING" 2>/dev/null || install -d -m 0700 "$RELIC_BACKUP_STAGING"

exec 9>"$RELIC_BACKUP_STAGING/.backup.lock"
if ! flock -n 9; then
    die "another RELIC backup is already running"
fi

run_id=$(date -u +%Y%m%dT%H%M%SZ)
run_dir="$RELIC_BACKUP_STAGING/run-$run_id"
while [[ -e "$run_dir" ]]; do
    sleep 1
    run_id=$(date -u +%Y%m%dT%H%M%SZ)
    run_dir="$RELIC_BACKUP_STAGING/run-$run_id"
done
mkdir -m 0700 "$run_dir"

created_at=$(date -u +%FT%TZ)
files_tsv="$run_dir/.files.tsv"
: > "$files_tsv"

log "starting backup run $run_id in $run_dir"

record_file() {
    local path=$1
    local name size digest
    name=$(basename "$path")
    size=$(stat -c %s "$path")
    digest=$(sha256sum "$path" | awk '{print $1}')
    printf '%s\t%s\t%s\n' "$name" "$size" "$digest" >> "$files_tsv"
}

# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------

log "dumping database $RELIC_DATABASE"
db_dump="$run_dir/${run_id}-db.dump.age"
run_pg "$PG_DUMP_BIN" "${PG_CONN_ARGS[@]}" \
    --format=custom --compress=6 --no-password \
    --dbname="$RELIC_DATABASE" \
    | "$AGE_BIN" "${AGE_ARGS[@]}" -o "$db_dump"
record_file "$db_dump"

log "dumping PostgreSQL globals"
globals_dump="$run_dir/${run_id}-globals.sql.age"
run_pg "$PG_DUMPALL_BIN" "${PG_CONN_ARGS[@]}" --globals-only --no-password \
    | "$AGE_BIN" "${AGE_ARGS[@]}" -o "$globals_dump"
record_file "$globals_dump"

# ---------------------------------------------------------------------------
# Objects, keys and configuration
# ---------------------------------------------------------------------------

archive_directory() {
    local source=$1
    local output=$2
    tar --numeric-owner -C "$source" -cf - . \
        | zstd -T0 -q -c \
        | "$AGE_BIN" "${AGE_ARGS[@]}" -o "$output"
}

if (( DO_OBJECTS )); then
    log "archiving FIDBF objects from $RELIC_FIDBF_ROOT"
    fidbf_archive="$run_dir/${run_id}-fidbf-objects.tar.zst.age"
    archive_directory "$RELIC_FIDBF_ROOT" "$fidbf_archive"
    record_file "$fidbf_archive"

    log "archiving provenance/BSim objects from $RELIC_PROVENANCE_ROOT"
    provenance_archive="$run_dir/${run_id}-provenance-objects.tar.zst.age"
    archive_directory "$RELIC_PROVENANCE_ROOT" "$provenance_archive"
    record_file "$provenance_archive"
fi

if (( DO_KEYS )); then
    log "archiving system keys from $RELIC_KEYS_DIR"
    keys_archive="$run_dir/${run_id}-keys.tar.zst.age"
    archive_directory "$RELIC_KEYS_DIR" "$keys_archive"
    record_file "$keys_archive"
fi

if (( DO_CONFIG )); then
    log "archiving PostgreSQL and RELIC configuration"
    config_paths=()
    config_paths+=("${RELIC_PG_CONFIG_DIR#/}")
    [[ -d /etc/relic ]] && config_paths+=("etc/relic")
    [[ -f /etc/systemd/system/relic-backup.service ]] && config_paths+=("etc/systemd/system/relic-backup.service")
    [[ -f /etc/systemd/system/relic-backup.timer ]] && config_paths+=("etc/systemd/system/relic-backup.timer")
    config_archive="$run_dir/${run_id}-config.tar.zst.age"
    tar --numeric-owner -C / -cf - "${config_paths[@]}" \
        | zstd -T0 -q -c \
        | "$AGE_BIN" "${AGE_ARGS[@]}" -o "$config_archive"
    record_file "$config_archive"
fi

# ---------------------------------------------------------------------------
# Checksums and manifest
# ---------------------------------------------------------------------------

log "writing checksums and manifest"
(
    cd "$run_dir"
    sha256sum ./*.age > "${run_id}-SHA256SUMS"
)
record_file "$run_dir/${run_id}-SHA256SUMS"

json_escape() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\r'/\\r}
    value=${value//$'\t'/\\t}
    printf '%s' "$value"
}

relic_commit=unknown
relic_dirty=false
if [[ -d "$RELIC_REPO_DIR/.git" ]]; then
    relic_commit=$(git -c "safe.directory=$RELIC_REPO_DIR" -C "$RELIC_REPO_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
    if [[ -n "$(git -c "safe.directory=$RELIC_REPO_DIR" -C "$RELIC_REPO_DIR" status --porcelain 2>/dev/null || true)" ]]; then
        relic_dirty=true
    fi
fi

host_label=$(hostname -f 2>/dev/null || hostname)
migration_files=()
if [[ -d "$RELIC_REPO_DIR/database/migrations" ]]; then
    mapfile -t migration_files < <(
        find "$RELIC_REPO_DIR/database/migrations" -maxdepth 1 -type f -name '*.sql' -printf '%f\n' 2>/dev/null | sort
    )
fi

manifest="$run_dir/${run_id}-manifest.json"
{
    printf '{\n'
    printf '  "run_id": "%s",\n' "$(json_escape "$run_id")"
    printf '  "created_at": "%s",\n' "$(json_escape "$created_at")"
    printf '  "hostname": "%s",\n' "$(json_escape "$host_label")"
    printf '  "database": "%s",\n' "$(json_escape "$RELIC_DATABASE")"
    printf '  "postgres_version": "%s",\n' "$(json_escape "$DB_VERSION")"
    printf '  "database_size_bytes": %s,\n' "${DB_SIZE_BYTES:-0}"
    printf '  "relic_commit": "%s",\n' "$(json_escape "$relic_commit")"
    printf '  "relic_dirty": %s,\n' "$relic_dirty"

    printf '  "age_recipients": ['
    first=1
    for recipient in "${AGE_RECIPIENTS[@]}"; do
        ((first)) || printf ', '
        printf '"%s"' "$(json_escape "$recipient")"
        first=0
    done
    printf '],\n'

    printf '  "migrations": ['
    first=1
    for migration in "${migration_files[@]}"; do
        ((first)) || printf ', '
        printf '"%s"' "$(json_escape "$migration")"
        first=0
    done
    printf '],\n'

    printf '  "files": [\n'
    first=1
    while IFS=$'\t' read -r name size digest; do
        ((first)) || printf ',\n'
        printf '    {"name": "%s", "size": %s, "sha256": "%s"}' \
            "$(json_escape "$name")" "$size" "$(json_escape "$digest")"
        first=0
    done < "$files_tsv"
    printf '\n  ]\n'
    printf '}\n'
} > "$manifest"
chmod 0600 "$manifest"

manifest_sha=$(sha256sum "$manifest" | awk '{print $1}')
complete="$run_dir/${run_id}-COMPLETE"
{
    printf 'run_id=%s\n' "$run_id"
    printf 'manifest_sha256=%s\n' "$manifest_sha"
    printf 'created_at=%s\n' "$created_at"
} > "$complete"
chmod 0600 "$complete"

# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

if (( DO_UPLOAD )); then
    log "uploading run $run_id to $RELIC_BACKUP_REMOTE"
    if remote_is_local; then
        mkdir -p -- "$RELIC_BACKUP_REMOTE"
        "$RSYNC_BIN" -a --checksum --exclude '*-COMPLETE' -- \
            "$run_dir/" "${RELIC_BACKUP_REMOTE%/}/"
        "$RSYNC_BIN" -a --checksum -- \
            "$complete" "${RELIC_BACKUP_REMOTE%/}/"
    else
        "$RSYNC_BIN" -a --checksum --protect-args -e "$RSYNC_RSH" \
            --exclude '*-COMPLETE' -- \
            "$run_dir/" "${RELIC_BACKUP_REMOTE%/}/"
        "$RSYNC_BIN" -a --checksum --protect-args -e "$RSYNC_RSH" -- \
            "$complete" "${RELIC_BACKUP_REMOTE%/}/"
    fi
    : > "$run_dir/UPLOADED"
    chmod 0600 "$run_dir/UPLOADED"
    log "upload completed"
else
    warn "upload disabled; encrypted run retained at $run_dir"
fi

# ---------------------------------------------------------------------------
# Local retention
# ---------------------------------------------------------------------------

if [[ "$RELIC_BACKUP_LOCAL_RETAIN_DAYS" =~ ^[0-9]+$ ]] && (( RELIC_BACKUP_LOCAL_RETAIN_DAYS > 0 )); then
    while IFS= read -r -d '' old_run; do
        if [[ -f "$old_run/UPLOADED" ]]; then
            log "removing expired local run $(basename "$old_run")"
            rm -rf -- "$old_run"
        fi
    done < <(
        find "$RELIC_BACKUP_STAGING" -mindepth 1 -maxdepth 1 -type d \
            -name 'run-*' -mtime +"$RELIC_BACKUP_LOCAL_RETAIN_DAYS" -print0
    )
fi

log "backup run $run_id completed successfully"
log "artifacts: $run_dir"
