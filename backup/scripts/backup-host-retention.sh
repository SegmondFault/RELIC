#!/usr/bin/env bash
#
# Move completed RELIC backup runs from the write-only incoming directory into
# the archive and apply retention.
#
# This script runs as root on the backup host (the friend's NAS/server). It
# never decrypts backups and never reads the age identity.
#
# The VPS upload account can only write to <base>/incoming. This script is the
# only component that reads, moves or deletes completed runs.

set -Eeuo pipefail

CONFIG_FILE=${RELIC_RETENTION_CONFIG:-/etc/relic-backup-retention.env}

RELIC_BACKUP_BASE=${RELIC_BACKUP_BASE:-/srv/backups/relic}
RELIC_BACKUP_INCOMING=${RELIC_BACKUP_INCOMING:-$RELIC_BACKUP_BASE/incoming}
RELIC_BACKUP_ARCHIVE=${RELIC_BACKUP_ARCHIVE:-$RELIC_BACKUP_BASE/archive}
RELIC_BACKUP_KEEP_DAILY=${RELIC_BACKUP_KEEP_DAILY:-30}
RELIC_BACKUP_KEEP_MONTHLY=${RELIC_BACKUP_KEEP_MONTHLY:-12}
RELIC_BACKUP_INCOMPLETE_HOURS=${RELIC_BACKUP_INCOMPLETE_HOURS:-24}

if [[ -r "$CONFIG_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

RELIC_BACKUP_BASE=${RELIC_BACKUP_BASE:-/srv/backups/relic}
RELIC_BACKUP_INCOMING=${RELIC_BACKUP_INCOMING:-$RELIC_BACKUP_BASE/incoming}
RELIC_BACKUP_ARCHIVE=${RELIC_BACKUP_ARCHIVE:-$RELIC_BACKUP_BASE/archive}
RELIC_BACKUP_KEEP_DAILY=${RELIC_BACKUP_KEEP_DAILY:-30}
RELIC_BACKUP_KEEP_MONTHLY=${RELIC_BACKUP_KEEP_MONTHLY:-12}
RELIC_BACKUP_INCOMPLETE_HOURS=${RELIC_BACKUP_INCOMPLETE_HOURS:-24}

DRY_RUN=0
while (($#)); do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --help|-h)
            cat <<'EOF'
Usage: backup-host-retention.sh [--dry-run]

Environment (or /etc/relic-backup-retention.env):
  RELIC_BACKUP_BASE              default /srv/backups/relic
  RELIC_BACKUP_INCOMING          default $BASE/incoming
  RELIC_BACKUP_ARCHIVE           default $BASE/archive
  RELIC_BACKUP_KEEP_DAILY        default 30
  RELIC_BACKUP_KEEP_MONTHLY      default 12
  RELIC_BACKUP_INCOMPLETE_HOURS  default 24
EOF
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

LOGGER_CMD=$(command -v logger 2>/dev/null || true)
log() {
    local message
    message=$(printf '%s' "$*")
    printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$message" >&2
    if [[ -n "$LOGGER_CMD" ]]; then
        "$LOGGER_CMD" -t relic-backup-retention -- "$message" 2>/dev/null || true
    fi
}

warn() {
    log "WARNING: $*"
}

die() {
    log "ERROR: $*"
    exit 1
}

if (( EUID != 0 )) && (( DRY_RUN == 0 )); then
    die "this script must run as root; use --dry-run for a read-only preview"
fi

for command in sha256sum find sort date awk mv chmod chown mkdir basename wc rm flock; do
    command -v "$command" >/dev/null 2>&1 || die "missing required command: $command"
done

for value in "$RELIC_BACKUP_KEEP_DAILY" "$RELIC_BACKUP_KEEP_MONTHLY" "$RELIC_BACKUP_INCOMPLETE_HOURS"; do
    [[ "$value" =~ ^[0-9]+$ ]] || die "retention values must be non-negative integers"
done

[[ -d "$RELIC_BACKUP_INCOMING" ]] || die "incoming directory is missing: $RELIC_BACKUP_INCOMING"
[[ -d "$RELIC_BACKUP_ARCHIVE" ]] || die "archive directory is missing: $RELIC_BACKUP_ARCHIVE"

if (( DRY_RUN == 0 )); then
    exec 9>"$RELIC_BACKUP_BASE/.retention.lock"
    flock -n 9 || die "another retention run is already active"
fi

move_completed_runs() {
    local marker run_id manifest checksums expected actual
    local dest
    local files=()

    while IFS= read -r -d '' marker; do
        run_id=$(basename "$marker")
        run_id=${run_id%-COMPLETE}
        manifest="$RELIC_BACKUP_INCOMING/$run_id-manifest.json"
        checksums="$RELIC_BACKUP_INCOMING/$run_id-SHA256SUMS"

        if [[ ! -f "$manifest" || ! -f "$checksums" ]]; then
            warn "skipping incomplete run $run_id: manifest or checksums missing"
            continue
        fi

        if ! (cd "$RELIC_BACKUP_INCOMING" && sha256sum -c "$run_id-SHA256SUMS" >/dev/null 2>&1); then
            warn "skipping run $run_id: ciphertext checksums do not match"
            continue
        fi

        expected=$(awk -F= '$1 == "manifest_sha256" {print $2; exit}' "$marker")
        actual=$(sha256sum "$manifest" | awk '{print $1}')
        if [[ -z "$expected" || "$expected" != "$actual" ]]; then
            warn "skipping run $run_id: manifest checksum marker does not match"
            continue
        fi

        log "archiving completed run $run_id"
        if (( DRY_RUN )); then
            log "dry-run: would move $run_id-* to $RELIC_BACKUP_ARCHIVE/$run_id"
            continue
        fi

        dest="$RELIC_BACKUP_ARCHIVE/$run_id"
        mkdir -p -- "$dest"
        chmod 0700 "$dest"

        shopt -s nullglob
        files=("$RELIC_BACKUP_INCOMING/$run_id"-*)
        shopt -u nullglob
        for file in "${files[@]}"; do
            [[ "$file" == *-COMPLETE ]] && continue
            mv -- "$file" "$dest/"
        done
        mv -- "$marker" "$dest/"

        chown -R root:root "$dest"
        find "$dest" -type f -exec chmod 0600 {} +
        log "archived $run_id ($(find "$dest" -type f | wc -l) files)"
    done < <(find "$RELIC_BACKUP_INCOMING" -maxdepth 1 -type f -name '*-COMPLETE' -print0)
}

warn_incomplete_runs() {
    local manifest run_id
    while IFS= read -r -d '' manifest; do
        run_id=$(basename "$manifest")
        run_id=${run_id%-manifest.json}
        if [[ ! -f "$RELIC_BACKUP_INCOMING/$run_id-COMPLETE" ]]; then
            warn "incomplete run remains in incoming: $run_id (no COMPLETE marker)"
        fi
    done < <(
        find "$RELIC_BACKUP_INCOMING" -maxdepth 1 -type f \
            -name '*-manifest.json' -mmin +"$((RELIC_BACKUP_INCOMPLETE_HOURS * 60))" -print0
    )
}

prune_archive() {
    local runs=()
    local run month keep index
    local cutoff_month
    local -A seen_months=()

    mapfile -t runs < <(
        find "$RELIC_BACKUP_ARCHIVE" -mindepth 1 -maxdepth 1 -type d \
            -name '20*T*Z' -printf '%f\n' | sort -r
    )

    if ((${#runs[@]} == 0)); then
        log "archive is empty; nothing to prune"
        return
    fi

    cutoff_month=$(date -u -d "$RELIC_BACKUP_KEEP_MONTHLY months ago" +%Y%m)

    for index in "${!runs[@]}"; do
        run=${runs[$index]}
        month=${run:0:6}
        keep=0

        if (( index < RELIC_BACKUP_KEEP_DAILY )); then
            keep=1
        fi

        if (( RELIC_BACKUP_KEEP_MONTHLY > 0 )) \
            && [[ "$month" > "$cutoff_month" || "$month" == "$cutoff_month" ]] \
            && [[ -z "${seen_months[$month]:-}" ]]; then
            seen_months[$month]=1
            keep=1
        fi

        if (( keep )); then
            continue
        fi

        if (( DRY_RUN )); then
            log "dry-run: would remove archive run $run"
        else
            log "removing expired archive run $run"
            rm -rf -- "${RELIC_BACKUP_ARCHIVE:?}/$run"
        fi
    done
}

move_completed_runs
warn_incomplete_runs
prune_archive

log "retention completed"
