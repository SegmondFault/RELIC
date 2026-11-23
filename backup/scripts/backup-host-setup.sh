#!/usr/bin/env bash
#
# Prepare a backup host for RELIC encrypted uploads.
#
# This script is intended to run as root on the machine that receives the
# backups (the friend's NAS/server). It creates a restricted SSH account that
# can only push files with rrsync into the incoming directory. It does not
# install an age identity and it does not decrypt backups.
#
# Usage:
#   backup-host-setup.sh --public-key-file /path/to/relic_backup_ed25519.pub \
#       --vps-ip 203.0.113.10
#
# The public key file is the .pub file generated on the RELIC VPS. Give the VPS
# owner the host-key fingerprint printed by this script and have them verify it
# out of band before adding it to known_hosts.

set -Eeuo pipefail

BACKUP_USER=${RELIC_BACKUP_USER:-relic-backup}
BACKUP_HOME=${RELIC_BACKUP_HOME:-}
BACKUP_BASE=${RELIC_BACKUP_BASE:-/srv/backups/relic}
VPS_IP=${RELIC_BACKUP_VPS_IP:-}
PUBKEY_FILE=
RETENTION_SCRIPT=
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: backup-host-setup.sh --public-key-file FILE [options]

Options:
  --public-key-file FILE   SSH public key generated on the RELIC VPS.
  --vps-ip ADDRESS         Restrict the key to this source address.
  --base DIR               Backup root (default: /srv/backups/relic).
  --user NAME              Restricted account (default: relic-backup).
  --retention-script FILE  Install this retention script under
                           /usr/local/sbin/relic-backup-retention.
  --dry-run                Print actions without changing the system.
  --help                   Show this help.

Environment:
  RELIC_BACKUP_USER, RELIC_BACKUP_HOME, RELIC_BACKUP_BASE,
  RELIC_BACKUP_VPS_IP

The account is restricted to:
  rrsync -wo <base>/incoming
The VPS can upload, but cannot read or delete the archive.
EOF
}

while (($#)); do
    case "$1" in
        --public-key-file) PUBKEY_FILE=${2:-}; shift 2 ;;
        --vps-ip) VPS_IP=${2:-}; shift 2 ;;
        --base) BACKUP_BASE=${2:-}; shift 2 ;;
        --user) BACKUP_USER=${2:-}; shift 2 ;;
        --retention-script) RETENTION_SCRIPT=${2:-}; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
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

BACKUP_HOME=${BACKUP_HOME:-/var/lib/$BACKUP_USER}

if (( EUID != 0 )) && (( DRY_RUN == 0 )); then
    die "this script must run as root; use --dry-run for a read-only preview"
fi

[[ -n "$BACKUP_BASE" ]] || die "backup base directory must not be empty"
[[ "$BACKUP_BASE" == /* ]] || die "backup base directory must be absolute"
[[ "$BACKUP_BASE" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "backup base directory contains unsupported characters: $BACKUP_BASE"
[[ "$BACKUP_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid backup user name: $BACKUP_USER"

INCOMING="$BACKUP_BASE/incoming"
ARCHIVE="$BACKUP_BASE/archive"
AUTH_DIR="$BACKUP_HOME/.ssh"
AUTH_FILE="$AUTH_DIR/authorized_keys"

for cmd in install useradd id rsync ssh-keygen; do
    command -v "$cmd" >/dev/null 2>&1 || die "missing required command: $cmd"
done

install_rrsync() {
    if command -v rrsync >/dev/null 2>&1; then
        RRSYNC_BIN=$(command -v rrsync)
        return
    fi

    RRSYNC_BIN=/usr/local/bin/rrsync
    if (( DRY_RUN )); then
        log "dry-run: would install rrsync at $RRSYNC_BIN"
        return
    fi

    if [[ -f /usr/share/doc/rsync/scripts/rrsync.gz ]]; then
        command -v zcat >/dev/null 2>&1 || die "rrsync is missing and zcat is not installed"
        zcat /usr/share/doc/rsync/scripts/rrsync.gz > "$RRSYNC_BIN"
    elif [[ -f /usr/share/doc/rsync/scripts/rrsync ]]; then
        cp /usr/share/doc/rsync/scripts/rrsync "$RRSYNC_BIN"
    else
        die "rrsync was not found; install the rsync package and retry"
    fi
    chmod 0755 "$RRSYNC_BIN"
}

RRSYNC_BIN=
install_rrsync
if [[ -z "$RRSYNC_BIN" ]]; then
    die "could not determine the rrsync path"
fi

if [[ -n "$RRSYNC_BIN" && -r "$RRSYNC_BIN" ]] && ! grep -q -- '-wo' "$RRSYNC_BIN"; then
    die "$RRSYNC_BIN does not support write-only (-wo) mode; install a newer rsync"
fi

if (( DRY_RUN )); then
    log "dry-run: backup user: $BACKUP_USER"
    log "dry-run: backup home: $BACKUP_HOME"
    log "dry-run: incoming: $INCOMING"
    log "dry-run: archive: $ARCHIVE"
    if [[ -n "$PUBKEY_FILE" ]]; then
        [[ -r "$PUBKEY_FILE" ]] || die "public key file is not readable: $PUBKEY_FILE"
        dry_auth_options="command=\"$RRSYNC_BIN -wo $INCOMING\",restrict"
        if [[ -n "$VPS_IP" ]]; then
            dry_auth_options="from=\"$VPS_IP\",$dry_auth_options"
        fi
        log "dry-run: would authorize $PUBKEY_FILE for $BACKUP_USER"
        log "dry-run: authorized_keys options: $dry_auth_options"
    else
        log "dry-run: no --public-key-file supplied; key installation skipped"
    fi
    if [[ -n "$RETENTION_SCRIPT" ]]; then
        [[ -r "$RETENTION_SCRIPT" ]] || die "retention script is not readable: $RETENTION_SCRIPT"
        log "dry-run: would install $RETENTION_SCRIPT as /usr/local/sbin/relic-backup-retention"
    fi
    log "dry-run completed"
    exit 0
fi

[[ -n "$PUBKEY_FILE" ]] || die "--public-key-file is required"
[[ -r "$PUBKEY_FILE" ]] || die "public key file is not readable: $PUBKEY_FILE"

PUBKEY=$(head -n 1 "$PUBKEY_FILE" | tr -d '\r')
[[ -n "$PUBKEY" ]] || die "public key file is empty: $PUBKEY_FILE"
if [[ ! "$PUBKEY" =~ ^(ssh-|ecdsa-) ]]; then
    die "public key file does not look like an OpenSSH public key: $PUBKEY_FILE"
fi
if [[ -n "$VPS_IP" ]] && [[ ! "$VPS_IP" =~ ^[A-Za-z0-9:._-]+$ ]]; then
    die "invalid VPS address for from= restriction: $VPS_IP"
fi

if [[ -z "$VPS_IP" ]]; then
    log "WARNING: no --vps-ip supplied; the key is not restricted by source address"
fi

if ! id -u "$BACKUP_USER" >/dev/null 2>&1; then
    log "creating system account $BACKUP_USER"
    useradd --system --create-home --home-dir "$BACKUP_HOME" \
        --shell /bin/bash "$BACKUP_USER"
else
    log "account $BACKUP_USER already exists"
fi

install -d -m 0755 -o root -g root "$BACKUP_BASE"
install -d -m 0700 -o "$BACKUP_USER" -g "$BACKUP_USER" "$INCOMING"
install -d -m 0700 -o root -g root "$ARCHIVE"
install -d -m 0700 -o "$BACKUP_USER" -g "$BACKUP_USER" "$AUTH_DIR"

if [[ ! -f "$AUTH_FILE" ]]; then
    install -m 0600 -o "$BACKUP_USER" -g "$BACKUP_USER" /dev/null "$AUTH_FILE"
fi

AUTH_OPTIONS="command=\"$RRSYNC_BIN -wo $INCOMING\",restrict"
if [[ -n "$VPS_IP" ]]; then
    AUTH_OPTIONS="from=\"$VPS_IP\",$AUTH_OPTIONS"
fi
AUTH_LINE="$AUTH_OPTIONS $PUBKEY"

if grep -qF -- "$PUBKEY" "$AUTH_FILE"; then
    log "the supplied public key is already present in $AUTH_FILE"
else
    printf '%s\n' "$AUTH_LINE" >> "$AUTH_FILE"
    log "installed the public key in $AUTH_FILE"
fi
chown "$BACKUP_USER:$BACKUP_USER" "$AUTH_FILE"
chmod 0600 "$AUTH_FILE"

if [[ -n "$RETENTION_SCRIPT" ]]; then
    [[ -r "$RETENTION_SCRIPT" ]] || die "retention script is not readable: $RETENTION_SCRIPT"
    install -m 0755 -o root -g root "$RETENTION_SCRIPT" /usr/local/sbin/relic-backup-retention
    log "installed retention script as /usr/local/sbin/relic-backup-retention"

    retention_config=/etc/relic-backup-retention.env
    if [[ ! -e "$retention_config" ]]; then
        {
            printf 'RELIC_BACKUP_BASE=%s\n' "$BACKUP_BASE"
            printf 'RELIC_BACKUP_INCOMING=%s\n' "$INCOMING"
            printf 'RELIC_BACKUP_ARCHIVE=%s\n' "$ARCHIVE"
            printf 'RELIC_BACKUP_KEEP_DAILY=30\n'
            printf 'RELIC_BACKUP_KEEP_MONTHLY=12\n'
            printf 'RELIC_BACKUP_INCOMPLETE_HOURS=24\n'
        } > "$retention_config"
        chmod 0600 "$retention_config"
        log "wrote retention configuration to $retention_config"
    else
        log "retention configuration already exists: $retention_config (not overwritten)"
    fi
fi

log "host key fingerprints (verify these with the RELIC VPS owner):"
for key in /etc/ssh/ssh_host_ed25519_key.pub \
           /etc/ssh/ssh_host_ecdsa_key.pub \
           /etc/ssh/ssh_host_rsa_key.pub; do
    if [[ -r "$key" ]]; then
        ssh-keygen -lf "$key"
    fi
done

log "setup complete"
log "incoming directory: $INCOMING"
log "archive directory:  $ARCHIVE"
log "authorized_keys:    $AUTH_FILE"
log "restricted command: $RRSYNC_BIN -wo $INCOMING"
log ""
log "Next steps:"
log "1. Verify the host-key fingerprint with the RELIC VPS owner."
log "2. On the VPS, add the verified key to known_hosts and test:"
log "   rsync -a -e 'ssh -i /root/.ssh/relic_backup_ed25519 -p 22 -o BatchMode=yes -o StrictHostKeyChecking=yes' /etc/hostname '${BACKUP_USER}@THIS_HOST:.'"
log "3. Schedule the installed retention script on this host (systemd timer or cron)."
log "4. Keep the age private key offline; it must not be stored on this host."
