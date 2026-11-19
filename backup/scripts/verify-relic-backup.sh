#!/usr/bin/env bash
#
# Verify a RELIC backup run without touching live data.
#
# This is a small, explicit wrapper around restore-relic.sh --scratch. It
# restores the database into a unique scratch database, runs the database
# verification, and drops the scratch database.
#
# Usage:
#   verify-relic-backup.sh --run-dir DIR --age-identity FILE
#
# The run directory can be a local staging run, a downloaded archive directory,
# or a mounted copy from the backup host.

set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

exec "$SCRIPT_DIR/restore-relic.sh" --scratch "$@"
