#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SYNC_ENV_FILE:=$ROOT_DIR/.env.local-sync}"
: "${SYNC_MODE:=preflight}"   # preflight|dry-run|apply

[[ -f "$SYNC_ENV_FILE" ]] || {
  cat >&2 <<EOF
sync env file not found: $SYNC_ENV_FILE

Create it first:
  cp $ROOT_DIR/.env.local-sync.example $ROOT_DIR/.env.local-sync

Then fill remote credentials and rerun.
EOF
  exit 1
}

set -a
# shellcheck disable=SC1090
source "$SYNC_ENV_FILE"
set +a

case "$SYNC_MODE" in
  preflight)
    exec "$ROOT_DIR/scripts/sync-online-data-preflight.sh"
    ;;
  dry-run)
    export DRY_RUN=1
    exec "$ROOT_DIR/scripts/sync-online-data-to-local.sh"
    ;;
  apply)
    export DRY_RUN=0
    exec "$ROOT_DIR/scripts/sync-online-data-to-local.sh"
    ;;
  *)
    echo "Unsupported SYNC_MODE=$SYNC_MODE (expected preflight|dry-run|apply)" >&2
    exit 1
    ;;
esac
