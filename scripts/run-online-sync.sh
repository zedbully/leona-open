#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SYNC_ENV_FILE:=$ROOT_DIR/.env.local-sync}"
: "${SYNC_MODE:=status}"   # status|preflight|dry-run|apply

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

: "${SYNC_COMPONENTS:=all}"

need_var() {
  local name="$1"
  local value="${!name:-}"
  if [[ -z "$value" ]]; then
    echo "Missing required variable in $SYNC_ENV_FILE: $name" >&2
    exit 1
  fi
}

validate_remote_config() {
  case "$SYNC_COMPONENTS" in
    postgres)
      need_var REMOTE_PGHOST
      need_var REMOTE_PGDATABASE
      need_var REMOTE_PGUSER
      need_var REMOTE_PGPASSWORD
      ;;
    redis)
      need_var REMOTE_REDIS_HOST
      ;;
    all)
      need_var REMOTE_PGHOST
      need_var REMOTE_PGDATABASE
      need_var REMOTE_PGUSER
      need_var REMOTE_PGPASSWORD
      need_var REMOTE_REDIS_HOST
      ;;
    *)
      echo "Unsupported SYNC_COMPONENTS=$SYNC_COMPONENTS (expected postgres|redis|all)" >&2
      exit 1
      ;;
  esac
}

print_status() {
  local keys=(
    SYNC_COMPONENTS
    REMOTE_NAME
    REMOTE_PGHOST
    REMOTE_PGPORT
    REMOTE_PGDATABASE
    REMOTE_PGUSER
    REMOTE_PGPASSWORD
    REMOTE_REDIS_HOST
    REMOTE_REDIS_PORT
    REMOTE_REDIS_PASSWORD
  )

  echo "sync env file: $SYNC_ENV_FILE"
  echo "sync mode    : $SYNC_MODE"
  echo

  for key in "${keys[@]}"; do
    local value="${!key:-}"
    local shown="$value"
    if [[ "$key" == *PASSWORD ]]; then
      if [[ -n "$value" ]]; then
        shown="<set>"
      else
        shown="<empty>"
      fi
    elif [[ -z "$value" ]]; then
      shown="<empty>"
    fi
    printf '%-22s %s\n' "$key" "$shown"
  done

  echo
  echo "required now:"
  case "$SYNC_COMPONENTS" in
    postgres)
      echo "  REMOTE_PGHOST REMOTE_PGDATABASE REMOTE_PGUSER REMOTE_PGPASSWORD"
      ;;
    redis)
      echo "  REMOTE_REDIS_HOST"
      ;;
    all)
      echo "  REMOTE_PGHOST REMOTE_PGDATABASE REMOTE_PGUSER REMOTE_PGPASSWORD REMOTE_REDIS_HOST"
      ;;
    *)
      echo "  unsupported SYNC_COMPONENTS=$SYNC_COMPONENTS"
      ;;
  esac
}

case "$SYNC_MODE" in
  status)
    print_status
    ;;
  preflight)
    exec "$ROOT_DIR/scripts/sync-online-data-preflight.sh"
    ;;
  dry-run)
    validate_remote_config
    export DRY_RUN=1
    exec "$ROOT_DIR/scripts/sync-online-data-to-local.sh"
    ;;
  apply)
    validate_remote_config
    export DRY_RUN=0
    exec "$ROOT_DIR/scripts/sync-online-data-to-local.sh"
    ;;
  *)
    echo "Unsupported SYNC_MODE=$SYNC_MODE (expected status|preflight|dry-run|apply)" >&2
    exit 1
    ;;
esac
