#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SYNC_COMPONENTS:=all}"          # postgres|redis|all
: "${DRY_RUN:=1}"                    # 1=safe preview, 0=execute
: "${REMOTE_NAME:=online}"
: "${BACKUP_DIR:=/tmp/leona-online-sync-$(date +%Y%m%d-%H%M%S)}"

# Local Leona defaults from docker-compose
: "${LOCAL_PG_CONTAINER:=leona-postgres}"
: "${LOCAL_PGHOST:=127.0.0.1}"
: "${LOCAL_PGPORT:=5432}"
: "${LOCAL_PGDATABASE:=leona}"
: "${LOCAL_PGUSER:=leona}"
: "${LOCAL_PGPASSWORD:=leona}"

: "${LOCAL_REDIS_CONTAINER:=leona-redis}"
: "${LOCAL_REDIS_HOST:=127.0.0.1}"
: "${LOCAL_REDIS_PORT:=6379}"
: "${LOCAL_REDIS_PASSWORD:=}"

# Remote/online connection variables: must be supplied by caller when used
: "${REMOTE_PGHOST:=}"
: "${REMOTE_PGPORT:=5432}"
: "${REMOTE_PGDATABASE:=}"
: "${REMOTE_PGUSER:=}"
: "${REMOTE_PGPASSWORD:=}"

: "${REMOTE_REDIS_HOST:=}"
: "${REMOTE_REDIS_PORT:=6379}"
: "${REMOTE_REDIS_PASSWORD:=}"

POSTGRES_CLIENT_IMAGE="postgres:16-alpine"
REDIS_CLIENT_IMAGE="redis:7-alpine"

LOCAL_PG_BACKUP="$BACKUP_DIR/local-postgres-before-sync.sql"
REMOTE_PG_DUMP="$BACKUP_DIR/${REMOTE_NAME}-postgres.sql"
LOCAL_REDIS_BACKUP="$BACKUP_DIR/local-redis-before-sync.rdb"
REMOTE_REDIS_DUMP="$BACKUP_DIR/${REMOTE_NAME}-redis.rdb"

log() {
  printf '[sync-online-data] %s\n' "$*"
}

die() {
  printf '[sync-online-data] ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

maybe_run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '[dry-run] %s\n' "$*"
  else
    eval "$@"
  fi
}

component_enabled() {
  case "$SYNC_COMPONENTS" in
    all) return 0 ;;
    postgres) [[ "$1" == "postgres" ]] ;;
    redis) [[ "$1" == "redis" ]] ;;
    *) die "unsupported SYNC_COMPONENTS=$SYNC_COMPONENTS (expected postgres|redis|all)" ;;
  esac
}

require_remote_postgres() {
  [[ -n "$REMOTE_PGHOST" ]] || die "REMOTE_PGHOST is required for postgres sync"
  [[ -n "$REMOTE_PGDATABASE" ]] || die "REMOTE_PGDATABASE is required for postgres sync"
  [[ -n "$REMOTE_PGUSER" ]] || die "REMOTE_PGUSER is required for postgres sync"
  [[ -n "$REMOTE_PGPASSWORD" ]] || die "REMOTE_PGPASSWORD is required for postgres sync"
}

require_remote_redis() {
  [[ -n "$REMOTE_REDIS_HOST" ]] || die "REMOTE_REDIS_HOST is required for redis sync"
}

wait_for_local_redis() {
  local pass_args=""
  if [[ -n "$LOCAL_REDIS_PASSWORD" ]]; then
    pass_args="-a '$LOCAL_REDIS_PASSWORD'"
  fi
  for _ in $(seq 1 30); do
    if eval "redis-cli -h '$LOCAL_REDIS_HOST' -p '$LOCAL_REDIS_PORT' $pass_args ping" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "local redis did not become ready after restore"
}

sync_postgres() {
  require_remote_postgres
  mkdir -p "$BACKUP_DIR"

  log "postgres: backing up local database to $LOCAL_PG_BACKUP"
  maybe_run "docker exec '$LOCAL_PG_CONTAINER' sh -lc \"PGPASSWORD='$LOCAL_PGPASSWORD' pg_dump -U '$LOCAL_PGUSER' -d '$LOCAL_PGDATABASE' --clean --if-exists --no-owner --no-privileges\" > '$LOCAL_PG_BACKUP'"

  log "postgres: dumping $REMOTE_NAME database from $REMOTE_PGHOST:$REMOTE_PGPORT/$REMOTE_PGDATABASE to $REMOTE_PG_DUMP"
  maybe_run "docker run --rm -e PGPASSWORD='$REMOTE_PGPASSWORD' '$POSTGRES_CLIENT_IMAGE' sh -lc \"pg_dump -h '$REMOTE_PGHOST' -p '$REMOTE_PGPORT' -U '$REMOTE_PGUSER' -d '$REMOTE_PGDATABASE' --clean --if-exists --no-owner --no-privileges\" > '$REMOTE_PG_DUMP'"

  log "postgres: restoring remote dump into local $LOCAL_PGDATABASE"
  maybe_run "cat '$REMOTE_PG_DUMP' | docker exec -i '$LOCAL_PG_CONTAINER' sh -lc \"PGPASSWORD='$LOCAL_PGPASSWORD' psql -U '$LOCAL_PGUSER' -d '$LOCAL_PGDATABASE'\""
}

sync_redis() {
  require_remote_redis
  mkdir -p "$BACKUP_DIR"

  local local_pass_args=""
  local remote_pass_args=""
  [[ -n "$LOCAL_REDIS_PASSWORD" ]] && local_pass_args="-a '$LOCAL_REDIS_PASSWORD'"
  [[ -n "$REMOTE_REDIS_PASSWORD" ]] && remote_pass_args="-a '$REMOTE_REDIS_PASSWORD'"

  log "redis: backing up local redis to $LOCAL_REDIS_BACKUP"
  maybe_run "redis-cli -h '$LOCAL_REDIS_HOST' -p '$LOCAL_REDIS_PORT' $local_pass_args --rdb '$LOCAL_REDIS_BACKUP'"

  log "redis: dumping $REMOTE_NAME redis from $REMOTE_REDIS_HOST:$REMOTE_REDIS_PORT to $REMOTE_REDIS_DUMP"
  maybe_run "docker run --rm '$REDIS_CLIENT_IMAGE' sh -lc \"redis-cli -h '$REMOTE_REDIS_HOST' -p '$REMOTE_REDIS_PORT' $remote_pass_args --rdb /tmp/remote.rdb >/dev/null && cat /tmp/remote.rdb\" > '$REMOTE_REDIS_DUMP'"

  log "redis: replacing local dump.rdb in container $LOCAL_REDIS_CONTAINER"
  maybe_run "docker stop '$LOCAL_REDIS_CONTAINER'"
  maybe_run "docker cp '$REMOTE_REDIS_DUMP' '$LOCAL_REDIS_CONTAINER:/data/dump.rdb'"
  maybe_run "docker start '$LOCAL_REDIS_CONTAINER'"

  if [[ "$DRY_RUN" == "0" ]]; then
    wait_for_local_redis
  fi
}

summary() {
  cat <<EOF
sync target: remote($REMOTE_NAME) -> local
components : $SYNC_COMPONENTS
dry-run    : $DRY_RUN
backup dir : $BACKUP_DIR

local postgres:
  container=$LOCAL_PG_CONTAINER
  db=$LOCAL_PGDATABASE
  addr=$LOCAL_PGHOST:$LOCAL_PGPORT

local redis:
  container=$LOCAL_REDIS_CONTAINER
  addr=$LOCAL_REDIS_HOST:$LOCAL_REDIS_PORT

remote postgres:
  host=${REMOTE_PGHOST:-<unset>}
  port=$REMOTE_PGPORT
  db=${REMOTE_PGDATABASE:-<unset>}
  user=${REMOTE_PGUSER:-<unset>}

remote redis:
  host=${REMOTE_REDIS_HOST:-<unset>}
  port=$REMOTE_REDIS_PORT
EOF
}

main() {
  need_cmd docker
  need_cmd redis-cli

  mkdir -p "$BACKUP_DIR"
  log "$(summary)"

  component_enabled postgres && sync_postgres
  component_enabled redis && sync_redis

  log "done"
  if [[ "$DRY_RUN" == "1" ]]; then
    log "dry-run only; no local data was modified"
  else
    log "local backup artifacts saved under $BACKUP_DIR"
  fi
}

main "$@"
