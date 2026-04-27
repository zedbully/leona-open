#!/usr/bin/env bash
set -euo pipefail

: "${LOCAL_PG_CONTAINER:=leona-postgres}"
: "${LOCAL_PGHOST:=127.0.0.1}"
: "${LOCAL_PGPORT:=5432}"
: "${LOCAL_PGDATABASE:=leona}"
: "${LOCAL_PGUSER:=leona}"

: "${LOCAL_REDIS_CONTAINER:=leona-redis}"
: "${LOCAL_REDIS_HOST:=127.0.0.1}"
: "${LOCAL_REDIS_PORT:=6379}"

: "${REMOTE_PGHOST:=}"
: "${REMOTE_PGPORT:=5432}"
: "${REMOTE_PGDATABASE:=}"
: "${REMOTE_PGUSER:=}"

: "${REMOTE_REDIS_HOST:=}"
: "${REMOTE_REDIS_PORT:=6379}"

log() {
  printf '[sync-preflight] %s\n' "$*"
}

die() {
  printf '[sync-preflight] ERROR: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

check_container() {
  local name="$1"
  docker inspect "$name" >/dev/null 2>&1 || die "docker container not found: $name"
  local running
  running="$(docker inspect -f '{{.State.Running}}' "$name")"
  [[ "$running" == "true" ]] || die "docker container not running: $name"
}

tcp_check() {
  local host="$1"
  local port="$2"
  local label="$3"
  if command -v nc >/dev/null 2>&1; then
    if nc -z -w 3 "$host" "$port" >/dev/null 2>&1; then
      log "$label tcp ok: $host:$port"
    else
      log "$label tcp failed: $host:$port"
    fi
  else
    log "nc not found; skip tcp check for $label"
  fi
}

local_postgres_summary() {
  docker exec "$LOCAL_PG_CONTAINER" sh -lc \
    "psql -U '$LOCAL_PGUSER' -d '$LOCAL_PGDATABASE' -Atc \"\
select 'tenants='||count(*) from public.tenants union all \
select 'api_keys='||count(*) from public.api_keys union all \
select 'boxes='||count(*) from public.boxes union all \
select 'databasechangelog='||count(*) from public.databasechangelog union all \
select 'databasechangeloglock='||count(*) from public.databasechangeloglock;\""
}

local_redis_summary() {
  redis-cli -h "$LOCAL_REDIS_HOST" -p "$LOCAL_REDIS_PORT" INFO keyspace | sed -n '/^db/p'
}

main() {
  need_cmd docker
  need_cmd redis-cli

  check_container "$LOCAL_PG_CONTAINER"
  check_container "$LOCAL_REDIS_CONTAINER"

  log "local postgres: $LOCAL_PGHOST:$LOCAL_PGPORT/$LOCAL_PGDATABASE"
  log "local redis   : $LOCAL_REDIS_HOST:$LOCAL_REDIS_PORT"

  tcp_check "$LOCAL_PGHOST" "$LOCAL_PGPORT" "local postgres"
  tcp_check "$LOCAL_REDIS_HOST" "$LOCAL_REDIS_PORT" "local redis"

  log "local postgres counts:"
  local_postgres_summary | sed 's/^/  /'

  log "local redis keyspace:"
  local_redis_summary | sed 's/^/  /'

  if [[ -n "$REMOTE_PGHOST" ]]; then
    log "remote postgres configured: $REMOTE_PGHOST:$REMOTE_PGPORT/${REMOTE_PGDATABASE:-<unset>} user=${REMOTE_PGUSER:-<unset>}"
    tcp_check "$REMOTE_PGHOST" "$REMOTE_PGPORT" "remote postgres"
  else
    log "remote postgres not configured"
  fi

  if [[ -n "$REMOTE_REDIS_HOST" ]]; then
    log "remote redis configured: $REMOTE_REDIS_HOST:$REMOTE_REDIS_PORT"
    tcp_check "$REMOTE_REDIS_HOST" "$REMOTE_REDIS_PORT" "remote redis"
  else
    log "remote redis not configured"
  fi
}

main "$@"
