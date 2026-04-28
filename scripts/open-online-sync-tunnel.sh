#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SYNC_ENV_FILE:=$ROOT_DIR/.env.local-sync}"

[[ -f "$SYNC_ENV_FILE" ]] || {
  cat >&2 <<EOF
sync env file not found: $SYNC_ENV_FILE

Create it first:
  cp $ROOT_DIR/.env.local-sync.example $ROOT_DIR/.env.local-sync
EOF
  exit 1
}

set -a
# shellcheck disable=SC1090
source "$SYNC_ENV_FILE"
set +a

: "${SSH_SYNC_HOST:=}"
: "${SSH_SYNC_USER:=}"
: "${SSH_SYNC_PORT:=}"
: "${LOCAL_TUNNEL_PG_PORT:=15432}"
: "${LOCAL_TUNNEL_REDIS_PORT:=16379}"
: "${REMOTE_TUNNEL_PG_HOST:=127.0.0.1}"
: "${REMOTE_TUNNEL_PG_PORT:=5432}"
: "${REMOTE_TUNNEL_REDIS_HOST:=127.0.0.1}"
: "${REMOTE_TUNNEL_REDIS_PORT:=6379}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

[[ -n "$SSH_SYNC_HOST" ]] || {
  echo "SSH_SYNC_HOST is required in $SYNC_ENV_FILE" >&2
  exit 1
}

SSH_TARGET="$SSH_SYNC_HOST"
if [[ -n "$SSH_SYNC_USER" ]]; then
  SSH_TARGET="$SSH_SYNC_USER@$SSH_TARGET"
fi

SSH_ARGS=()
if [[ -n "$SSH_SYNC_PORT" ]]; then
  SSH_ARGS+=(-p "$SSH_SYNC_PORT")
fi

FORWARDS=()
if [[ -n "${REMOTE_PGHOST:-}" || -n "${REMOTE_PGDATABASE:-}" ]]; then
  FORWARDS+=(-L "${LOCAL_TUNNEL_PG_PORT}:${REMOTE_TUNNEL_PG_HOST}:${REMOTE_TUNNEL_PG_PORT}")
fi
if [[ -n "${REMOTE_REDIS_HOST:-}" ]]; then
  FORWARDS+=(-L "${LOCAL_TUNNEL_REDIS_PORT}:${REMOTE_TUNNEL_REDIS_HOST}:${REMOTE_TUNNEL_REDIS_PORT}")
fi

if [[ "${#FORWARDS[@]}" -eq 0 ]]; then
  echo "No remote postgres/redis sync target configured; nothing to tunnel." >&2
  exit 1
fi

need_cmd ssh

echo "[online-sync-tunnel] target: $SSH_TARGET"
echo "[online-sync-tunnel] forwards:"
for ((i=0; i<${#FORWARDS[@]}; i+=2)); do
  echo "  ${FORWARDS[i+1]}"
done
echo
echo "Keep this session open while running preflight/dry-run/apply."
echo "Suggested local overrides after tunnel opens:"
if [[ -n "${REMOTE_PGHOST:-}" || -n "${REMOTE_PGDATABASE:-}" ]]; then
  echo "  REMOTE_PGHOST=127.0.0.1"
  echo "  REMOTE_PGPORT=${LOCAL_TUNNEL_PG_PORT}"
fi
if [[ -n "${REMOTE_REDIS_HOST:-}" ]]; then
  echo "  REMOTE_REDIS_HOST=127.0.0.1"
  echo "  REMOTE_REDIS_PORT=${LOCAL_TUNNEL_REDIS_PORT}"
fi
echo

exec ssh -N ${SSH_ARGS:+${SSH_ARGS[@]}} "${FORWARDS[@]}" "$SSH_TARGET"
