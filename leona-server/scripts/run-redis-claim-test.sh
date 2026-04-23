#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTAINER_NAME="${LEONA_TEST_REDIS_CONTAINER_NAME:-leona-test-redis}"
HOST_PORT="${LEONA_TEST_REDIS_PORT:-16379}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

cleanup

docker run -d --rm \
  --name "${CONTAINER_NAME}" \
  -p "${HOST_PORT}:6379" \
  redis:7-alpine >/dev/null

LEONA_TEST_REDIS_HOST=127.0.0.1 \
LEONA_TEST_REDIS_PORT="${HOST_PORT}" \
"${PROJECT_ROOT}/scripts/gradlew-java21.sh" \
  :query-service:test \
  --tests io.leonasec.server.query.infra.RedisBoxIdClaimIntegrationTest \
  --rerun-tasks \
  --no-daemon
