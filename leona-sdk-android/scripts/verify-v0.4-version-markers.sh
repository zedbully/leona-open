#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_VERSION="${LEONA_TARGET_RELEASE_VERSION:-0.4.0}"
REPORT_DIR="${LEONA_ANDROID_VERSION_MARKERS_OUT:-/tmp/leona-v0.4-version-markers-$(date +%Y%m%d-%H%M%S)}"
SUMMARY_PATH="${REPORT_DIR}/summary.md"
REQUIRE_READY="${LEONA_REQUIRE_ANDROID_VERSION_MARKERS:-0}"
STATUS="local-pass-with-version-blocker"
EXIT_CODE=0
PASS_COUNT=0
FAILURES=()
BLOCKERS=()

mkdir -p "${REPORT_DIR}"

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[pass] %s\n' "$1"
}

fail() {
  FAILURES+=("$1")
  printf '[fail] %s\n' "$1" >&2
}

blocker() {
  BLOCKERS+=("$1")
  printf '[blocked] %s\n' "$1"
}

require_contains() {
  local label="$1"
  local path="$2"
  local pattern="$3"
  local output="${REPORT_DIR}/${label// /-}.txt"
  local result=0
  if command -v rg >/dev/null 2>&1; then
    rg -n "${pattern}" "${ROOT_DIR}/${path}" > "${output}" 2>&1 || result=$?
  else
    grep -En "${pattern}" "${ROOT_DIR}/${path}" > "${output}" 2>&1 || result=$?
  fi
  if [[ ${result} -eq 0 ]]; then
    pass "${label}"
  else
    fail "${label}"
  fi
}

CURRENT_VERSION="$(grep '^VERSION_NAME=' "${ROOT_DIR}/gradle.properties" | cut -d= -f2-)"

echo "[version-markers] target version: ${TARGET_VERSION}"
echo "[version-markers] current VERSION_NAME: ${CURRENT_VERSION}"
echo "[version-markers] report dir: ${REPORT_DIR}"

require_contains "gradle properties has VERSION_NAME" \
  "gradle.properties" \
  "^VERSION_NAME=${CURRENT_VERSION}$"
require_contains "SDK BuildConstants matches VERSION_NAME" \
  "sdk/src/main/kotlin/io/leonasec/leona/BuildConstants.kt" \
  "VERSION_NAME = \"${CURRENT_VERSION}\""
require_contains "sample app versionName matches VERSION_NAME" \
  "sample-app/build.gradle.kts" \
  "versionName = \"${CURRENT_VERSION}\""
require_contains "Maven local consumer defaults to gradle VERSION_NAME" \
  "scripts/verify-maven-local-consumer.sh" \
  "VERSION_NAME="
require_contains "publish workflow dry-run reads gradle VERSION_NAME" \
  "scripts/verify-v0.4-publish-workflow-dry-run.sh" \
  "VERSION_NAME="
require_contains "release candidate manifest reads gradle VERSION_NAME" \
  "scripts/verify-v0.4-release-candidate-manifest.sh" \
  "VERSION_NAME="
require_contains "tag release runbook mentions target version" \
  "docs/v0.4-tag-release-runbook.md" \
  "${TARGET_VERSION}"

if [[ "${CURRENT_VERSION}" == "${TARGET_VERSION}" ]]; then
  STATUS="pass"
  pass "VERSION_NAME already matches target ${TARGET_VERSION}"
else
  blocker "Android SDK coordinate is ${CURRENT_VERSION}; bump VERSION_NAME to ${TARGET_VERSION} before cutting a real v${TARGET_VERSION} tag."
fi

if (( ${#FAILURES[@]} > 0 )); then
  STATUS="failed"
  EXIT_CODE=1
elif [[ "${REQUIRE_READY}" == "1" && "${CURRENT_VERSION}" != "${TARGET_VERSION}" ]]; then
  STATUS="failed"
  EXIT_CODE=1
fi

{
  echo "# Leona v0.4 Android Version Markers"
  echo
  echo "- status: ${STATUS}"
  echo "- target version: \`${TARGET_VERSION}\`"
  echo "- current VERSION_NAME: \`${CURRENT_VERSION}\`"
  echo "- strict mode: \`${REQUIRE_READY}\`"
  echo "- report dir: \`${REPORT_DIR}\`"
  echo "- secret values printed: no"
  echo "- local pass checks: ${PASS_COUNT}"
  echo
  echo "## Failures"
  if (( ${#FAILURES[@]} == 0 )); then
    echo "- none"
  else
    printf -- '- %s\n' "${FAILURES[@]}"
  fi
  echo
  echo "## Blockers"
  if (( ${#BLOCKERS[@]} == 0 )); then
    echo "- none"
  else
    printf -- '- %s\n' "${BLOCKERS[@]}"
  fi
  echo
  echo "## Rule"
  echo "- This gate is read-only. It does not edit versions, stage files, create tags, publish artifacts, start devices, or print secrets."
  echo "- Use \`LEONA_REQUIRE_ANDROID_VERSION_MARKERS=1\` during final tag readiness to require \`VERSION_NAME=${TARGET_VERSION}\`."
} > "${SUMMARY_PATH}"

echo "[version-markers] summary: ${SUMMARY_PATH}"
exit "${EXIT_CODE}"
