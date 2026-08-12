#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
WORKFLOW="${REPO_DIR}/.github/workflows/android.yml"
VERSION="${LEONA_SDK_VERSION:-$(grep '^VERSION_NAME=' "${ROOT_DIR}/gradle.properties" | cut -d= -f2-)}"
TARGET_RELEASE_VERSION="${LEONA_TARGET_RELEASE_VERSION:-${VERSION}}"
REPORT_DIR="${LEONA_V04_PUBLISH_WORKFLOW_OUT:-/tmp/leona-v0.4-publish-workflow-$(date +%Y%m%d-%H%M%S)}"
SUMMARY_PATH="${REPORT_DIR}/summary.md"

STATUS=0
PASS_COUNT=0
FAILURES=()
WARNINGS=()
BLOCKERS=()

mkdir -p "${REPORT_DIR}"

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  printf '[pass] %s\n' "$1"
}

fail() {
  STATUS=1
  FAILURES+=("$1")
  printf '[fail] %s\n' "$1" >&2
}

warn() {
  WARNINGS+=("$1")
  printf '[warn] %s\n' "$1" >&2
}

blocker() {
  BLOCKERS+=("$1")
  printf '[blocked] %s\n' "$1"
}

contains() {
  local file="$1"
  local pattern="$2"
  [[ -f "${file}" ]] && grep -Eq "${pattern}" "${file}"
}

require_contains() {
  local label="$1"
  local file="$2"
  local pattern="$3"
  if contains "${file}" "${pattern}"; then
    pass "${label}"
  else
    fail "${label}: missing pattern ${pattern} in ${file}"
  fi
}

cd "${REPO_DIR}"

echo "[publish-workflow] Android tag publish workflow dry-run"
echo "[publish-workflow] SDK coordinate version: ${VERSION}"
echo "[publish-workflow] target release version: ${TARGET_RELEASE_VERSION}"
echo "[publish-workflow] report dir: ${REPORT_DIR}"
echo "[publish-workflow] secret values are never printed by this script"

if [[ ! -f "${WORKFLOW}" ]]; then
  fail "Android workflow is missing: ${WORKFLOW}"
else
  pass "Android workflow exists"
fi

require_contains "workflow runs on v* tags" \
  "${WORKFLOW}" \
  'tags:[[:space:]]*\["v\*"\]'
require_contains "workflow can write release contents" \
  "${WORKFLOW}" \
  'contents:[[:space:]]*write'
require_contains "workflow can write packages" \
  "${WORKFLOW}" \
  'packages:[[:space:]]*write'

require_contains "publish-release job is present" \
  "${WORKFLOW}" \
  '^  publish-release:'
require_contains "publish-release is tag-gated" \
  "${WORKFLOW}" \
  "if:[[:space:]]*startsWith\\(github\\.ref, 'refs/tags/v'\\)"
require_contains "publish-release waits for local verification jobs" \
  "${WORKFLOW}" \
  'needs:[[:space:]]*\[lint-and-test, assemble, native-sanity\]'
require_contains "publish-release builds release AAR" \
  "${WORKFLOW}" \
  ':sdk:assembleRelease'
require_contains "publish-release prepares versioned AAR asset" \
  "${WORKFLOW}" \
  'leona-sdk-android-\$\{VERSION\}\.aar'
require_contains "publish-release prepares sha256 asset" \
  "${WORKFLOW}" \
  'leona-sdk-android-\$\{VERSION\}\.aar\.sha256'
require_contains "publish-release uploads AAR assets to GitHub Release" \
  "${WORKFLOW}" \
  'softprops/action-gh-release@[0-9a-f]{40}[[:space:]]*#[[:space:]]*v2'
require_contains "publish-release includes aar glob" \
  "${WORKFLOW}" \
  'leona-sdk-android/build/release-assets/\*\.aar'
require_contains "publish-release includes sha256 glob" \
  "${WORKFLOW}" \
  'leona-sdk-android/build/release-assets/\*\.sha256'
require_contains "publish-release keeps prerelease flag for alpha/beta/rc tags" \
  "${WORKFLOW}" \
  "contains\\(github\\.ref, '-alpha'\\).*contains\\(github\\.ref, '-beta'\\).*contains\\(github\\.ref, '-rc'\\)"

require_contains "publish-maven job is present" \
  "${WORKFLOW}" \
  '^  publish-maven:'
require_contains "publish-maven is tag-gated" \
  "${WORKFLOW}" \
  "publish-maven:|Publish Maven package"
require_contains "publish-maven uses repository-scoped token" \
  "${WORKFLOW}" \
  'GITHUB_TOKEN:[[:space:]]*\$\{\{ secrets\.GITHUB_TOKEN \}\}'
require_contains "publish-maven publishes release publication to GitHub Packages" \
  "${WORKFLOW}" \
  'publishReleasePublicationToGitHubPackagesRepository'

EXPECTED_AAR="leona-sdk-android-${TARGET_RELEASE_VERSION}.aar"
EXPECTED_SHA="${EXPECTED_AAR}.sha256"
{
  echo "${EXPECTED_AAR}"
  echo "${EXPECTED_SHA}"
} > "${REPORT_DIR}/expected-release-assets.txt"

if contains "${WORKFLOW}" 'CENTRAL_PORTAL_|SIGNING_KEY|SIGNING_PASSWORD|LEONA_SECRET|TENANT_SECRET|PLAY_INTEGRITY|APP_ATTEST|DEVICECHECK'; then
  fail "public Android workflow references non-public release/provider secrets"
else
  pass "public Android workflow does not reference Central/provider/customer secrets"
fi

warn "This is a workflow structure dry-run only; final tag publish still requires GitHub Actions execution on the pushed tag."
if [[ "${VERSION}" != "${TARGET_RELEASE_VERSION}" ]]; then
  blocker "GitHub Packages Maven coordinate is still ${VERSION}; bump VERSION_NAME to ${TARGET_RELEASE_VERSION} before cutting a real v${TARGET_RELEASE_VERSION} tag."
fi
blocker "GitHub Release AAR and sha256 are produced only after the v${TARGET_RELEASE_VERSION} tag workflow completes."
blocker "GitHub Packages remote consumer smoke must be rerun after the tag publishes."
blocker "Maven Central publish remains external until namespace, token, and signing material are configured outside the public repository."

{
  echo "# Leona v0.4 Android Publish Workflow Dry Run"
  echo
  echo "- status: $([[ "${STATUS}" == "0" ]] && echo "local-pass-with-external-blockers" || echo "failed")"
  echo "- target release version: \`${TARGET_RELEASE_VERSION}\`"
  echo "- SDK coordinate version: \`${VERSION}\`"
  echo "- expected AAR asset: \`${EXPECTED_AAR}\`"
  echo "- expected checksum asset: \`${EXPECTED_SHA}\`"
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
  echo "## Warnings"
  if (( ${#WARNINGS[@]} == 0 )); then
    echo "- none"
  else
    printf -- '- %s\n' "${WARNINGS[@]}"
  fi
  echo
  echo "## External Blockers"
  if (( ${#BLOCKERS[@]} == 0 )); then
    echo "- none"
  else
    printf -- '- %s\n' "${BLOCKERS[@]}"
  fi
} > "${SUMMARY_PATH}"

echo "[publish-workflow] summary: ${SUMMARY_PATH}"
exit "${STATUS}"
