#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
REPORT_DIR="${LEONA_V04_PUBLIC_ARCHIVE_OUT:-/tmp/leona-v0.4-public-archive-$(date +%Y%m%d-%H%M%S)}"
STAGING_DIR="${REPORT_DIR}/staging/leona-android-public"
ARCHIVE_PATH="${REPORT_DIR}/leona-android-public.tar.gz"
SUMMARY_PATH="${REPORT_DIR}/summary.md"

mkdir -p "${STAGING_DIR}"

copy_file() {
  local src="$1"
  local dst="${STAGING_DIR}/${src}"
  if [[ -f "${REPO_DIR}/${src}" ]]; then
    mkdir -p "$(dirname "${dst}")"
    cp "${REPO_DIR}/${src}" "${dst}"
  fi
}

is_allowed_android_file() {
  local path="$1"
  case "${path}" in
    */.DS_Store|*/local.properties|*/build/*|*/.gradle/*|*/.idea/*|*/DerivedData/*|*/__pycache__/*)
      return 1
      ;;
    leona-sdk-android/private/README.md)
      return 0
      ;;
    leona-sdk-android/private/*|leona-sdk-android/sdk-private-core/*|leona-sdk-android/server/*)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

cd "${REPO_DIR}"

copy_file "README.md"
copy_file "LICENSE"
copy_file ".github/workflows/android.yml"
copy_file ".github/PULL_REQUEST_TEMPLATE.md"
copy_file ".github/ISSUE_TEMPLATE/bug_report.md"
copy_file ".github/ISSUE_TEMPLATE/feature_request.md"
copy_file "docs/README.md"
copy_file "docs/open-source-policy.md"
copy_file "docs/open-vs-private-final-matrix.md"

while IFS= read -r path; do
  if is_allowed_android_file "${path}"; then
    copy_file "${path}"
  fi
done < <(find leona-sdk-android -type f | LC_ALL=C sort)

if find "${STAGING_DIR}" -name '.DS_Store' -o -name 'local.properties' -o -path '*/build/*' -o -path '*/.gradle/*' | grep -q .; then
  echo "[archive] forbidden generated/local files copied into archive staging" >&2
  exit 1
fi

if find "${STAGING_DIR}/leona-sdk-android/private" -type f ! -name 'README.md' 2>/dev/null | grep -q .; then
  echo "[archive] private Android files other than placeholder README copied into archive staging" >&2
  exit 1
fi

FORBIDDEN_PATTERN='/home/leona|111\.170|tenant SecretKey=.*|SecretKey=.*|BEGIN (RSA |OPENSSH |PGP )?PRIVATE KEY|full BoxId:|raw Android ID:|raw device id:|raw install id:'
MATCHES="$(
  rg -n "${FORBIDDEN_PATTERN}" "${STAGING_DIR}" \
    --glob '!**/scripts/verify-v0.*-release-readiness.sh' \
    --glob '!**/scripts/verify-v0.4-public-archive.sh' \
    --glob '!**/scripts/verify-v0.4-public-archive-consumer.sh' \
    2>/dev/null || true
)"
if [[ -n "${MATCHES}" ]]; then
  echo "[archive] forbidden public-boundary match found:" >&2
  echo "${MATCHES}" >&2
  exit 1
fi

FILE_COUNT="$(find "${STAGING_DIR}" -type f | wc -l | tr -d ' ')"
MANIFEST_PATH="${REPORT_DIR}/manifest.txt"
(
  cd "${STAGING_DIR}"
  find . -type f | sed 's#^\./##' | LC_ALL=C sort
) > "${MANIFEST_PATH}"

MANIFEST_SHA="$(shasum -a 256 "${MANIFEST_PATH}" | awk '{print $1}')"
tar -czf "${ARCHIVE_PATH}" -C "${REPORT_DIR}/staging" "leona-android-public"
ARCHIVE_SHA="$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')"

{
  echo "# Leona v0.4 Android Public Archive Dry Run"
  echo
  echo "- status: pass"
  echo "- archive path: \`${ARCHIVE_PATH}\`"
  echo "- archive sha256: \`${ARCHIVE_SHA}\`"
  echo "- manifest path: \`${MANIFEST_PATH}\`"
  echo "- manifest sha256: \`${MANIFEST_SHA}\`"
  echo "- file count: ${FILE_COUNT}"
  echo "- secret values printed: no"
  echo "- includes iOS/Web/server/homepage implementation: no"
  echo
  echo "## Included Roots"
  echo "- root public README/LICENSE and Android CI workflow"
  echo "- public docs index and public/private boundary docs"
  echo "- leona-sdk-android public SDK, sample, scripts, docs, and wrappers"
  echo "- leona-sdk-android/private/README.md placeholder only"
} > "${SUMMARY_PATH}"

echo "[archive] summary: ${SUMMARY_PATH}"
