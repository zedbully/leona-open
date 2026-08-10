#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
REPORT_DIR="${LEONA_V04_PUBLIC_ARCHIVE_CONSUMER_OUT:-/tmp/leona-v0.4-public-archive-consumer-$(date +%Y%m%d-%H%M%S)}"
ARCHIVE_REPORT_DIR="${REPORT_DIR}/archive-dry-run"
ARCHIVE_PATH="${LEONA_V04_PUBLIC_ARCHIVE_PATH:-}"
EXTRACT_DIR="${REPORT_DIR}/extract"
PUBLIC_ROOT="${EXTRACT_DIR}/leona-android-public"
SUMMARY_PATH="${REPORT_DIR}/summary.md"

mkdir -p "${REPORT_DIR}" "${EXTRACT_DIR}"

if [[ -z "${ARCHIVE_PATH}" ]]; then
  LEONA_V04_PUBLIC_ARCHIVE_OUT="${ARCHIVE_REPORT_DIR}" "${ROOT_DIR}/scripts/verify-v0.4-public-archive.sh" \
    > "${REPORT_DIR}/archive-dry-run.txt" 2>&1
  ARCHIVE_PATH="${ARCHIVE_REPORT_DIR}/leona-android-public.tar.gz"
fi

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  echo "[archive-consumer] archive does not exist: ${ARCHIVE_PATH}" >&2
  exit 1
fi

tar -xzf "${ARCHIVE_PATH}" -C "${EXTRACT_DIR}"

required_file() {
  local rel="$1"
  if [[ ! -f "${PUBLIC_ROOT}/${rel}" ]]; then
    echo "[archive-consumer] missing required file: ${rel}" >&2
    exit 1
  fi
}

forbidden_path() {
  local label="$1"
  shift
  local matches
  matches="$(find "${PUBLIC_ROOT}" "$@" 2>/dev/null | sed "s#^${PUBLIC_ROOT}/##" | LC_ALL=C sort || true)"
  if [[ -n "${matches}" ]]; then
    echo "[archive-consumer] forbidden ${label} found:" >&2
    echo "${matches}" >&2
    exit 1
  fi
}

if [[ ! -d "${PUBLIC_ROOT}" ]]; then
  echo "[archive-consumer] archive missing top-level leona-android-public directory" >&2
  exit 1
fi

required_file "README.md"
required_file "LICENSE"
required_file ".github/workflows/android.yml"
required_file ".github/workflows/android-cloud-runtime.yml"
required_file "docs/README.md"
required_file "docs/open-source-policy.md"
required_file "docs/open-vs-private-final-matrix.md"
required_file "leona-sdk-android/README.md"
required_file "leona-sdk-android/CHANGELOG.md"
required_file "leona-sdk-android/settings.gradle.kts"
required_file "leona-sdk-android/build.gradle.kts"
required_file "leona-sdk-android/sdk/build.gradle.kts"
required_file "leona-sdk-android/sample-app/build.gradle.kts"
required_file "leona-sdk-android/docs/v0.4-release-checklist.md"
required_file "leona-sdk-android/compatibility/android-6-16-contract.json"
required_file "leona-sdk-android/scripts/build-android-6-16-runtime-manifest.py"
required_file "leona-sdk-android/scripts/verify-android-6-16-compatibility.py"
required_file "leona-sdk-android/scripts/tests/test_build_android_6_16_runtime_manifest.py"
required_file "leona-sdk-android/scripts/tests/test_import_android_matrix_external_sample.py"
required_file "leona-sdk-android/scripts/tests/test_github_hosted_runtime_workflow.py"
required_file "leona-sdk-android/scripts/tests/test_run_public_hosted_reporting_fixture.py"
required_file "leona-sdk-android/scripts/tests/test_run_cloud_device_collection.py"
required_file "leona-sdk-android/scripts/tests/test_parse_cloud_test_sense_result.py"
required_file "leona-sdk-android/scripts/tests/test_verify_github_hosted_runtime_evidence.py"
required_file "leona-sdk-android/scripts/tests/test_verify_v04_android_matrix_readiness.py"
required_file "leona-sdk-android/scripts/tests/test_verify_v04_version_markers.py"
required_file "leona-sdk-android/scripts/tests/test_verify_android_6_16_compatibility.py"
required_file "leona-sdk-android/scripts/run-github-hosted-runtime-matrix.sh"
required_file "leona-sdk-android/scripts/run-public-hosted-reporting-fixture.py"
required_file "leona-sdk-android/scripts/parse-cloud-test-sense-result.py"
required_file "leona-sdk-android/scripts/verify-github-hosted-runtime-evidence.py"
required_file "leona-sdk-android/scripts/verify-v0.4-domestic-private-distribution.py"
required_file "leona-sdk-android/scripts/verify-v0.4-release-readiness.sh"
required_file "leona-sdk-android/scripts/verify-v0.4-public-archive.sh"
required_file "leona-sdk-android/scripts/tests/test_verify_v04_domestic_private_distribution.py"
required_file "leona-sdk-android/wrappers/README.md"
required_file "leona-sdk-android/private/README.md"

forbidden_path "sensitive roots" \
  \( -path "${PUBLIC_ROOT}/leona-server" -o \
     -path "${PUBLIC_ROOT}/leona-homepage" -o \
     -path "${PUBLIC_ROOT}/leona-sdk-ios" -o \
     -path "${PUBLIC_ROOT}/leona-web-sdk" -o \
     -path "${PUBLIC_ROOT}/wdblogs" \)

forbidden_path "generated or local files" \
  \( -name ".DS_Store" -o \
     -name "local.properties" -o \
     -path "*/build/*" -o \
     -path "*/.gradle/*" -o \
     -path "*/.idea/*" -o \
     -path "*/DerivedData/*" -o \
     -path "*/__pycache__/*" \)

if find "${PUBLIC_ROOT}" -type l | grep -q .; then
  echo "[archive-consumer] archive contains symlinks; release archive must be regular files/directories only" >&2
  exit 1
fi

if find "${PUBLIC_ROOT}/leona-sdk-android/private" -type f ! -name "README.md" 2>/dev/null | grep -q .; then
  echo "[archive-consumer] private Android files other than placeholder README are present" >&2
  exit 1
fi

FORBIDDEN_PATTERN='/home/leona|111\.170|tenant SecretKey=.*|SecretKey=.*|BEGIN (RSA |OPENSSH |PGP )?PRIVATE KEY|full BoxId:|raw Android ID:|raw device id:|raw install id:'
MATCHES="$(
  rg -n "${FORBIDDEN_PATTERN}" "${PUBLIC_ROOT}" \
    --glob '!**/scripts/verify-v0.*-release-readiness.sh' \
    --glob '!**/scripts/verify-v0.4-public-archive.sh' \
    --glob '!**/scripts/verify-v0.4-public-archive-consumer.sh' \
    2>/dev/null || true
)"
if [[ -n "${MATCHES}" ]]; then
  echo "[archive-consumer] forbidden public-boundary match found:" >&2
  echo "${MATCHES}" >&2
  exit 1
fi

while IFS= read -r script; do
  bash -n "${script}"
done < <(find "${PUBLIC_ROOT}/leona-sdk-android/scripts" -type f -name "*.sh" | LC_ALL=C sort)

FILE_COUNT="$(find "${PUBLIC_ROOT}" -type f | wc -l | tr -d ' ')"
ARCHIVE_SHA="$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')"

{
  echo "# Leona v0.4 Android Public Archive Consumer Smoke"
  echo
  echo "- status: pass"
  echo "- archive path: \`${ARCHIVE_PATH}\`"
  echo "- archive sha256: \`${ARCHIVE_SHA}\`"
  echo "- extracted root: \`${PUBLIC_ROOT}\`"
  echo "- file count: ${FILE_COUNT}"
  echo "- secret values printed: no"
  echo "- required public Android files present: yes"
  echo "- shell syntax check for archived scripts: pass"
  echo "- symlinks present: no"
  echo "- includes iOS/Web/server/homepage implementation: no"
} > "${SUMMARY_PATH}"

echo "[archive-consumer] summary: ${SUMMARY_PATH}"
