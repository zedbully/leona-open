#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_LEVEL="${1:-${LEONA_GITHUB_MATRIX_API_LEVEL:-}}"
PRIVATE_ENV="${LEONA_GITHUB_MATRIX_PRIVATE_ENV:-}"
OUT_ROOT="${LEONA_GITHUB_MATRIX_OUT:-${RUNNER_TEMP:-/tmp}/leona-github-cloud-runtime}"
FIXTURE_PORT="${LEONA_GITHUB_MATRIX_FIXTURE_PORT:-18080}"

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  echo "This runner is restricted to GitHub Actions-managed hosts." >&2
  exit 2
fi
if [[ ! "${API_LEVEL}" =~ ^[0-9]+$ ]] || (( API_LEVEL < 23 || API_LEVEL > 36 )); then
  echo "API level must be an integer within 23..36." >&2
  exit 2
fi
if [[ -z "${PRIVATE_ENV}" || ! -f "${PRIVATE_ENV}" ]]; then
  echo "LEONA_GITHUB_MATRIX_PRIVATE_ENV must point to the ephemeral 0600 env file." >&2
  exit 2
fi

private_mode="$(stat -c '%a' "${PRIVATE_ENV}" 2>/dev/null || stat -f '%Lp' "${PRIVATE_ENV}")"
if [[ "${private_mode}" != "600" ]]; then
  echo "Private env mode must be 600, got ${private_mode}." >&2
  exit 2
fi

set -a
# shellcheck disable=SC1090
source "${PRIVATE_ENV}"
set +a
: "${LEONA_API_KEY:?LEONA_API_KEY missing from private env}"
: "${LEONA_CLOUD_TEST_TOKEN:?LEONA_CLOUD_TEST_TOKEN missing from private env}"
: "${GITHUB_SHA:?GITHUB_SHA is required for provenance}"

API_DIR="${OUT_ROOT}/api-${API_LEVEL}"
RAW_DIR="${API_DIR}/raw"
REDACTED_DIR="${API_DIR}/redacted"
VERIFY_DIR="${API_DIR}/verification"
RECEIPT="${API_DIR}/fixture-receipt.json"
READY_FILE="${API_DIR}/fixture.ready"
FIXTURE_LOG="${API_DIR}/fixture.log"
mkdir -p "${API_DIR}"
rm -rf "${RAW_DIR}" "${REDACTED_DIR}" "${VERIFY_DIR}"

APK="$(find "${ROOT_DIR}/sample-app/build/outputs/apk/cloudTest" -maxdepth 1 -type f -name '*.apk' -print -quit 2>/dev/null || true)"
if [[ -z "${APK}" || ! -f "${APK}" ]]; then
  echo "cloudTest APK not found; build :sample-app:assembleCloudTest first." >&2
  exit 2
fi

cleanup() {
  if [[ -n "${FIXTURE_PID:-}" ]]; then
    kill "${FIXTURE_PID}" >/dev/null 2>&1 || true
    wait "${FIXTURE_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${RAW_DIR}"
  rm -f "${READY_FILE}"
  unset LEONA_API_KEY LEONA_CLOUD_TEST_TOKEN LEONA_FIXTURE_APP_KEY
}
trap cleanup EXIT

export LEONA_FIXTURE_APP_KEY="${LEONA_API_KEY}"
python3 "${ROOT_DIR}/scripts/run-public-hosted-reporting-fixture.py" \
  --host 127.0.0.1 \
  --port "${FIXTURE_PORT}" \
  --api-key-env LEONA_FIXTURE_APP_KEY \
  --receipt "${RECEIPT}" \
  --ready-file "${READY_FILE}" \
  --max-requests 1 \
  >"${FIXTURE_LOG}" 2>&1 &
FIXTURE_PID="$!"

deadline=$((SECONDS + 20))
while [[ ! -f "${READY_FILE}" && SECONDS -lt deadline ]]; do
  if ! kill -0 "${FIXTURE_PID}" >/dev/null 2>&1; then
    echo "Public-hosted fixture exited before readiness." >&2
    exit 3
  fi
  sleep 1
done
if [[ ! -f "${READY_FILE}" ]]; then
  echo "Timed out waiting for public-hosted fixture readiness." >&2
  exit 3
fi
curl --fail --silent --show-error "http://127.0.0.1:${FIXTURE_PORT}/healthz" >/dev/null

if [[ -z "${ANDROID_SERIAL:-}" ]]; then
  export ANDROID_SERIAL
  ANDROID_SERIAL="$(adb devices | awk 'NR > 1 && $2 == "device" {print $1; exit}')"
fi
if [[ -z "${ANDROID_SERIAL:-}" ]]; then
  echo "No ready ADB target was found." >&2
  exit 3
fi

# The domestic CI lane must run on a plain AOSP image.  Failing this check is
# safer than accidentally treating a Google-enabled image as no-Google
# compatibility evidence.
for forbidden_package in com.google.android.gms com.android.vending com.google.android.gsf; do
  if adb -s "${ANDROID_SERIAL}" shell pm path "${forbidden_package}" 2>/dev/null \
      | tr -d '\r' | grep -q '^package:'; then
    echo "Forbidden Google runtime package is installed: ${forbidden_package}" >&2
    exit 3
  fi
done

LEONA_APK="${APK}" \
LEONA_PACKAGE="io.leonasec.leona.sample" \
LEONA_ACTIVITY="io.leonasec.leona.sample/.MainActivity" \
LEONA_COLLECTION_OUT="${RAW_DIR}" \
LEONA_TRIGGER_SENSE="direct" \
LEONA_CLOUD_TEST_TOKEN="${LEONA_CLOUD_TEST_TOKEN}" \
LEONA_ENVIRONMENT_TYPE="github-hosted-avd" \
LEONA_TESTBED_NOTE="GitHub-managed Ubuntu runner and Android Emulator" \
LEONA_INSTALL_CHANNEL="adb-sideload-ci" \
LEONA_APK_LANE="cloudTest-public-hosted-fixture" \
LEONA_KEEP_FULL_LOGCAT=0 \
LEONA_SENSE_WAIT_SECONDS=25 \
  "${ROOT_DIR}/scripts/run-cloud-device-collection.sh"

if [[ ! -f "${RECEIPT}" ]]; then
  echo "Fixture did not persist a successful redacted report receipt." >&2
  exit 4
fi

python3 "${ROOT_DIR}/scripts/import-android-matrix-external-sample.py" \
  --input-dir "${RAW_DIR}" \
  --output-dir "${REDACTED_DIR}" \
  --source-label "github-hosted-avd-api-${API_LEVEL}" \
  --require-sample

APK_SHA256="$(sha256sum "${APK}" | awk '{print $1}')"
API_LEVEL="${API_LEVEL}" \
APK_SHA256="${APK_SHA256}" \
PROVENANCE_PATH="${API_DIR}/provenance.json" \
python3 - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["PROVENANCE_PATH"])
payload = {
    "schemaVersion": 1,
    "provider": "github-actions",
    "runnerManaged": True,
    "runnerOs": os.environ.get("RUNNER_OS", "Linux"),
    "runnerArch": os.environ.get("RUNNER_ARCH", "X64"),
    "apiLevel": int(os.environ["API_LEVEL"]),
    "architecture": "x86_64",
    "target": "default",
    "aospNoGms": True,
    "forbiddenGoogleRuntimePackageCount": 0,
    "triggerType": "direct",
    "artifactBoundary": "redacted-only",
    "sdkRole": "collect-and-report-evidence-only",
    "businessDecisionOwner": "customer-backend",
    "commercialAdmissionClaimed": False,
    "gitCommit": os.environ["GITHUB_SHA"],
    "githubRunId": os.environ.get("GITHUB_RUN_ID", "local"),
    "githubRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local"),
    "apkSha256": os.environ["APK_SHA256"],
    "generatedAt": datetime.now(timezone.utc).isoformat(),
    "secretValuesPrinted": False,
    "rawIdentifiersPrinted": False,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

# Raw collection contains the short-lived BoxId needed to prove the direct
# trigger.  The importer has now reduced it to a hint/hash, so remove the raw
# directory before any artifact or aggregate verifier can see it.
rm -rf "${RAW_DIR}"

python3 "${ROOT_DIR}/scripts/verify-github-hosted-runtime-evidence.py" \
  --input-root "${OUT_ROOT}" \
  --output-dir "${VERIFY_DIR}" \
  --required-api "${API_LEVEL}"

echo "GitHub-hosted runtime evidence complete for API ${API_LEVEL}: ${API_DIR}"
