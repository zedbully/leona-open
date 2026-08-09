#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
VERSION="${LEONA_SDK_VERSION:-$(grep '^VERSION_NAME=' "${ROOT_DIR}/gradle.properties" | cut -d= -f2-)}"
REPORT_DIR="${LEONA_V04_READINESS_OUT:-/tmp/leona-v0.4-readiness-$(date +%Y%m%d-%H%M%S)}"

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

require_executable() {
  local label="$1"
  local file="$2"
  if [[ -x "${file}" ]]; then
    pass "${label}"
  else
    fail "${label}: not executable (${file})"
  fi
}

require_absent() {
  local label="$1"
  local pattern="$2"
  shift 2
  local matches
  matches="$(rg -n "${pattern}" "$@" 2>/dev/null || true)"
  if [[ -z "${matches}" ]]; then
    pass "${label}"
  else
    fail "${label}: found forbidden public-boundary match
${matches}"
  fi
}

run_gate() {
  local label="$1"
  local output_name="$2"
  shift 2
  echo "[v0.4-readiness] running ${label}"
  if "$@" > "${REPORT_DIR}/${output_name}.txt" 2>&1; then
    pass "${label} passes"
  else
    fail "${label} failed; see ${REPORT_DIR}/${output_name}.txt"
  fi
}

run_optional_gate() {
  local label="$1"
  local output_name="$2"
  local enabled="$3"
  shift 3
  if [[ "${enabled}" == "1" ]]; then
    run_gate "${label}" "${output_name}" "$@"
  else
    warn "${label} not rerun; set the documented env flag to execute it."
  fi
}

ACQUISITION_ATTEMPT_ARGS=()
ACQUISITION_ATTEMPT_COUNT=0
if [[ -n "${LEONA_ANDROID_EXTERNAL_EMULATOR_INSTALL_ATTEMPTS:-}" ]]; then
  IFS=',' read -r -a ACQUISITION_ATTEMPTS <<< "${LEONA_ANDROID_EXTERNAL_EMULATOR_INSTALL_ATTEMPTS}"
  for attempt in "${ACQUISITION_ATTEMPTS[@]}"; do
    if [[ -n "${attempt}" ]]; then
      ACQUISITION_ATTEMPT_ARGS+=(--record-install-attempt "${attempt}")
      ACQUISITION_ATTEMPT_COUNT=$((ACQUISITION_ATTEMPT_COUNT + 1))
    fi
  done
fi

cd "${REPO_DIR}"

echo "[v0.4-readiness] Leona Android/Server public-safe gate"
echo "[v0.4-readiness] SDK coordinate version: ${VERSION}"
echo "[v0.4-readiness] report dir: ${REPORT_DIR}"
echo "[v0.4-readiness] secret values are never printed by this script"

require_contains "public Android CI still has native sanity gate" \
  ".github/workflows/android.yml" \
  "Native source sanity"
require_contains "public Android CI still has lint/unit gate" \
  ".github/workflows/android.yml" \
  "Lint \\+ Unit tests|sdk:testDebugUnitTest"
require_contains "public Android CI still assembles release AAR" \
  ".github/workflows/android.yml" \
  "Assemble AAR|sdk:assembleRelease"

require_contains "root README documents current SDK dependency" \
  "README.md" \
  "leona-sdk-android:${VERSION}"
require_contains "SDK README documents current SDK dependency" \
  "leona-sdk-android/README.md" \
  "leona-sdk-android:${VERSION}"
require_contains "SDK README documents Android 6-16 compatibility gate" \
  "leona-sdk-android/README.md" \
  "verify-android-6-16-compatibility\.py"
require_contains "SDK README documents v0.4 release readiness gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-readiness\\.sh"
require_contains "SDK README documents Maven Central readiness gate" \
  "leona-sdk-android/README.md" \
  "verify-maven-central-readiness\\.sh"
require_contains "SDK README documents backend wrapper contract" \
  "leona-sdk-android/README.md" \
  "backend-wrapper-contract"
require_contains "SDK README documents v0.4 evidence and privacy boundary" \
  "leona-sdk-android/README.md" \
  "v0\\.4-evidence-privacy-boundary"
require_contains "SDK README documents v0.4 release notes draft" \
  "leona-sdk-android/README.md" \
  "v0\\.4-release-notes-draft"
require_contains "SDK README documents v0.4 release checklist" \
  "leona-sdk-android/README.md" \
  "v0\\.4-release-checklist"
require_contains "SDK README documents v0.4 tag release runbook" \
  "leona-sdk-android/README.md" \
  "v0\\.4-tag-release-runbook"
require_contains "SDK README documents v0.4 public archive dry-run" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-public-archive\\.sh"
require_contains "SDK README documents v0.4 public archive consumer smoke" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-public-archive-consumer\\.sh"
require_contains "SDK README documents v0.4 publish workflow dry-run" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-publish-workflow-dry-run\\.sh"
require_contains "SDK README documents v0.4 release candidate manifest" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-candidate-manifest\\.sh"
require_contains "SDK README documents v0.4 release candidate review wrapper" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-candidate-review\\.sh"
require_contains "SDK README documents v0.4 release candidate review schema gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-candidate-review-schema\\.py"
require_contains "SDK README documents v0.4 release candidate final review wrapper" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-candidate-final-review\\.sh"
require_contains "SDK README documents v0.4 release candidate final review schema gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-candidate-final-review-schema\\.py"
require_contains "SDK README documents v0.4 release candidate manifest schema gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-candidate-manifest-schema\\.py"
require_contains "SDK README documents v0.4 release evidence pack schema gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-release-evidence-pack-schema\\.py"
require_contains "SDK README documents v0.4 version bump plan gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-version-bump-plan\\.py"
require_contains "SDK README documents v0.4 version bump dry-run gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-version-bump-dry-run\\.py"
require_contains "SDK README documents v0.4 public commit scope gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-public-commit-scope\\.sh"
require_contains "SDK README documents v0.4 public release batch planner" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-public-release-batch\\.sh"
require_contains "SDK README documents v0.4 public release batch schema gate" \
  "leona-sdk-android/README.md" \
  "verify-v0\\.4-public-release-batch-schema\\.py"
require_contains "SDK README documents Android changelog" \
  "leona-sdk-android/README.md" \
  "CHANGELOG\\.md"
require_contains "v0.4 public boundary doc keeps evidence-only wording" \
  "leona-sdk-android/docs/v0.4-evidence-privacy-boundary.md" \
  "evidence-only|only collects and reports"
require_contains "v0.4 public boundary doc bans business decisions in SDK" \
  "leona-sdk-android/docs/v0.4-evidence-privacy-boundary.md" \
  "allow, reject, block|business decisions"
require_contains "v0.4 public boundary doc documents redaction" \
  "leona-sdk-android/docs/v0.4-evidence-privacy-boundary.md" \
  'full `BoxId`|raw Android ID|SecretKey'
require_contains "v0.4 release notes draft keeps evidence-only positioning" \
  "leona-sdk-android/docs/v0.4-release-notes-draft.md" \
  "evidence-only|customer backend"
require_contains "v0.4 release notes draft records external blockers" \
  "leona-sdk-android/docs/v0.4-release-notes-draft.md" \
  "External Blockers|custom ROM|Play Integrity|Maven Central"
require_contains "v0.4 release notes draft records non-goals" \
  "leona-sdk-android/docs/v0.4-release-notes-draft.md" \
  "Explicit Non-Goals|business decisions|open source"
require_contains "v0.4 release checklist keeps evidence-only positioning" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "evidence-only|customer backend"
require_contains "v0.4 release checklist records required local gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-readiness\\.sh|local-pass-with-external-blockers"
require_contains "v0.4 release checklist records privacy boundary" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "full BoxIds|tenant SecretKey|raw Android ID"
require_contains "v0.4 release checklist records public archive dry-run" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-public-archive\\.sh|Public Archive Dry Run"
require_contains "v0.4 release checklist records public archive consumer smoke" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-public-archive-consumer\\.sh|Public Archive Consumer Smoke"
require_contains "v0.4 release checklist records publish workflow dry-run" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-publish-workflow-dry-run\\.sh|Publish Workflow Dry Run"
require_contains "v0.4 release checklist records release candidate manifest" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-candidate-manifest\\.sh|Release Candidate Manifest"
require_contains "v0.4 release checklist records release candidate review wrapper" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-candidate-review\\.sh|release candidate review"
require_contains "v0.4 release checklist records release candidate review schema gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-candidate-review-schema\\.py|review schema"
require_contains "v0.4 release checklist records release candidate final review wrapper" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-candidate-final-review\\.sh|final review"
require_contains "v0.4 release checklist records release candidate final review schema gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-candidate-final-review-schema\\.py|final review schema"
require_contains "v0.4 release checklist records release candidate manifest schema gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-candidate-manifest-schema\\.py|manifest schema"
require_contains "v0.4 release checklist records evidence pack schema gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-release-evidence-pack-schema\\.py|evidence pack schema"
require_contains "v0.4 release checklist records version bump plan gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-version-bump-plan\\.py|version bump plan"
require_contains "v0.4 release checklist records version bump dry-run gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-version-bump-dry-run\\.py|version bump dry-run"
require_contains "v0.4 release checklist records tag release runbook" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "v0\\.4-tag-release-runbook|Tag Release Runbook"
require_contains "v0.4 release checklist records public commit scope gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-public-commit-scope\\.sh|Public Commit Scope"
require_contains "v0.4 release checklist records public release batch planner" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-public-release-batch\\.sh|public Android release batch plan"
require_contains "v0.4 release checklist records public release batch schema gate" \
  "leona-sdk-android/docs/v0.4-release-checklist.md" \
  "verify-v0\\.4-public-release-batch-schema\\.py|public release batch schema"
require_contains "v0.4 tag release runbook records version alignment" \
  "leona-sdk-android/docs/v0.4-tag-release-runbook.md" \
  "VERSION_NAME=0\\.4\\.0"
require_contains "v0.4 tag release runbook records post-release consumption smoke" \
  "leona-sdk-android/docs/v0.4-tag-release-runbook.md" \
  "verify-v0\\.4-post-release-consumption\\.sh"
require_contains "v0.4 tag release runbook keeps evidence-only positioning" \
  "leona-sdk-android/docs/v0.4-tag-release-runbook.md" \
  "evidence-only|Customer backends own final business decisions"
require_contains "Android changelog keeps evidence-only positioning" \
  "leona-sdk-android/CHANGELOG.md" \
  "evidence-only|customer backends"
require_contains "Android changelog records v0.4 external blockers" \
  "leona-sdk-android/CHANGELOG.md" \
  "External blockers|Maven Central|attestation provider"
require_contains "Android changelog records v0.4 readiness gate" \
  "leona-sdk-android/CHANGELOG.md" \
  "v0\\.4 Android/Server aggregate release-readiness gate"
require_contains "Android changelog records public commit scope gate" \
  "leona-sdk-android/CHANGELOG.md" \
  "public commit scope gate"
require_contains "Android changelog records public release batch planner" \
  "leona-sdk-android/CHANGELOG.md" \
  "public release batch planner"
require_contains "Android changelog records public release batch schema gate" \
  "leona-sdk-android/CHANGELOG.md" \
  "public release batch schema gate"
require_contains "Android changelog records release candidate manifest schema gate" \
  "leona-sdk-android/CHANGELOG.md" \
  "release candidate manifest schema gate"
require_contains "Android changelog records release candidate review wrapper" \
  "leona-sdk-android/CHANGELOG.md" \
  "release candidate review wrapper"
require_contains "Android changelog records release candidate review schema gate" \
  "leona-sdk-android/CHANGELOG.md" \
  "release candidate review schema gate"
require_contains "Android changelog records release candidate final review wrapper" \
  "leona-sdk-android/CHANGELOG.md" \
  "release candidate final review wrapper"
require_contains "Android changelog records release candidate final review schema gate" \
  "leona-sdk-android/CHANGELOG.md" \
  "release candidate final review schema gate"
require_contains "Android changelog records version bump dry-run gate" \
  "leona-sdk-android/CHANGELOG.md" \
  "version bump dry-run"
require_contains "root README keeps evidence-only business policy wording" \
  "README.md" \
  "client only collects evidence and reports it|Leona provides evidence and"
require_contains "SDK README keeps evidence-only business policy wording" \
  "leona-sdk-android/README.md" \
  "Leona provides evidence, not final business decisions|does not make allow/reject/block decisions"

require_executable "clean OEM ledger gate is executable" \
  "leona-sdk-android/scripts/verify-clean-oem-ledger.sh"
require_executable "v0.4 Android matrix readiness gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-android-matrix-readiness.sh"
require_executable "Android 6-16 compatibility gate is executable" \
  "leona-sdk-android/scripts/verify-android-6-16-compatibility.py"
require_executable "Android 6-16 runtime manifest builder is executable" \
  "leona-sdk-android/scripts/build-android-6-16-runtime-manifest.py"
require_executable "Android physical/OEM closure verifier is executable" \
  "leona-sdk-android/scripts/verify-android-physical-oem-closure.py"
require_executable "Android matrix external import gate is executable" \
  "leona-sdk-android/scripts/import-android-matrix-external-sample.py"
require_executable "Android external emulator acquisition preflight is executable" \
  "leona-sdk-android/scripts/probe-android-external-emulator-acquisition.py"
require_executable "attestation real-smoke preflight gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-attestation-real-smoke-preflight.py"
require_executable "Maven Central readiness gate is executable" \
  "leona-sdk-android/scripts/verify-maven-central-readiness.sh"
require_executable "backend wrapper verification gate is executable" \
  "leona-sdk-android/scripts/verify-backend-wrapper-skeletons.sh"
require_executable "v0.4 public archive dry-run is executable" \
  "leona-sdk-android/scripts/verify-v0.4-public-archive.sh"
require_executable "v0.4 public archive consumer smoke is executable" \
  "leona-sdk-android/scripts/verify-v0.4-public-archive-consumer.sh"
require_executable "v0.4 publish workflow dry-run is executable" \
  "leona-sdk-android/scripts/verify-v0.4-publish-workflow-dry-run.sh"
require_executable "v0.4 release candidate manifest gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-release-candidate-manifest.sh"
require_executable "v0.4 release candidate review wrapper is executable" \
  "leona-sdk-android/scripts/verify-v0.4-release-candidate-review.sh"
require_executable "v0.4 release candidate review schema gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-release-candidate-review-schema.py"
require_executable "v0.4 release candidate final review wrapper is executable" \
  "leona-sdk-android/scripts/verify-v0.4-release-candidate-final-review.sh"
require_executable "v0.4 release candidate final review schema gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-release-candidate-final-review-schema.py"
require_executable "v0.4 release candidate manifest schema gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-release-candidate-manifest-schema.py"
require_executable "v0.4 release evidence pack schema gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-release-evidence-pack-schema.py"
require_executable "v0.4 version bump plan gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-version-bump-plan.py"
require_executable "v0.4 version bump dry-run gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-version-bump-dry-run.py"
require_executable "v0.4 public commit scope gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-public-commit-scope.sh"
require_executable "v0.4 public release batch planner is executable" \
  "leona-sdk-android/scripts/verify-v0.4-public-release-batch.sh"
require_executable "v0.4 public release batch schema gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-public-release-batch-schema.py"
require_executable "v0.4 post-release consumption gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-post-release-consumption.sh"
require_executable "v0.4 Android version marker gate is executable" \
  "leona-sdk-android/scripts/verify-v0.4-version-markers.sh"

require_absent "public Android docs do not expose private/deployment terms" \
  '/home/leona|111\.170|leona-homepage|RiskScoringEngine|LEONA_INCLUDE_PRIVATE_CORE|internal console|recent boxes|private ops' \
  README.md \
  leona-sdk-android/README.md \
  leona-sdk-android/docs/TESTING.md \
  leona-sdk-android/docs/wetest-matrix-runbook.md \
  leona-sdk-android/docs/emulator-matrix.md \
  leona-sdk-android/docs/rom-matrix.md \
  leona-sdk-android/docs/backend-wrapper-contract.md \
  leona-sdk-android/docs/v0.4-evidence-privacy-boundary.md \
  leona-sdk-android/docs/v0.4-release-notes-draft.md \
  leona-sdk-android/docs/v0.4-release-checklist.md \
  leona-sdk-android/docs/v0.4-tag-release-runbook.md \
  leona-sdk-android/CHANGELOG.md

require_absent "release readiness avoids login-shell environment leakage" \
  'bash[[:space:]]+-l(c|[[:space:]])' \
  leona-sdk-android/scripts/verify-v0.4-release-readiness.sh

run_gate "clean OEM ledger gate" \
  "clean-oem-ledger" \
  "${ROOT_DIR}/scripts/verify-clean-oem-ledger.sh"

if [[ -n "${LEONA_ANDROID_6_16_RUNTIME_EVIDENCE:-}" ]]; then
  if [[ "${LEONA_REQUIRE_ANDROID_6_16_RUNTIME:-0}" == "1" ]]; then
    run_gate "Android 6-16 strict compatibility gate" \
      "android-6-16-compatibility" \
      "${ROOT_DIR}/scripts/verify-android-6-16-compatibility.py" \
        --runtime-evidence "${LEONA_ANDROID_6_16_RUNTIME_EVIDENCE}" \
        --strict-runtime \
        --output-dir "${REPORT_DIR}/android-6-16-compatibility"
  else
    run_gate "Android 6-16 compatibility gate" \
      "android-6-16-compatibility" \
      "${ROOT_DIR}/scripts/verify-android-6-16-compatibility.py" \
        --runtime-evidence "${LEONA_ANDROID_6_16_RUNTIME_EVIDENCE}" \
        --output-dir "${REPORT_DIR}/android-6-16-compatibility"
  fi
else
  if [[ "${LEONA_REQUIRE_ANDROID_6_16_RUNTIME:-0}" == "1" ]]; then
    run_gate "Android 6-16 strict compatibility gate" \
      "android-6-16-compatibility" \
      "${ROOT_DIR}/scripts/verify-android-6-16-compatibility.py" \
        --strict-runtime \
        --output-dir "${REPORT_DIR}/android-6-16-compatibility"
  else
    run_gate "Android 6-16 build compatibility gate" \
      "android-6-16-compatibility" \
      "${ROOT_DIR}/scripts/verify-android-6-16-compatibility.py" \
        --output-dir "${REPORT_DIR}/android-6-16-compatibility"
  fi
fi

PHYSICAL_OEM_CLOSURE_VERIFIED=0
if [[ -n "${LEONA_ANDROID_PHYSICAL_OEM_CLOSURE_SUMMARY:-}" && -n "${LEONA_ANDROID_6_16_RUNTIME_EVIDENCE:-}" ]]; then
  run_gate "Android physical/OEM same-candidate closure gate" \
    "android-physical-oem-closure" \
    "${ROOT_DIR}/scripts/verify-android-physical-oem-closure.py" \
      --physical-summary "${LEONA_ANDROID_PHYSICAL_OEM_CLOSURE_SUMMARY}" \
      --runtime-evidence "${LEONA_ANDROID_6_16_RUNTIME_EVIDENCE}" \
      --output-dir "${REPORT_DIR}/android-physical-oem-closure"
  if grep -Eq '"status"[[:space:]]*:[[:space:]]*"pass"' "${REPORT_DIR}/android-physical-oem-closure/summary.json" 2>/dev/null; then
    PHYSICAL_OEM_CLOSURE_VERIFIED=1
  fi
fi

run_gate "v0.4 Android matrix readiness gate" \
  "android-matrix-readiness" \
  env LEONA_V04_ANDROID_MATRIX_OUT="${REPORT_DIR}/android-matrix" \
    "${ROOT_DIR}/scripts/verify-v0.4-android-matrix-readiness.sh"

MATRIX_IMPORT_INPUT="${LEONA_ANDROID_MATRIX_EXTERNAL_IMPORT_DIR:-/tmp/leona-android-matrix-bootstrap-active}"
if [[ -d "${MATRIX_IMPORT_INPUT}" ]]; then
  run_gate "Android matrix external sample import gate" \
    "android-matrix-external-import" \
    "${ROOT_DIR}/scripts/import-android-matrix-external-sample.py" \
      --input-dir "${MATRIX_IMPORT_INPUT}" \
      --output-dir "${REPORT_DIR}/android-matrix-external-import" \
      --source-label "release-readiness-import" \
      --require-sample
else
  warn "Android matrix external sample import gate skipped; set LEONA_ANDROID_MATRIX_EXTERNAL_IMPORT_DIR to a collected matrix artifact directory."
fi

if (( ACQUISITION_ATTEMPT_COUNT > 0 )); then
  run_gate "Android external emulator acquisition preflight" \
    "android-external-emulator-acquisition" \
    "${ROOT_DIR}/scripts/probe-android-external-emulator-acquisition.py" \
      --output-dir "${REPORT_DIR}/android-external-emulator-acquisition" \
      "${ACQUISITION_ATTEMPT_ARGS[@]}"
else
  # Bash 3.2 treats an empty-array expansion as an unbound variable under
  # `set -u`, so omit the optional arguments entirely on the default path.
  run_gate "Android external emulator acquisition preflight" \
    "android-external-emulator-acquisition" \
    "${ROOT_DIR}/scripts/probe-android-external-emulator-acquisition.py" \
      --output-dir "${REPORT_DIR}/android-external-emulator-acquisition"
fi

run_gate "attestation real-smoke preflight gate" \
  "attestation-real-smoke-preflight" \
  "${ROOT_DIR}/scripts/verify-v0.4-attestation-real-smoke-preflight.py" \
    --output-dir "${REPORT_DIR}/attestation-real-smoke-preflight"

run_gate "Maven Central readiness gate" \
  "maven-central-readiness" \
  env LEONA_MAVEN_CENTRAL_READINESS_OUT="${REPORT_DIR}/maven-central" \
    "${ROOT_DIR}/scripts/verify-maven-central-readiness.sh"

if [[ "${LEONA_RUN_BACKEND_WRAPPER_GATE:-1}" == "1" ]]; then
  run_gate "backend wrapper skeleton and mock HTTP gate" \
    "backend-wrapper-gate" \
    env LEONA_WRAPPER_VERIFY_OUT="${REPORT_DIR}/backend-wrappers" \
      "${ROOT_DIR}/scripts/verify-backend-wrapper-skeletons.sh"
else
  warn "backend wrapper gate skipped; set LEONA_RUN_BACKEND_WRAPPER_GATE=1 to execute it."
fi

run_gate "v0.4 public Android archive dry-run" \
  "public-archive" \
  env LEONA_V04_PUBLIC_ARCHIVE_OUT="${REPORT_DIR}/public-archive" \
    "${ROOT_DIR}/scripts/verify-v0.4-public-archive.sh"

run_gate "v0.4 public Android archive consumer smoke" \
  "public-archive-consumer" \
  env LEONA_V04_PUBLIC_ARCHIVE_CONSUMER_OUT="${REPORT_DIR}/public-archive-consumer" \
    "${ROOT_DIR}/scripts/verify-v0.4-public-archive-consumer.sh"

run_gate "v0.4 Android publish workflow dry-run" \
  "publish-workflow" \
  env LEONA_V04_PUBLISH_WORKFLOW_OUT="${REPORT_DIR}/publish-workflow" \
    "${ROOT_DIR}/scripts/verify-v0.4-publish-workflow-dry-run.sh"

run_gate "v0.4 public commit scope gate" \
  "public-commit-scope" \
  env LEONA_V04_PUBLIC_COMMIT_SCOPE_OUT="${REPORT_DIR}/public-commit-scope" \
    "${ROOT_DIR}/scripts/verify-v0.4-public-commit-scope.sh"

run_gate "v0.4 public release batch planner" \
  "public-release-batch" \
  env LEONA_V04_PUBLIC_RELEASE_BATCH_OUT="${REPORT_DIR}/public-release-batch" \
    "${ROOT_DIR}/scripts/verify-v0.4-public-release-batch.sh"

run_gate "v0.4 public release batch schema gate" \
  "public-release-batch-schema" \
  env LEONA_V04_PUBLIC_RELEASE_BATCH_SCHEMA_OUT="${REPORT_DIR}/public-release-batch-schema" \
    "${ROOT_DIR}/scripts/verify-v0.4-public-release-batch-schema.py" \
    "${REPORT_DIR}/public-release-batch/summary.md"

run_gate "v0.4 Android version marker gate" \
  "version-markers" \
  env LEONA_ANDROID_VERSION_MARKERS_OUT="${REPORT_DIR}/version-markers" \
    "${ROOT_DIR}/scripts/verify-v0.4-version-markers.sh"

run_gate "v0.4 Android version bump plan gate" \
  "version-bump-plan" \
  env LEONA_TARGET_RELEASE_VERSION="${LEONA_TARGET_RELEASE_VERSION:-0.4.0}" \
    LEONA_ANDROID_VERSION_BUMP_PLAN_OUT="${REPORT_DIR}/version-bump-plan" \
    "${ROOT_DIR}/scripts/verify-v0.4-version-bump-plan.py"

run_gate "v0.4 Android version bump dry-run gate" \
  "version-bump-dry-run" \
  env LEONA_TARGET_RELEASE_VERSION="${LEONA_TARGET_RELEASE_VERSION:-0.4.0}" \
    LEONA_ANDROID_VERSION_BUMP_DRY_RUN_OUT="${REPORT_DIR}/version-bump-dry-run" \
    "${ROOT_DIR}/scripts/verify-v0.4-version-bump-dry-run.py"

run_optional_gate "public Gradle gate" \
  "public-gradle-gate" \
  "${LEONA_RUN_PUBLIC_GRADLE_GATE:-0}" \
  bash -c "cd '${ROOT_DIR}' && exec ./gradlew :sdk:lint :sdk:testDebugUnitTest :sdk:assembleRelease :sample-app:assembleRelease --no-daemon"

run_optional_gate "public post-release consumption smoke" \
  "public-consumption" \
  "${LEONA_RUN_PUBLIC_CONSUMPTION:-0}" \
  env LEONA_TARGET_RELEASE_VERSION="${VERSION}" \
    "${ROOT_DIR}/scripts/verify-v0.4-post-release-consumption.sh"

if [[ "${PHYSICAL_OEM_CLOSURE_VERIFIED}" != "1" ]]; then
  blocker "Android physical/OEM closure requires a redacted two-OEM/two-API direct sense/report summary bound to the same API 23-36 APK candidate; emulator/custom-ROM/hide-module rows remain support evidence only."
fi
if [[ "${LEONA_REQUIRE_ANDROID_6_16_RUNTIME:-0}" != "1" || -z "${LEONA_ANDROID_6_16_RUNTIME_EVIDENCE:-}" ]]; then
  blocker "Android 6-16 strict compatibility acceptance requires one current redacted direct sense/report sample for every API 23-36."
fi
blocker "Real Play Integrity or OEM attestation provider smoke still needs Play cloud project/ADC/package/certificate/device-token material or the corresponding OEM allowlist/namespace/private bridge; the server Play verifier implementation is present."
blocker "Maven Central publish still needs Sonatype Central Portal namespace/token and PGP signing material."
blocker "A non-public customer evidence/backend-wrapper pilot still needs its endpoint, server-side SecretKey, connector/auth configuration, and a testable BoxId."
blocker "Production feedback acceptance still needs a real customer feedback export/report path; local generated labels remain semantic support evidence only."

{
  echo "# Leona v0.4 Android/Server Release Readiness"
  echo
  echo "- status: $([[ "${STATUS}" == "0" ]] && echo "local-pass-with-external-blockers" || echo "failed")"
  echo "- SDK coordinate version: \`${VERSION}\`"
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
} > "${REPORT_DIR}/summary.md"

echo "[v0.4-readiness] summary: ${REPORT_DIR}/summary.md"
exit "${STATUS}"
