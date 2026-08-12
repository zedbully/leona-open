#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "${ROOT_DIR}/.." && pwd)"
REPORT_DIR="${LEONA_V04_PUBLIC_COMMIT_SCOPE_OUT:-/tmp/leona-v0.4-public-commit-scope-$(date +%Y%m%d-%H%M%S)}"
MODE="${LEONA_PUBLIC_COMMIT_SCOPE_MODE:-working-tree}"
STRICT="${LEONA_REQUIRE_PUBLIC_COMMIT_CLEAN:-0}"

STATUS=0
PASS_COUNT=0
FAILURES=()
WARNINGS=()
BLOCKERS=()
PUBLIC_PATHS=()
NON_PUBLIC_DIRTY_PATHS=()
STAGED_FORBIDDEN_PATHS=()

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

is_forbidden_path() {
  local path="$1"
  case "${path}" in
    leona-sdk-ios|leona-sdk-ios/*) return 0 ;;
    leona-web-sdk|leona-web-sdk/*) return 0 ;;
    leona-server|leona-server/*) return 0 ;;
    leona-homepage|leona-homepage/*) return 0 ;;
    wdblogs|wdblogs/*) return 0 ;;
    private|private/*) return 0 ;;
    server|server/*) return 0 ;;
    homepage|homepage/*) return 0 ;;
    policy|policy/*) return 0 ;;
    deploy|deploy/*) return 0 ;;
    scripts/deploy*|scripts/*deploy*) return 0 ;;
    docs/ios-*|docs/leona-web-*|docs/web-*) return 0 ;;
    docs/device-fingerprint-market-analysis-v0.4.md) return 0 ;;
    docs/v0.4-command-board.md|docs/next-version-plan.md|docs/work-items.md) return 0 ;;
  esac
  return 1
}

is_public_allowed_path() {
  local path="$1"
  case "${path}" in
    README.md|LICENSE|AGENTS.md) return 0 ;;
    .github|.github/*) return 0 ;;
    examples|examples/*) return 0 ;;
    docs/README.md|docs/open-source-policy.md|docs/open-vs-private-final-matrix.md) return 0 ;;
    leona-sdk-android/private/README.md) return 0 ;;
    leona-sdk-android/private/*) return 1 ;;
    leona-sdk-android/sdk-private-core|leona-sdk-android/sdk-private-core/*) return 1 ;;
    leona-sdk-android/server|leona-sdk-android/server/*) return 1 ;;
    leona-sdk-android/build|leona-sdk-android/build/*) return 1 ;;
    leona-sdk-android/.gradle|leona-sdk-android/.gradle/*) return 1 ;;
    leona-sdk-android/local.properties) return 1 ;;
    leona-sdk-android/*) return 0 ;;
  esac
  return 1
}

classify_path() {
  local path="$1"
  [[ -z "${path}" ]] && return 0
  if is_forbidden_path "${path}"; then
    NON_PUBLIC_DIRTY_PATHS+=("${path}")
  elif is_public_allowed_path "${path}"; then
    PUBLIC_PATHS+=("${path}")
  else
    NON_PUBLIC_DIRTY_PATHS+=("${path}")
  fi
}

dedupe_file() {
  local input="$1"
  local output="$2"
  awk 'NF && !seen[$0]++' "${input}" > "${output}"
}

cd "${REPO_DIR}"

echo "[v0.4-public-commit-scope] checking public Android commit scope"
echo "[v0.4-public-commit-scope] mode: ${MODE}"
echo "[v0.4-public-commit-scope] report dir: ${REPORT_DIR}"
echo "[v0.4-public-commit-scope] secret values are never printed by this script"

git status --short > "${REPORT_DIR}/git-status-short.txt"
git diff --name-only --cached > "${REPORT_DIR}/staged-paths.raw"

case "${MODE}" in
  working-tree)
    sed -E 's/^.{3}//; s/ -> /\n/g' "${REPORT_DIR}/git-status-short.txt" \
      | awk 'NF' > "${REPORT_DIR}/dirty-paths.raw"
    ;;
  staged)
    cp "${REPORT_DIR}/staged-paths.raw" "${REPORT_DIR}/dirty-paths.raw"
    ;;
  *)
    fail "unsupported mode: ${MODE}"
    : > "${REPORT_DIR}/dirty-paths.raw"
    ;;
esac

dedupe_file "${REPORT_DIR}/dirty-paths.raw" "${REPORT_DIR}/dirty-paths.txt"
dedupe_file "${REPORT_DIR}/staged-paths.raw" "${REPORT_DIR}/staged-paths.txt"

while IFS= read -r path; do
  classify_path "${path}"
done < "${REPORT_DIR}/dirty-paths.txt"

while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  if is_forbidden_path "${path}" || ! is_public_allowed_path "${path}"; then
    STAGED_FORBIDDEN_PATHS+=("${path}")
  fi
done < "${REPORT_DIR}/staged-paths.txt"

printf '%s\n' "${PUBLIC_PATHS[@]:-}" | awk 'NF && !seen[$0]++' > "${REPORT_DIR}/public-candidate-paths.txt"
printf '%s\n' "${NON_PUBLIC_DIRTY_PATHS[@]:-}" | awk 'NF && !seen[$0]++' > "${REPORT_DIR}/non-public-dirty-paths.txt"
printf '%s\n' "${STAGED_FORBIDDEN_PATHS[@]:-}" | awk 'NF && !seen[$0]++' > "${REPORT_DIR}/staged-forbidden-paths.txt"

PUBLIC_COUNT="$(wc -l < "${REPORT_DIR}/public-candidate-paths.txt" | tr -d ' ')"
NON_PUBLIC_COUNT="$(wc -l < "${REPORT_DIR}/non-public-dirty-paths.txt" | tr -d ' ')"
STAGED_FORBIDDEN_COUNT="$(wc -l < "${REPORT_DIR}/staged-forbidden-paths.txt" | tr -d ' ')"

if [[ "${STAGED_FORBIDDEN_COUNT}" == "0" ]]; then
  pass "no forbidden or non-public paths are staged"
else
  fail "forbidden or non-public paths are staged; see ${REPORT_DIR}/staged-forbidden-paths.txt"
fi

if [[ "${NON_PUBLIC_COUNT}" == "0" ]]; then
  pass "dirty tree is limited to public Android commit scope"
else
  blocker "non-public dirty paths are present and must stay out of any public GitHub commit; see ${REPORT_DIR}/non-public-dirty-paths.txt"
  if [[ "${STRICT}" == "1" || "${MODE}" == "staged" ]]; then
    fail "non-public dirty paths present in strict/staged mode"
  fi
fi

if [[ "${PUBLIC_COUNT}" == "0" ]]; then
  warn "no public Android candidate paths detected in ${MODE} mode"
else
  pass "public Android candidate paths detected: ${PUBLIC_COUNT}"
fi

SCAN_LIST="${REPORT_DIR}/public-files-to-scan.txt"
while IFS= read -r path; do
  [[ -z "${path}" ]] && continue
  [[ -f "${path}" ]] || continue
  case "${path}" in
    leona-sdk-android/scripts/verify-v0.4-public-commit-scope.sh) continue ;;
    leona-sdk-android/scripts/verify-v0.4-public-archive.sh) continue ;;
    leona-sdk-android/scripts/verify-v0.4-public-archive-consumer.sh) continue ;;
    leona-sdk-android/scripts/verify-v0.4-release-readiness.sh) continue ;;
  esac
  printf '%s\n' "${path}" >> "${SCAN_LIST}"
done < "${REPORT_DIR}/public-candidate-paths.txt"
touch "${SCAN_LIST}"

if [[ -s "${SCAN_LIST}" ]]; then
  SECRET_MATCHES="$(
    xargs rg -n --no-heading \
      'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{20,}|-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----|LEONA_[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PRIVATE_KEY)=[A-Za-z0-9+/=_-]{20,}|full[[:space:]]BoxId:|raw[[:space:]]Android[[:space:]]ID:|raw[[:space:]]install[[:space:]]ID:' \
      < "${SCAN_LIST}" 2>/dev/null || true
  )"
  if [[ -z "${SECRET_MATCHES}" ]]; then
    pass "public candidate files do not contain forbidden secret/raw-identifier patterns"
  else
    fail "public candidate files contain forbidden secret/raw-identifier patterns:
${SECRET_MATCHES}"
  fi
else
  warn "no regular public files to scan"
fi

{
  echo "# Leona v0.4 Public Commit Scope Gate"
  echo
  if [[ "${STATUS}" == "0" && "${NON_PUBLIC_COUNT}" != "0" ]]; then
    SUMMARY_STATUS="local-pass-with-non-public-dirty-paths"
  elif [[ "${STATUS}" == "0" ]]; then
    SUMMARY_STATUS="pass"
  else
    SUMMARY_STATUS="failed"
  fi
  echo "- status: ${SUMMARY_STATUS}"
  echo "- mode: \`${MODE}\`"
  echo "- strict: \`${STRICT}\`"
  echo "- report dir: \`${REPORT_DIR}\`"
  echo "- secret values printed: no"
  echo "- public candidate paths: ${PUBLIC_COUNT}"
  echo "- non-public dirty paths: ${NON_PUBLIC_COUNT}"
  echo "- staged forbidden paths: ${STAGED_FORBIDDEN_COUNT}"
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
  echo "## Non-Public Commit Blockers"
  if (( ${#BLOCKERS[@]} == 0 )); then
    echo "- none"
  else
    printf -- '- %s\n' "${BLOCKERS[@]}"
  fi
  echo
  echo "## Policy"
  echo "- Only public Android SDK, public docs, root README/LICENSE/AGENTS, and GitHub workflow/template files are public commit candidates."
  echo "- iOS, Web, server, homepage, deployment, policy, private detector, internal docs, raw identifiers, and secrets must not be included in public GitHub commits."
} > "${REPORT_DIR}/summary.md"

echo "[v0.4-public-commit-scope] summary: ${REPORT_DIR}/summary.md"
exit "${STATUS}"
