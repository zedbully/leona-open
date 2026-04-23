#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STRICT=0
RUN_BUILD=0
TARGETS=()

usage() {
  cat <<USAGE
Usage:
  $(basename "$0") [--strict] [--with-build] [repo_dir ...]

Examples:
  $(basename "$0")
  $(basename "$0") --strict leona-sdk-android leona-server
  $(basename "$0") --strict --with-build leona-sdk-android leona-server

Notes:
  - Run this inside the real Git working tree that you plan to publish.
  - By default it checks common child repos under the current workspace root.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict)
      STRICT=1
      shift
      ;;
    --with-build)
      RUN_BUILD=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      TARGETS+=("$1")
      shift
      ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(leona-sdk-android leona-server demo-backend leona)
fi

failures=0
checked=0

print_section() {
  printf '\n===== %s =====\n' "$1"
}

check_repo() {
  local rel="$1"
  local dir="$ROOT_DIR/$rel"
  local status_out cached_out tracked_private staged_private ignored_private suspicious_local

  print_section "$rel"

  if [[ ! -d "$dir" ]]; then
    echo "skip: missing directory"
    return 0
  fi

  if ! git -C "$dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "skip: not a git working tree"
    return 0
  fi

  checked=$((checked + 1))
  echo "repo: $dir"

  status_out="$(git -C "$dir" status --short || true)"
  cached_out="$(git -C "$dir" diff --cached --name-only || true)"
  tracked_private="$(git -C "$dir" ls-files | grep -E '(^|/)private/' || true)"
  staged_private="$(printf '%s\n' "$cached_out" | grep -E '(^|/)private/' || true)"
  ignored_private="$(git -C "$dir" check-ignore -v private 2>/dev/null || true)"
  suspicious_local="$(find "$dir" \
    \( -name '.DS_Store' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.jks' -o -name '*.keystore' -o -name '.env' -o -name '.env.*' -o -name 'application-local.yml' -o -name 'application-local.properties' \) \
    -not -path '*/build/*' -not -path '*/.gradle/*' -not -path '*/.git/*' -not -path '*/.cxx/*' -print || true)"

  echo "-- git status --short"
  if [[ -n "$status_out" ]]; then
    printf '%s\n' "$status_out"
  else
    echo "clean"
  fi

  echo "-- git diff --cached --name-only"
  if [[ -n "$cached_out" ]]; then
    printf '%s\n' "$cached_out"
  else
    echo "empty"
  fi

  echo "-- tracked private files"
  if [[ -n "$tracked_private" ]]; then
    printf '%s\n' "$tracked_private"
  else
    echo "none"
  fi

  echo "-- staged private files"
  if [[ -n "$staged_private" ]]; then
    printf '%s\n' "$staged_private"
  else
    echo "none"
  fi

  echo "-- ignore rule for private"
  if [[ -n "$ignored_private" ]]; then
    printf '%s\n' "$ignored_private"
  else
    echo "warning: no direct ignore match for ./private"
  fi

  echo "-- suspicious local files"
  if [[ -n "$suspicious_local" ]]; then
    printf '%s\n' "$suspicious_local"
  else
    echo "none"
  fi

  if [[ $RUN_BUILD -eq 1 ]]; then
    echo "-- optional build checks"
    case "$rel" in
      leona-sdk-android)
        (cd "$dir" && ./gradlew :sdk:assembleDebug :sample-app:assembleDebug --no-daemon --no-configuration-cache)
        ;;
      leona-server)
        (cd "$dir" && ./scripts/gradlew-java21.sh :common:classes :ingestion-service:classes :worker-event-persister:classes --no-daemon --no-configuration-cache)
        ;;
      *)
        echo "skip build check for $rel"
        ;;
    esac
  fi

  if [[ $STRICT -eq 1 ]]; then
    if [[ -n "$tracked_private" || -n "$staged_private" || -n "$suspicious_local" ]]; then
      echo "strict result: FAIL"
      failures=$((failures + 1))
    else
      echo "strict result: PASS"
    fi
  else
    echo "result: reviewed"
  fi
}

for repo in "${TARGETS[@]}"; do
  check_repo "$repo"
done

print_section "summary"
echo "checked git repos: $checked"
if [[ $STRICT -eq 1 ]]; then
  echo "strict failures: $failures"
  [[ $failures -eq 0 ]]
else
  echo "mode: advisory"
fi
