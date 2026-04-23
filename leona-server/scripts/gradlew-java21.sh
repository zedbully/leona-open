#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_GRADLE_USER_HOME="${PROJECT_ROOT}/../.gradle-home"

choose_java_home() {
  if [[ -n "${LEONA_SERVER_JAVA_HOME:-}" && -x "${LEONA_SERVER_JAVA_HOME}/bin/java" ]]; then
    printf '%s\n' "${LEONA_SERVER_JAVA_HOME}"
    return 0
  fi

  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    local current_major
    current_major="$("${JAVA_HOME}/bin/java" -version 2>&1 | awk -F '[\".]' '/version/ {print $2; exit}')"
    if [[ "${current_major}" == "21" ]]; then
      printf '%s\n' "${JAVA_HOME}"
      return 0
    fi
  fi

  local candidates=(
    "/Applications/IntelliJ IDEA.app/Contents/jbr/Contents/Home"
    "/Applications/PyCharm.app/Contents/jbr/Contents/Home"
  )

  local candidate
  for candidate in "${candidates[@]}"; do
    if [[ -x "${candidate}/bin/java" ]]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done

  return 1
}

JAVA_HOME_SELECTED="$(choose_java_home || true)"
if [[ -z "${JAVA_HOME_SELECTED}" ]]; then
  cat >&2 <<'EOF'
ERROR: No compatible Java 21 runtime found for leona-server Gradle tasks.

Reason:
- Gradle 8.10.2 Kotlin DSL in this repo still fails under launcher Java 25.

Fix:
- Install/start IntelliJ IDEA or PyCharm bundled JBR 21, or
- export LEONA_SERVER_JAVA_HOME=/path/to/jdk-21
EOF
  exit 1
fi

export JAVA_HOME="${JAVA_HOME_SELECTED}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-${DEFAULT_GRADLE_USER_HOME}}"

cd "${PROJECT_ROOT}"
exec "${PROJECT_ROOT}/gradlew" "$@"
