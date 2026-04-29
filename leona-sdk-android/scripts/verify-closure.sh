#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

resolve_java_home() {
  if [[ -n "${JAVA_HOME:-}" && -x "${JAVA_HOME}/bin/java" ]]; then
    printf '%s\n' "$JAVA_HOME"
    return 0
  fi

  if command -v brew >/dev/null 2>&1; then
    local brew_home
    brew_home="$(brew --prefix openjdk@21 2>/dev/null || true)"
    if [[ -n "$brew_home" && -x "$brew_home/libexec/openjdk.jdk/Contents/Home/bin/java" ]]; then
      printf '%s\n' "$brew_home/libexec/openjdk.jdk/Contents/Home"
      return 0
    fi
  fi

  return 1
}

JAVA_HOME_RESOLVED="$(resolve_java_home || true)"
if [[ -z "$JAVA_HOME_RESOLVED" ]]; then
  cat >&2 <<'EOF'
Unable to resolve JAVA_HOME for OpenJDK 21.

Set it explicitly, for example:
  export JAVA_HOME="$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home"
EOF
  exit 1
fi

export JAVA_HOME="$JAVA_HOME_RESOLVED"
export PATH="$JAVA_HOME/bin:$PATH"

GRADLE_ARGS=(
  --no-configuration-cache
  :sdk:testDebugUnitTest
  :sample-app:assembleDebug
)

if [[ -d "$ROOT_DIR/private/sdk-private-core" ]]; then
  GRADLE_ARGS+=(:sdk-private-core:assembleDebug)
else
  echo "[Leona closure] private sdk core not present; skipping :sdk-private-core:assembleDebug"
fi

echo "[Leona closure] repo      : $ROOT_DIR"
echo "[Leona closure] JAVA_HOME : $JAVA_HOME"
echo "[Leona closure] tasks     : ${GRADLE_ARGS[*]}"
echo

cd "$ROOT_DIR"
./gradlew "${GRADLE_ARGS[@]}"

echo
echo "[Leona closure] build gates passed"
echo "  - sdk JVM/unit parity tests"
if [[ -d "$ROOT_DIR/private/sdk-private-core" ]]; then
  echo "  - private native core debug assemble"
else
  echo "  - private native core debug assemble skipped (public-only checkout)"
fi
echo "  - sample app debug assemble"
echo
echo "[Leona closure] remaining manual gates"
echo "  1. Handshake attestation summary regression"
echo "  2. Real-device false-positive regression"
echo "  3. Backend canonicalDeviceId / cloud-config regression"
echo "  4. Sample app diagnostics/verdict/support-bundle sanity check"
