#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANDROID_DIR="$ROOT_DIR/leona-sdk-android"
SERVER_DIR="$ROOT_DIR/leona-server"

export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}"
export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$ROOT_DIR/.gradle-home}"

echo "[1/4] Verify Android private core build"
(
  cd "$ANDROID_DIR"
  ./gradlew \
    :sdk-private-core:assembleDebug \
    :sdk:assembleDebug \
    :sample-app:assembleDebug \
    --no-daemon \
    --no-configuration-cache
)

PRIVATE_SO="$ANDROID_DIR/private/sdk-private-core/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libleona_private.so"
SAMPLE_PRIVATE_SO="$ANDROID_DIR/sample-app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libleona_private.so"
SAMPLE_OSS_SO="$ANDROID_DIR/sample-app/build/intermediates/merged_native_libs/debug/mergeDebugNativeLibs/out/lib/arm64-v8a/libleona.so"

[[ -f "$PRIVATE_SO" ]] || { echo "missing private core native library: $PRIVATE_SO" >&2; exit 1; }
[[ -f "$SAMPLE_PRIVATE_SO" ]] || { echo "sample-app missing libleona_private.so" >&2; exit 1; }
[[ -f "$SAMPLE_OSS_SO" ]] || { echo "sample-app missing libleona.so" >&2; exit 1; }

echo "[2/4] Verify server private backend build"
(
  cd "$SERVER_DIR"
  ./scripts/gradlew-java21.sh \
    :common:classes \
    :admin-service:classes \
    :ingestion-service:classes \
    :worker-event-persister:classes \
    :private-api-backend:classes \
    --no-daemon \
    --no-configuration-cache
)

PRIVATE_BACKEND_JAR="$(find "$SERVER_DIR/private/api-backend/build/libs" -maxdepth 1 -type f -name '*.jar' | head -n 1)"
[[ -n "${PRIVATE_BACKEND_JAR:-}" && -f "$PRIVATE_BACKEND_JAR" ]] || {
  echo "missing private backend jar under $SERVER_DIR/private/api-backend/build/libs" >&2
  exit 1
}

echo "[3/4] Artifact summary"
echo "  Android private lib : $PRIVATE_SO"
echo "  Sample merged OSS   : $SAMPLE_OSS_SO"
echo "  Sample merged private: $SAMPLE_PRIVATE_SO"
echo "  Server private jar  : $PRIVATE_BACKEND_JAR"

echo "[4/4] Private module split verification passed"
