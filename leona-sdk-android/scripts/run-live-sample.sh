#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${JAVA_HOME:=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
: "${ANDROID_SDK_ROOT:=/Users/a/Library/Android/sdk}"
: "${GRADLE_USER_HOME:=/Users/a/back/Game/cq/.gradle-home}"
: "${LEONA_REPORTING_ENDPOINT:=http://10.0.2.2:8080}"
: "${LEONA_CLOUD_CONFIG_ENDPOINT:=http://10.0.2.2:8090/v1/mobile-config}"
: "${LEONA_DEMO_BACKEND_BASE_URL:=http://10.0.2.2:8090}"
: "${LEONA_SAMPLE_ATTESTATION_MODE:=off}"
: "${LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER:=}"
: "${LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP:=false}"
: "${LEONA_TASK:=auto}"

if [[ -z "${LEONA_API_KEY:-}" ]]; then
  cat >&2 <<'USAGE'
LEONA_API_KEY is required.

Example:
  LEONA_API_KEY=<appKey> \
  /Users/a/back/Game/cq/leona-sdk-android/scripts/run-live-sample.sh

Optional env:
  LEONA_REPORTING_ENDPOINT=http://10.0.2.2:8080
  LEONA_CLOUD_CONFIG_ENDPOINT=http://10.0.2.2:8090/v1/mobile-config
  LEONA_DEMO_BACKEND_BASE_URL=http://10.0.2.2:8090
  LEONA_TENANT_ID=sample
  LEONA_SAMPLE_ATTESTATION_MODE=off|debug_fake|bridge|oem_debug_fake|oem_bridge
  LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER=1234567890123
  LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP=false|true
  LEONA_TASK=assembleDebug|installDebug|auto
USAGE
  exit 1
fi

if [[ ! -x "$ROOT_DIR/gradlew" ]]; then
  echo "gradlew not found or not executable: $ROOT_DIR/gradlew" >&2
  exit 1
fi

export JAVA_HOME
export ANDROID_SDK_ROOT
export GRADLE_USER_HOME

if [[ "$LEONA_TASK" == "auto" ]]; then
  if command -v adb >/dev/null 2>&1 && adb devices | awk 'NR>1 && $2=="device" { found=1 } END { exit(found ? 0 : 1) }'; then
    LEONA_TASK="installDebug"
  else
    LEONA_TASK="assembleDebug"
  fi
fi

cd "$ROOT_DIR"

./gradlew \
  :sample-app:"$LEONA_TASK" \
  -PLEONA_API_KEY="$LEONA_API_KEY" \
  -PLEONA_TENANT_ID="${LEONA_TENANT_ID:-sample}" \
  -PLEONA_REPORTING_ENDPOINT="$LEONA_REPORTING_ENDPOINT" \
  -PLEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
  -PLEONA_DEMO_BACKEND_BASE_URL="$LEONA_DEMO_BACKEND_BASE_URL" \
  -PLEONA_SAMPLE_ATTESTATION_MODE="$LEONA_SAMPLE_ATTESTATION_MODE" \
  -PLEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER="$LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER" \
  -PLEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP="$LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP" \
  --no-daemon \
  --no-configuration-cache \
  --stacktrace

BUILD_CONFIG="$ROOT_DIR/sample-app/build/generated/source/buildConfig/debug/io/leonasec/leona/sample/BuildConfig.java"
AAR_PATH="$ROOT_DIR/sdk/build/outputs/aar/sdk-release.aar"
APK_PATH="$ROOT_DIR/sample-app/build/outputs/apk/debug/sample-app-debug.apk"

echo
echo "[Leona] task completed: $LEONA_TASK"
echo "[Leona] BuildConfig: $BUILD_CONFIG"
echo "[Leona] APK:         $APK_PATH"
echo "[Leona] AAR:         $AAR_PATH"

grep -E 'LEONA_(API_KEY|TENANT_ID|REPORTING_ENDPOINT|CLOUD_CONFIG_ENDPOINT|DEMO_BACKEND_BASE_URL|SAMPLE_ATTESTATION_MODE|SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER)' "$BUILD_CONFIG" || true
