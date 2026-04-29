#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${GRADLE_USER_HOME:=$HOME/.gradle}"
: "${LEONA_API_KEY:?LEONA_API_KEY is required. Use a Leona issued public SDK app key.}"
: "${LEONA_REPORTING_ENDPOINT:?LEONA_REPORTING_ENDPOINT is required. Use the Leona hosted reporting endpoint.}"
: "${LEONA_CLOUD_CONFIG_ENDPOINT:=}"
: "${LEONA_DEMO_BACKEND_BASE_URL:=}"
: "${LEONA_TENANT_ID:=sample}"
: "${LEONA_SAMPLE_ATTESTATION_MODE:=off}"
: "${LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER:=}"
: "${LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP:=false}"
: "${LEONA_TASK:=auto}"

if [[ ! -x "$ROOT_DIR/gradlew" ]]; then
  echo "gradlew not found or not executable: $ROOT_DIR/gradlew" >&2
  exit 1
fi

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
  -PLEONA_TENANT_ID="$LEONA_TENANT_ID" \
  -PLEONA_REPORTING_ENDPOINT="$LEONA_REPORTING_ENDPOINT" \
  -PLEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
  -PLEONA_DEMO_BACKEND_BASE_URL="$LEONA_DEMO_BACKEND_BASE_URL" \
  -PLEONA_DEMO_VERDICT_SECRET_KEY="" \
  -PLEONA_SAMPLE_ATTESTATION_MODE="$LEONA_SAMPLE_ATTESTATION_MODE" \
  -PLEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER="$LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER" \
  -PLEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP="$LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP" \
  --no-daemon \
  --no-configuration-cache \
  --stacktrace

BUILD_CONFIG="$ROOT_DIR/sample-app/build/generated/source/buildConfig/debug/io/leonasec/leona/sample/BuildConfig.java"
APK_PATH="$ROOT_DIR/sample-app/build/outputs/apk/debug/sample-app-debug.apk"

echo
echo "[Leona] task completed: $LEONA_TASK"
echo "[Leona] BuildConfig: $BUILD_CONFIG"
echo "[Leona] APK:         $APK_PATH"

python3 - "$BUILD_CONFIG" <<'PY' || true
import re
import sys

path = sys.argv[1]
secret_keys = {"LEONA_API_KEY", "LEONA_DEMO_VERDICT_SECRET_KEY"}
pattern = re.compile(
    r'public static final String '
    r'(LEONA_(?:API_KEY|TENANT_ID|REPORTING_ENDPOINT|CLOUD_CONFIG_ENDPOINT|DEMO_BACKEND_BASE_URL|'
    r'DEMO_VERDICT_SECRET_KEY|SAMPLE_ATTESTATION_MODE|SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER))'
    r' = "(.*)";'
)

for line in open(path, "r", encoding="utf-8"):
    match = pattern.search(line)
    if not match:
        continue
    key, value = match.groups()
    if key in secret_keys and value:
        value = "<redacted>"
    print(f"public static final String {key} = \"{value}\";")
PY
