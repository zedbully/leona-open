#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="$(cd "$ROOT_DIR/.." && pwd)"
DEMO_BACKEND_DIR="$WORKSPACE_ROOT/demo-backend"

: "${OUTPUT_DIR:=/tmp/leona-alpha-closure-$(date +%Y%m%d-%H%M%S)}"
: "${RUN_EMULATOR_E2E:=0}"
: "${RUN_DEVICE_E2E:=0}"
: "${DEMO_BACKEND_ADDR:=127.0.0.1:18090}"
: "${DEMO_BACKEND_BASE_URL:=http://127.0.0.1:18090}"
: "${DEMO_CLOUD_DISABLED_SIGNALS:=androidId}"
: "${DEMO_CLOUD_DISABLE_COLLECTION_WINDOW_MS:=120000}"

mkdir -p "$OUTPUT_DIR"

log() {
  printf '[Leona alpha closure] %s\n' "$*"
}

require_file() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "Required path missing: $path" >&2
    exit 1
  fi
}

run_and_capture() {
  local name="$1"
  shift
  log "running $name"
  if "$@" >"$OUTPUT_DIR/$name.log" 2>&1; then
    log "$name: PASS"
    return 0
  fi
  log "$name: FAIL"
  cat "$OUTPUT_DIR/$name.log" >&2
  return 1
}

start_demo_backend() {
  require_file "$DEMO_BACKEND_DIR/main.go"
  (
    cd "$DEMO_BACKEND_DIR"
    DEMO_BACKEND_ADDR="$DEMO_BACKEND_ADDR" \
    DEMO_CLOUD_DISABLED_SIGNALS="$DEMO_CLOUD_DISABLED_SIGNALS" \
    DEMO_CLOUD_DISABLE_COLLECTION_WINDOW_MS="$DEMO_CLOUD_DISABLE_COLLECTION_WINDOW_MS" \
    go run . >"$OUTPUT_DIR/demo-backend.log" 2>&1 &
    echo $! > "$OUTPUT_DIR/demo-backend.pid"
  )
  DEMO_BACKEND_PID="$(cat "$OUTPUT_DIR/demo-backend.pid")"
  for _ in $(seq 1 30); do
    if curl -fsS "$DEMO_BACKEND_BASE_URL/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Demo backend failed to start on $DEMO_BACKEND_ADDR" >&2
  [[ -f "$OUTPUT_DIR/demo-backend.log" ]] && cat "$OUTPUT_DIR/demo-backend.log" >&2
  return 1
}

stop_demo_backend() {
  if [[ -n "${DEMO_BACKEND_PID:-}" ]]; then
    kill "$DEMO_BACKEND_PID" >/dev/null 2>&1 || true
  fi
}

write_report() {
  local build_gate="$1"
  local cloud_smoke="$2"
  local emulator_gate="$3"
  local device_gate="$4"
  python3 - "$OUTPUT_DIR/report.json" "$OUTPUT_DIR/report.md" \
    "$build_gate" "$cloud_smoke" "$emulator_gate" "$device_gate" \
    "$RUN_EMULATOR_E2E" "$RUN_DEVICE_E2E" <<'PY'
import json
import pathlib
import sys

report_json = pathlib.Path(sys.argv[1])
report_md = pathlib.Path(sys.argv[2])
build_gate, cloud_smoke, emulator_gate, device_gate = [v == "1" for v in sys.argv[3:7]]
run_emulator, run_device = [v == "1" for v in sys.argv[7:9]]

payload = {
    "buildGate": build_gate,
    "cloudConfigSmoke": cloud_smoke,
    "emulatorE2E": {
        "requested": run_emulator,
        "passed": emulator_gate if run_emulator else None,
    },
    "deviceE2E": {
        "requested": run_device,
        "passed": device_gate if run_device else None,
    },
}
report_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

lines = [
    "# Leona alpha closure report",
    "",
    f"- buildGate: `{build_gate}`",
    f"- cloudConfigSmoke: `{cloud_smoke}`",
    f"- emulatorE2E requested: `{run_emulator}`",
    f"- emulatorE2E passed: `{emulator_gate if run_emulator else 'skipped'}`",
    f"- deviceE2E requested: `{run_device}`",
    f"- deviceE2E passed: `{device_gate if run_device else 'skipped'}`",
]
report_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

main() {
  local build_gate=0
  local cloud_smoke=0
  local emulator_gate=0
  local device_gate=0

  trap stop_demo_backend EXIT

  run_and_capture build-gate "$ROOT_DIR/scripts/verify-closure.sh"
  build_gate=1

  start_demo_backend
  run_and_capture cloud-config-smoke env \
    DEMO_BACKEND_BASE_URL="$DEMO_BACKEND_BASE_URL" \
    LEONA_DISABLED_SIGNAL_EXPECT="$DEMO_CLOUD_DISABLED_SIGNALS" \
    LEONA_DISABLE_COLLECTION_WINDOW_EXPECT="$DEMO_CLOUD_DISABLE_COLLECTION_WINDOW_MS" \
    "$ROOT_DIR/scripts/verify-demo-cloud-config.sh"
  cloud_smoke=1

  if [[ "$RUN_EMULATOR_E2E" == "1" ]]; then
    if [[ -z "${LEONA_API_KEY:-}" ]]; then
      echo "LEONA_API_KEY is required when RUN_EMULATOR_E2E=1" >&2
      exit 1
    fi
    run_and_capture emulator-e2e env \
      LEONA_API_KEY="$LEONA_API_KEY" \
      LEONA_REPORTING_ENDPOINT="${LEONA_REPORTING_ENDPOINT:-http://10.0.2.2:8080}" \
      LEONA_CLOUD_CONFIG_ENDPOINT="${LEONA_CLOUD_CONFIG_ENDPOINT:-http://10.0.2.2:8090/v1/mobile-config}" \
      LEONA_DEMO_BACKEND_BASE_URL="${LEONA_DEMO_BACKEND_BASE_URL:-http://10.0.2.2:8090}" \
      "$ROOT_DIR/scripts/run-emulator-e2e.sh"
    emulator_gate=1
  fi

  if [[ "$RUN_DEVICE_E2E" == "1" ]]; then
    if [[ -z "${LEONA_API_KEY:-}" ]]; then
      echo "LEONA_API_KEY is required when RUN_DEVICE_E2E=1" >&2
      exit 1
    fi
    run_and_capture device-e2e env \
      ADB_SERIAL="${ADB_SERIAL:-}" \
      LEONA_API_KEY="$LEONA_API_KEY" \
      LEONA_REPORTING_ENDPOINT="${LEONA_REPORTING_ENDPOINT:-http://127.0.0.1:8080}" \
      LEONA_CLOUD_CONFIG_ENDPOINT="${LEONA_CLOUD_CONFIG_ENDPOINT:-http://127.0.0.1:8090/v1/mobile-config}" \
      LEONA_DEMO_BACKEND_BASE_URL="${LEONA_DEMO_BACKEND_BASE_URL:-http://127.0.0.1:8090}" \
      "$ROOT_DIR/scripts/run-device-e2e.sh"
    device_gate=1
  fi

  write_report "$build_gate" "$cloud_smoke" "$emulator_gate" "$device_gate"

  log "report.json: $OUTPUT_DIR/report.json"
  log "report.md:   $OUTPUT_DIR/report.md"
}

main "$@"
