#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${ADB_SERIAL:=emulator-5554}"
: "${OUTPUT_DIR:=/tmp/leona-e2e-$(date +%Y%m%d-%H%M%S)}"
: "${LEONA_REPORTING_ENDPOINT:=http://10.0.2.2:8080}"
: "${LEONA_CLOUD_CONFIG_ENDPOINT:=http://10.0.2.2:8090/v1/mobile-config}"
: "${LEONA_DEMO_BACKEND_BASE_URL:=http://10.0.2.2:8090}"
: "${SENSE_TIMEOUT_SEC:=30}"
: "${VERDICT_TIMEOUT_SEC:=20}"

if [[ -z "${LEONA_API_KEY:-}" ]]; then
  echo "LEONA_API_KEY is required" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

wait_for_device() {
  adb -s "$ADB_SERIAL" wait-for-device >/dev/null
  local boot_completed=""
  for _ in $(seq 1 60); do
    boot_completed="$(adb -s "$ADB_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')"
    [[ "$boot_completed" == "1" ]] && return 0
    sleep 2
  done
  echo "Device $ADB_SERIAL did not finish booting" >&2
  return 1
}

dump_ui() {
  local name="$1"
  adb -s "$ADB_SERIAL" shell uiautomator dump /sdcard/window_dump.xml >/dev/null
  adb -s "$ADB_SERIAL" pull /sdcard/window_dump.xml "$OUTPUT_DIR/$name.xml" >/dev/null
  adb -s "$ADB_SERIAL" exec-out screencap -p > "$OUTPUT_DIR/$name.png"
}

ui_value() {
  local xml="$1"
  local id="$2"
  python3 - "$xml" "$id" <<'PY'
import sys, xml.etree.ElementTree as ET
xml_path, view_id = sys.argv[1:3]
root = ET.parse(xml_path).getroot()
for node in root.iter('node'):
    if node.attrib.get('resource-id') == view_id:
        print(node.attrib.get('text', ''))
        break
PY
}

ui_enabled() {
  local xml="$1"
  local id="$2"
  python3 - "$xml" "$id" <<'PY'
import sys, xml.etree.ElementTree as ET
xml_path, view_id = sys.argv[1:3]
root = ET.parse(xml_path).getroot()
for node in root.iter('node'):
    if node.attrib.get('resource-id') == view_id:
        print(node.attrib.get('enabled', 'false'))
        break
PY
}

ui_tap() {
  local xml="$1"
  local id="$2"
  python3 - "$xml" "$id" <<'PY' > "$OUTPUT_DIR/tap.txt"
import sys, re, xml.etree.ElementTree as ET
xml_path, view_id = sys.argv[1:3]
root = ET.parse(xml_path).getroot()
for node in root.iter('node'):
    if node.attrib.get('resource-id') == view_id:
        bounds = node.attrib['bounds']
        m = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
        if not m:
            raise SystemExit('bad bounds')
        x1, y1, x2, y2 = map(int, m.groups())
        print((x1 + x2) // 2, (y1 + y2) // 2)
        break
else:
    raise SystemExit(f'view not found: {view_id}')
PY
  read -r x y < "$OUTPUT_DIR/tap.txt"
  adb -s "$ADB_SERIAL" shell input tap "$x" "$y"
}

poll_for_boxid() {
  local deadline=$(( $(date +%s) + SENSE_TIMEOUT_SEC ))
  while [[ $(date +%s) -lt $deadline ]]; do
    dump_ui sense-state >/dev/null 2>&1 || true
    local text
    text="$(ui_value "$OUTPUT_DIR/sense-state.xml" 'io.leonasec.leona.sample:id/boxId')"
    if [[ "$text" == BoxId:\ * && "$text" != "BoxId: (not yet run)" ]]; then
      echo "$text"
      return 0
    fi
    if [[ "$text" == BoxId\ error:* ]]; then
      echo "$text" >&2
      return 1
    fi
    sleep 2
  done
  echo "Timed out waiting for BoxId" >&2
  return 1
}

poll_for_verdict() {
  local deadline=$(( $(date +%s) + VERDICT_TIMEOUT_SEC ))
  while [[ $(date +%s) -lt $deadline ]]; do
    dump_ui verdict-state >/dev/null 2>&1 || true
    local text
    text="$(ui_value "$OUTPUT_DIR/verdict-state.xml" 'io.leonasec.leona.sample:id/verdictResult')"
    if [[ -n "$text" ]]; then
      if [[ "$text" == Verdict\ error:* ]]; then
        echo "$text" >&2
        return 1
      fi
      echo "$text"
      return 0
    fi
    sleep 2
  done
  echo "Timed out waiting for verdict result" >&2
  return 1
}

require_contains() {
  local haystack="$1"
  local needle="$2"
  local label="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    echo "$label missing expected fragment: $needle" >&2
    echo "--- $label ---" >&2
    printf '%s\n' "$haystack" >&2
    exit 1
  fi
}

echo "[Leona E2E] output dir: $OUTPUT_DIR"
wait_for_device

LEONA_API_KEY="$LEONA_API_KEY" \
LEONA_REPORTING_ENDPOINT="$LEONA_REPORTING_ENDPOINT" \
LEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
LEONA_DEMO_BACKEND_BASE_URL="$LEONA_DEMO_BACKEND_BASE_URL" \
LEONA_TASK=installDebug \
"$ROOT_DIR/scripts/run-live-sample.sh"

adb -s "$ADB_SERIAL" shell am force-stop io.leonasec.leona.sample
adb -s "$ADB_SERIAL" logcat -c
adb -s "$ADB_SERIAL" shell am start -n io.leonasec.leona.sample/.MainActivity >/dev/null
sleep 3

dump_ui home
ui_tap "$OUTPUT_DIR/home.xml" 'io.leonasec.leona.sample:id/buttonSense'
box_line="$(poll_for_boxid)"
box_id="${box_line#BoxId: }"

dump_ui post-sense
button_enabled="$(ui_enabled "$OUTPUT_DIR/post-sense.xml" 'io.leonasec.leona.sample:id/buttonVerdict')"
if [[ "$button_enabled" != "true" ]]; then
  echo "Verdict button is not enabled after sense(): $button_enabled" >&2
  exit 1
fi
device_line="$(ui_value "$OUTPUT_DIR/post-sense.xml" 'io.leonasec.leona.sample:id/deviceId')"
diagnostic_text="$(ui_value "$OUTPUT_DIR/post-sense.xml" 'io.leonasec.leona.sample:id/diagnosticSummary')"
support_bundle_text="$(ui_value "$OUTPUT_DIR/post-sense.xml" 'io.leonasec.leona.sample:id/supportBundleSummary')"

if [[ -n "$LEONA_CLOUD_CONFIG_ENDPOINT" ]]; then
  if [[ "$device_line" != DeviceId:\ L* ]]; then
    echo "Expected canonical device id after cloud-config, got: $device_line" >&2
    exit 1
  fi
  require_contains "$support_bundle_text" 'effectiveDisabled=androidId' 'supportBundleSummary'
  require_contains "$support_bundle_text" 'cloudRawPresent=true' 'supportBundleSummary'
fi

ui_tap "$OUTPUT_DIR/post-sense.xml" 'io.leonasec.leona.sample:id/buttonVerdict'
verdict_text="$(poll_for_verdict)"

dump_ui final
final_device_line="$(ui_value "$OUTPUT_DIR/final.xml" 'io.leonasec.leona.sample:id/deviceId')"
final_support_bundle_text="$(ui_value "$OUTPUT_DIR/final.xml" 'io.leonasec.leona.sample:id/supportBundleSummary')"
final_diagnostic_text="$(ui_value "$OUTPUT_DIR/final.xml" 'io.leonasec.leona.sample:id/diagnosticSummary')"

if [[ -n "$LEONA_CLOUD_CONFIG_ENDPOINT" ]]; then
  canonical_id="${final_device_line#DeviceId: }"
  require_contains "$final_support_bundle_text" "canonical=$canonical_id" 'supportBundleSummary'
  require_contains "$final_diagnostic_text" "canonical=$canonical_id" 'diagnosticSummary'
  require_contains "$verdict_text" "canonical=$canonical_id" 'verdictResult'
fi

echo
printf '[Leona E2E] BoxId: %s\n' "$box_id"
printf '[Leona E2E] Device: %s\n' "$final_device_line"
printf '[Leona E2E] Support bundle:\n%s\n' "$final_support_bundle_text"
printf '[Leona E2E] Verdict:\n%s\n' "$verdict_text"
