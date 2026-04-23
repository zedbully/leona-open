#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${OUTPUT_DIR:=/tmp/leona-device-e2e-$(date +%Y%m%d-%H%M%S)}"
: "${LEONA_REPORTING_ENDPOINT:=http://127.0.0.1:8080}"
: "${LEONA_CLOUD_CONFIG_ENDPOINT:=http://127.0.0.1:8090/v1/mobile-config}"
: "${LEONA_DEMO_BACKEND_BASE_URL:=http://127.0.0.1:8090}"
: "${SENSE_TIMEOUT_SEC:=30}"
: "${VERDICT_TIMEOUT_SEC:=20}"
: "${APP_ID:=io.leonasec.leona.sample}"
: "${APP_ACTIVITY:=.MainActivity}"

if [[ -z "${LEONA_API_KEY:-}" ]]; then
  echo "LEONA_API_KEY is required" >&2
  exit 1
fi

if [[ -z "${ADB_SERIAL:-}" ]]; then
  ADB_SERIAL="$(adb devices | awk 'NR>1 && $2=="device" { print $1; exit }')"
fi

if [[ -z "${ADB_SERIAL:-}" ]]; then
  echo "No connected Android device found. Set ADB_SERIAL explicitly." >&2
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
  local prefix="$1"
  local deadline=$(( $(date +%s) + SENSE_TIMEOUT_SEC ))
  while [[ $(date +%s) -lt $deadline ]]; do
    dump_ui "$prefix-sense-state" >/dev/null 2>&1 || true
    local text
    text="$(ui_value "$OUTPUT_DIR/$prefix-sense-state.xml" "$APP_ID:id/boxId")"
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
  local prefix="$1"
  local deadline=$(( $(date +%s) + VERDICT_TIMEOUT_SEC ))
  while [[ $(date +%s) -lt $deadline ]]; do
    dump_ui "$prefix-verdict-state" >/dev/null 2>&1 || true
    local text
    text="$(ui_value "$OUTPUT_DIR/$prefix-verdict-state.xml" "$APP_ID:id/verdictResult")"
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

install_sample() {
  LEONA_API_KEY="$LEONA_API_KEY" \
  LEONA_REPORTING_ENDPOINT="$LEONA_REPORTING_ENDPOINT" \
  LEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
  LEONA_DEMO_BACKEND_BASE_URL="$LEONA_DEMO_BACKEND_BASE_URL" \
  LEONA_TASK=installDebug \
  "$ROOT_DIR/scripts/run-live-sample.sh"
}

setup_port_reverse() {
  adb -s "$ADB_SERIAL" reverse tcp:8080 tcp:8080 >/dev/null
  adb -s "$ADB_SERIAL" reverse tcp:8090 tcp:8090 >/dev/null
}

launch_sample() {
  adb -s "$ADB_SERIAL" shell am force-stop "$APP_ID"
  adb -s "$ADB_SERIAL" logcat -c
  adb -s "$ADB_SERIAL" shell am start -n "$APP_ID/$APP_ACTIVITY" >/dev/null
  sleep 3
}

run_cycle() {
  local prefix="$1"

  adb -s "$ADB_SERIAL" uninstall "$APP_ID" >/dev/null 2>&1 || true
  install_sample
  launch_sample

  dump_ui "$prefix-home"
  local pre_device_line
  pre_device_line="$(ui_value "$OUTPUT_DIR/$prefix-home.xml" "$APP_ID:id/deviceId")"
  if [[ "$pre_device_line" != DeviceId:\ T* ]]; then
    echo "Expected temporary device id before sense(), got: $pre_device_line" >&2
    exit 1
  fi

  ui_tap "$OUTPUT_DIR/$prefix-home.xml" "$APP_ID:id/buttonSense"
  local box_line
  box_line="$(poll_for_boxid "$prefix")"

  dump_ui "$prefix-post-sense"
  local post_device_line support_bundle_text consistency_text
  post_device_line="$(ui_value "$OUTPUT_DIR/$prefix-post-sense.xml" "$APP_ID:id/deviceId")"
  support_bundle_text="$(ui_value "$OUTPUT_DIR/$prefix-post-sense.xml" "$APP_ID:id/supportBundleSummary")"
  consistency_text="$(ui_value "$OUTPUT_DIR/$prefix-post-sense.xml" "$APP_ID:id/consistencySummary")"

  if [[ "$post_device_line" != DeviceId:\ L* ]]; then
    echo "Expected canonical device id after sense(), got: $post_device_line" >&2
    exit 1
  fi
  require_contains "$support_bundle_text" 'effectiveDisabled=androidId' "$prefix supportBundleSummary"
  require_contains "$support_bundle_text" 'cloudRawPresent=true' "$prefix supportBundleSummary"
  require_contains "$consistency_text" 'aligned=true' "$prefix consistencySummary"

  ui_tap "$OUTPUT_DIR/$prefix-post-sense.xml" "$APP_ID:id/buttonVerdict"
  local verdict_text
  verdict_text="$(poll_for_verdict "$prefix")"

  dump_ui "$prefix-final"
  local final_device_line final_support_bundle_text final_consistency_text final_diagnostic_text final_consistency_json
  final_device_line="$(ui_value "$OUTPUT_DIR/$prefix-final.xml" "$APP_ID:id/deviceId")"
  final_support_bundle_text="$(ui_value "$OUTPUT_DIR/$prefix-final.xml" "$APP_ID:id/supportBundleSummary")"
  final_consistency_text="$(ui_value "$OUTPUT_DIR/$prefix-final.xml" "$APP_ID:id/consistencySummary")"
  final_diagnostic_text="$(ui_value "$OUTPUT_DIR/$prefix-final.xml" "$APP_ID:id/diagnosticSummary")"
  ui_tap "$OUTPUT_DIR/$prefix-final.xml" "$APP_ID:id/buttonToggleConsistencyJson"
  dump_ui "$prefix-consistency-json"
  final_consistency_json="$(ui_value "$OUTPUT_DIR/$prefix-consistency-json.xml" "$APP_ID:id/consistencyJson")"
  local canonical_id="${final_device_line#DeviceId: }"

  require_contains "$final_support_bundle_text" "canonical=$canonical_id" "$prefix supportBundleSummary"
  require_contains "$final_support_bundle_text" "verdictCanonical=$canonical_id" "$prefix supportBundleSummary"
  require_contains "$final_diagnostic_text" "canonical=$canonical_id" "$prefix diagnosticSummary"
  require_contains "$final_consistency_text" "device=$canonical_id" "$prefix consistencySummary"
  require_contains "$final_consistency_text" "transport=$canonical_id" "$prefix consistencySummary"
  require_contains "$final_consistency_text" "verdict=$canonical_id" "$prefix consistencySummary"
  require_contains "$final_consistency_text" "bundle=$canonical_id" "$prefix consistencySummary"
  require_contains "$final_consistency_text" 'aligned=true' "$prefix consistencySummary"
  require_contains "$verdict_text" "canonical=$canonical_id" "$prefix verdictResult"
  require_contains "$final_consistency_json" '"aligned": true' "$prefix consistencyJson"

  {
    echo "[$prefix]"
    echo "preDevice=$pre_device_line"
    echo "boxId=$box_line"
    echo "canonical=$canonical_id"
    echo "supportBundle=$final_support_bundle_text"
    echo "consistency=$final_consistency_text"
    echo "verdict=$verdict_text"
    echo
  } > "$OUTPUT_DIR/$prefix-summary.txt"

  PREFIX="$prefix" \
  PRE_DEVICE_LINE="$pre_device_line" \
  BOX_LINE="$box_line" \
  CANONICAL_ID="$canonical_id" \
  SUPPORT_BUNDLE_TEXT="$final_support_bundle_text" \
  CONSISTENCY_TEXT="$final_consistency_text" \
  CONSISTENCY_JSON="$final_consistency_json" \
  VERDICT_TEXT="$verdict_text" \
  python3 - "$OUTPUT_DIR/$prefix-report.json" <<'PY'
import json
import os
import sys

path = sys.argv[1]
payload = {
    "cycle": os.environ["PREFIX"],
    "preDevice": os.environ["PRE_DEVICE_LINE"],
    "boxId": os.environ["BOX_LINE"].removeprefix("BoxId: "),
    "canonicalDeviceId": os.environ["CANONICAL_ID"],
    "supportBundleSummary": os.environ["SUPPORT_BUNDLE_TEXT"],
    "consistencySummary": os.environ["CONSISTENCY_TEXT"],
    "consistencyJson": json.loads(os.environ["CONSISTENCY_JSON"]),
    "verdictSummary": os.environ["VERDICT_TEXT"],
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=2)
PY

  printf '%s\n' "$canonical_id"
}

echo "[Leona device E2E] serial    : $ADB_SERIAL"
echo "[Leona device E2E] output dir: $OUTPUT_DIR"
wait_for_device
setup_port_reverse

canonical_first="$(run_cycle first)"
canonical_second="$(run_cycle second)"

if [[ "$canonical_first" != "$canonical_second" ]]; then
  echo "Canonical device id changed across reinstall: $canonical_first != $canonical_second" >&2
  exit 1
fi

python3 - "$OUTPUT_DIR" "$ADB_SERIAL" "$canonical_first" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
serial = sys.argv[2]
canonical = sys.argv[3]
first = json.loads((out / "first-report.json").read_text())
second = json.loads((out / "second-report.json").read_text())

combined = {
    "deviceSerial": serial,
    "canonicalStableAcrossReinstall": canonical,
    "passes": {
        "temporaryBeforeSense": first["preDevice"].startswith("DeviceId: T") and second["preDevice"].startswith("DeviceId: T"),
        "canonicalAfterSense": first["canonicalDeviceId"].startswith("L") and second["canonicalDeviceId"].startswith("L"),
        "consistencyAligned": bool(first["consistencyJson"]["aligned"]) and bool(second["consistencyJson"]["aligned"]),
        "reinstallStable": first["canonicalDeviceId"] == second["canonicalDeviceId"] == canonical,
    },
    "cycles": [first, second],
}
(out / "report.json").write_text(json.dumps(combined, ensure_ascii=False, indent=2), encoding="utf-8")
(out / "report.md").write_text(
    "\n".join(
        [
            "# Leona device E2E report",
            "",
            f"- deviceSerial: `{serial}`",
            f"- canonicalStableAcrossReinstall: `{canonical}`",
            f"- temporaryBeforeSense: `{combined['passes']['temporaryBeforeSense']}`",
            f"- canonicalAfterSense: `{combined['passes']['canonicalAfterSense']}`",
            f"- consistencyAligned: `{combined['passes']['consistencyAligned']}`",
            f"- reinstallStable: `{combined['passes']['reinstallStable']}`",
            "",
            "## Cycles",
            "",
            *[
                "\n".join(
                    [
                        f"### {cycle['cycle']}",
                        f"- preDevice: `{cycle['preDevice']}`",
                        f"- boxId: `{cycle['boxId']}`",
                        f"- canonicalDeviceId: `{cycle['canonicalDeviceId']}`",
                        f"- supportBundleSummary: `{cycle['supportBundleSummary']}`",
                        f"- consistencySummary: `{cycle['consistencySummary']}`",
                        f"- verdictSummary: `{cycle['verdictSummary']}`",
                        "",
                    ]
                )
                for cycle in (first, second)
            ],
        ]
    ),
    encoding="utf-8",
)
PY

echo
echo "[Leona device E2E] canonical stable across reinstall: $canonical_first"
echo "[Leona device E2E] artifacts: $OUTPUT_DIR"
