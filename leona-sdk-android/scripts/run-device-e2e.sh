#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${OUTPUT_DIR:=/tmp/leona-device-e2e-$(date +%Y%m%d-%H%M%S)}"
: "${LEONA_REPORTING_ENDPOINT:=http://127.0.0.1:8080}"
: "${LEONA_FORMAL_VERDICT_BASE_URL:=http://127.0.0.1:8080}"
: "${LEONA_CLOUD_CONFIG_ENDPOINT:=http://127.0.0.1:8090/v1/mobile-config}"
: "${LEONA_DEMO_BACKEND_BASE_URL:=http://127.0.0.1:8090}"
: "${LEONA_ADMIN_BASE_URL:=http://127.0.0.1:8083}"
: "${LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY:=0}"
: "${SENSE_TIMEOUT_SEC:=30}"
: "${VERDICT_TIMEOUT_SEC:=20}"
: "${APP_ID:=io.leonasec.leona.sample}"
: "${APP_ACTIVITY:=.MainActivity}"
: "${LEONA_EXPECT_CLEAN_DEVICE:=0}"

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

ui_has_id() {
  local xml="$1"
  local id="$2"
  python3 - "$xml" "$id" <<'PY'
import sys, xml.etree.ElementTree as ET
xml_path, view_id = sys.argv[1:3]
root = ET.parse(xml_path).getroot()
for node in root.iter('node'):
    if node.attrib.get('resource-id') == view_id:
        raise SystemExit(0)
raise SystemExit(1)
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

init_screen_metrics() {
  read -r SCREEN_WIDTH SCREEN_HEIGHT < <(
    adb -s "$ADB_SERIAL" shell wm size 2>/dev/null | \
      awk '/Physical size:/ { split($3, a, "x"); print a[1], a[2]; exit }'
  )
  if [[ -z "${SCREEN_WIDTH:-}" || -z "${SCREEN_HEIGHT:-}" ]]; then
    SCREEN_WIDTH=1080
    SCREEN_HEIGHT=1920
  fi
  SWIPE_X=$(( SCREEN_WIDTH / 2 ))
  SWIPE_UP_START_Y=$(( SCREEN_HEIGHT * 8 / 10 ))
  SWIPE_UP_END_Y=$(( SCREEN_HEIGHT * 3 / 10 ))
  SWIPE_DOWN_START_Y=$(( SCREEN_HEIGHT * 3 / 10 ))
  SWIPE_DOWN_END_Y=$(( SCREEN_HEIGHT * 8 / 10 ))
}

scroll_forward() {
  adb -s "$ADB_SERIAL" shell input swipe \
    "$SWIPE_X" "$SWIPE_UP_START_Y" "$SWIPE_X" "$SWIPE_UP_END_Y" 220 >/dev/null
  sleep 1
}

scroll_backward() {
  adb -s "$ADB_SERIAL" shell input swipe \
    "$SWIPE_X" "$SWIPE_DOWN_START_Y" "$SWIPE_X" "$SWIPE_DOWN_END_Y" 220 >/dev/null
  sleep 1
}

scroll_to_top() {
  for _ in $(seq 1 6); do
    scroll_backward
  done
}

locate_view_xml() {
  local name="$1"
  local id="$2"
  local reset_to_top="${3:-1}"
  local max_scrolls="${4:-10}"

  if [[ "$reset_to_top" == "1" ]]; then
    scroll_to_top
  fi

  local attempt=0
  while [[ "$attempt" -le "$max_scrolls" ]]; do
    dump_ui "$name-$attempt"
    local xml="$OUTPUT_DIR/$name-$attempt.xml"
    if ui_has_id "$xml" "$id"; then
      printf '%s\n' "$xml"
      return 0
    fi
    if [[ "$attempt" -lt "$max_scrolls" ]]; then
      scroll_forward
    fi
    attempt=$(( attempt + 1 ))
  done

  echo "Unable to locate view $id after $max_scrolls scrolls" >&2
  return 1
}

read_view_with_scroll() {
  local name="$1"
  local id="$2"
  local reset_to_top="${3:-1}"
  local xml
  xml="$(locate_view_xml "$name" "$id" "$reset_to_top")"
  ui_value "$xml" "$id"
}

tap_view_with_scroll() {
  local name="$1"
  local id="$2"
  local reset_to_top="${3:-1}"
  local xml
  xml="$(locate_view_xml "$name" "$id" "$reset_to_top")"
  ui_tap "$xml" "$id"
  sleep 1
}

capture_json_section() {
  local base="$1"
  local toggle_id="$2"
  local text_id="$3"
  local output_path="$OUTPUT_DIR/$base.json"

  tap_view_with_scroll "$base-toggle" "$toggle_id" 1
  local value
  value="$(read_view_with_scroll "$base-text" "$text_id" 1)"
  if [[ -z "$value" || "$value" != \{* ]]; then
    echo "$base json is empty or malformed" >&2
    printf '%s\n' "$value" >&2
    exit 1
  fi
  printf '%s\n' "$value" > "$output_path"
  printf '%s\n' "$output_path"
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

build_config_value() {
  local key="$1"
  local build_config="$ROOT_DIR/sample-app/build/generated/source/buildConfig/debug/io/leonasec/leona/sample/BuildConfig.java"
  python3 - "$build_config" "$key" <<'PY'
import re
import sys

path, key = sys.argv[1:3]
text = open(path, "r", encoding="utf-8").read()
match = re.search(r'public static final String ' + re.escape(key) + r' = "(.*)";', text)
if not match:
    raise SystemExit(f"BuildConfig key missing: {key}")
print(bytes(match.group(1), "utf-8").decode("unicode_escape"))
PY
}

query_formal_verdict() {
  local box_id="$1"
  local secret="$2"
  local output_path="$3"
  FORMAL_BOX_ID="$box_id" \
  FORMAL_SECRET="$secret" \
  FORMAL_BASE_URL="$LEONA_FORMAL_VERDICT_BASE_URL" \
  FORMAL_OUTPUT_PATH="$output_path" \
  python3 <<'PY'
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

box_id = os.environ["FORMAL_BOX_ID"]
secret = os.environ["FORMAL_SECRET"]
base_url = os.environ["FORMAL_BASE_URL"].rstrip("/")
output_path = os.environ["FORMAL_OUTPUT_PATH"]

body = json.dumps({"boxId": box_id}, separators=(",", ":")).encode("utf-8")
timestamp = str(int(time.time() * 1000))
nonce = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii").rstrip("=")
body_hash = hashlib.sha256(body).hexdigest()
canonical = f"{timestamp}\n{nonce}\n{body_hash}".encode("utf-8")
signature = base64.urlsafe_b64encode(
    hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).digest()
).decode("ascii").rstrip("=")

request = urllib.request.Request(
    base_url + "/v1/verdict",
    data=body,
    method="POST",
    headers={
        "Authorization": "Bearer " + secret,
        "Content-Type": "application/json",
        "X-Leona-Timestamp": timestamp,
        "X-Leona-Nonce": nonce,
        "X-Leona-Signature": signature,
    },
)

try:
    with urllib.request.urlopen(request, timeout=15) as response:
        response_body = response.read()
        generated_at = response.headers.get("X-Leona-Verdict-Generated-At", "")
        response_sig = response.headers.get("X-Leona-Verdict-Signature", "")
except urllib.error.HTTPError as error:
    raise SystemExit(f"formal verdict failed: HTTP {error.code}: {error.read().decode('utf-8', 'replace')}")

if not generated_at or not response_sig:
    raise SystemExit("formal verdict response signature headers missing")

expected_sig = base64.urlsafe_b64encode(
    hmac.new(
        secret.encode("utf-8"),
        f"{generated_at}\n{hashlib.sha256(response_body).hexdigest()}".encode("utf-8"),
        hashlib.sha256,
    ).digest()
).decode("ascii").rstrip("=")
if not hmac.compare_digest(expected_sig, response_sig):
    raise SystemExit("formal verdict response signature mismatch")

payload = json.loads(response_body.decode("utf-8"))
with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=2)
    fh.write("\n")

canonical_device_id = payload.get("canonicalDeviceId") or ""
risk = payload.get("risk") or {}
print("formalBoxId=" + str(payload.get("boxId") or box_id))
print("formalCanonical=" + canonical_device_id)
print("formalRiskLevel=" + str(risk.get("level") or "-"))
print("formalRiskScore=" + str(risk.get("score") if risk.get("score") is not None else "-"))
print("formalSignatureVerified=true")
PY
}

install_sample() {
  LEONA_API_KEY="${LEONA_API_KEY:-}" \
  LEONA_SERVER_SECRET_KEY="${LEONA_SERVER_SECRET_KEY:-}" \
  LEONA_REPORTING_ENDPOINT="$LEONA_REPORTING_ENDPOINT" \
  LEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
  LEONA_DEMO_BACKEND_BASE_URL="$LEONA_DEMO_BACKEND_BASE_URL" \
  LEONA_ADMIN_BASE_URL="$LEONA_ADMIN_BASE_URL" \
  LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY="$LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY" \
  LEONA_TASK=installDebug \
  "$ROOT_DIR/scripts/run-live-sample.sh" >&2
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

  local pre_device_line
  pre_device_line="$(read_view_with_scroll "$prefix-home-device" "$APP_ID:id/deviceId" 1)"
  if [[ "$pre_device_line" != DeviceId:\ T* && "$pre_device_line" != DeviceId:\ L* ]]; then
    echo "Expected temporary or restored canonical device id before sense(), got: $pre_device_line" >&2
    exit 1
  fi

  tap_view_with_scroll "$prefix-sense-button" "$APP_ID:id/buttonSense" 1
  local box_line
  box_line="$(poll_for_boxid "$prefix")"

  local post_device_line support_bundle_text consistency_text
  post_device_line="$(read_view_with_scroll "$prefix-post-device" "$APP_ID:id/deviceId" 1)"
  support_bundle_text="$(read_view_with_scroll "$prefix-post-support-summary" "$APP_ID:id/supportBundleSummary" 1)"
  consistency_text="$(read_view_with_scroll "$prefix-post-consistency-summary" "$APP_ID:id/consistencySummary" 1)"

  if [[ "$post_device_line" != DeviceId:\ L* ]]; then
    echo "Expected canonical device id after sense(), got: $post_device_line" >&2
    exit 1
  fi
  require_contains "$support_bundle_text" 'effectiveDisabled=androidId' "$prefix supportBundleSummary"
  require_contains "$support_bundle_text" 'cloudRawPresent=true' "$prefix supportBundleSummary"
  require_contains "$consistency_text" 'aligned=true' "$prefix consistencySummary"

  tap_view_with_scroll "$prefix-verdict-button" "$APP_ID:id/buttonVerdict" 1
  local verdict_text
  verdict_text="$(poll_for_verdict "$prefix")"

  local final_device_line final_support_bundle_text final_consistency_text final_diagnostic_text
  final_device_line="$(read_view_with_scroll "$prefix-final-device" "$APP_ID:id/deviceId" 1)"
  final_support_bundle_text="$(read_view_with_scroll "$prefix-final-support-summary" "$APP_ID:id/supportBundleSummary" 1)"
  final_consistency_text="$(read_view_with_scroll "$prefix-final-consistency-summary" "$APP_ID:id/consistencySummary" 1)"
  final_diagnostic_text="$(read_view_with_scroll "$prefix-final-diagnostic-summary" "$APP_ID:id/diagnosticSummary" 1)"
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
  if [[ "$pre_device_line" == DeviceId:\ L* && "$pre_device_line" != "DeviceId: $canonical_id" ]]; then
    echo "Restored pre-sense canonical changed after sense(): $pre_device_line != DeviceId: $canonical_id" >&2
    exit 1
  fi

  local diagnostic_json_path consistency_json_path transport_json_path support_bundle_json_path verdict_json_path
  diagnostic_json_path="$(capture_json_section "$prefix-diagnostic" "$APP_ID:id/buttonToggleDiagnosticJson" "$APP_ID:id/diagnosticJson")"
  consistency_json_path="$(capture_json_section "$prefix-consistency" "$APP_ID:id/buttonToggleConsistencyJson" "$APP_ID:id/consistencyJson")"
  transport_json_path="$(capture_json_section "$prefix-transport" "$APP_ID:id/buttonToggleTransportJson" "$APP_ID:id/transportJson")"
  support_bundle_json_path="$(capture_json_section "$prefix-support-bundle" "$APP_ID:id/buttonToggleSupportBundle" "$APP_ID:id/supportBundleJson")"
  verdict_json_path="$(capture_json_section "$prefix-verdict" "$APP_ID:id/buttonToggleVerdictJson" "$APP_ID:id/verdictJson")"

  local formal_secret
  formal_secret="$(build_config_value LEONA_DEMO_VERDICT_SECRET_KEY)"
  if [[ -z "$formal_secret" ]]; then
    echo "Formal verdict secret missing from BuildConfig; enable LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 or pass LEONA_SERVER_SECRET_KEY." >&2
    exit 1
  fi

  launch_sample
  tap_view_with_scroll "$prefix-formal-sense-button" "$APP_ID:id/buttonSense" 1
  local formal_box_line formal_box_id formal_verdict_json_path formal_verdict_summary
  formal_box_line="$(poll_for_boxid "$prefix-formal")"
  formal_box_id="${formal_box_line#BoxId: }"
  formal_verdict_json_path="$OUTPUT_DIR/$prefix-formal-verdict.json"
  formal_verdict_summary="$(query_formal_verdict "$formal_box_id" "$formal_secret" "$formal_verdict_json_path")"

  PREFIX="$prefix" \
  PRE_DEVICE_LINE="$pre_device_line" \
  BOX_LINE="$box_line" \
  CANONICAL_ID="$canonical_id" \
  FORMAL_BOX_ID="$formal_box_id" \
  FORMAL_VERDICT_SUMMARY="$formal_verdict_summary" \
  SUPPORT_BUNDLE_TEXT="$final_support_bundle_text" \
  CONSISTENCY_TEXT="$final_consistency_text" \
  VERDICT_TEXT="$verdict_text" \
  DIAGNOSTIC_JSON_PATH="$diagnostic_json_path" \
  CONSISTENCY_JSON_PATH="$consistency_json_path" \
  TRANSPORT_JSON_PATH="$transport_json_path" \
  SUPPORT_BUNDLE_JSON_PATH="$support_bundle_json_path" \
  VERDICT_JSON_PATH="$verdict_json_path" \
  FORMAL_VERDICT_JSON_PATH="$formal_verdict_json_path" \
  EXPECT_CLEAN_DEVICE="$LEONA_EXPECT_CLEAN_DEVICE" \
  python3 - "$OUTPUT_DIR/$prefix-report.json" <<'PY'
import json
import os
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
prefix = os.environ["PREFIX"]
canonical = os.environ["CANONICAL_ID"]

def load_env_json(name: str):
    return json.loads(Path(os.environ[name]).read_text(encoding="utf-8"))

def require(condition: bool, message: str):
    if not condition:
        raise SystemExit(message)

def canonical_from_support_bundle_cloud_raw(raw):
    if isinstance(raw, dict):
        for value in (
            raw.get("canonicalDeviceId"),
            raw.get("device", {}).get("canonicalDeviceId"),
            raw.get("identity", {}).get("canonicalDeviceId"),
            raw.get("deviceIdentity", {}).get("canonicalDeviceId"),
            raw.get("deviceIdentity", {}).get("resolvedDeviceId"),
        ):
            if value:
                return value
    return None

def suspicious_hits(*collections):
    pattern = re.compile(r"(root|magisk|zygisk|xposed|frida|unidbg|hook|inject|su)", re.I)
    hits = []
    for collection in collections:
        for item in collection:
            if isinstance(item, str) and pattern.search(item):
                hits.append(item)
    return sorted(set(hits))

diagnostic = load_env_json("DIAGNOSTIC_JSON_PATH")
consistency = load_env_json("CONSISTENCY_JSON_PATH")
transport = load_env_json("TRANSPORT_JSON_PATH")
support_bundle = load_env_json("SUPPORT_BUNDLE_JSON_PATH")
verdict = load_env_json("VERDICT_JSON_PATH")
formal_verdict = load_env_json("FORMAL_VERDICT_JSON_PATH")

transport_canonical = transport.get("session", {}).get("canonicalDeviceId")
bundle_diagnostic_canonical = support_bundle.get("diagnosticSnapshot", {}).get("canonicalDeviceId")
bundle_transport_canonical = support_bundle.get("secureTransport", {}).get("session", {}).get("canonicalDeviceId")
bundle_verdict_canonical = support_bundle.get("serverVerdict", {}).get("canonicalDeviceId")
cloud_raw = support_bundle.get("cloudConfigRaw")
cloud_raw_canonical = canonical_from_support_bundle_cloud_raw(cloud_raw)
formal_verdict_canonical = (formal_verdict.get("canonicalDeviceId") or "").strip()
formal_verdict_fingerprint = (formal_verdict.get("deviceFingerprint") or "").strip()
formal_signature_verified = "formalSignatureVerified=true" in os.environ["FORMAL_VERDICT_SUMMARY"]

require(diagnostic.get("canonicalDeviceId") == canonical, f"{prefix}: diagnostic canonical mismatch")
require(consistency.get("aligned") is True, f"{prefix}: consistency json not aligned")
require(consistency.get("diagnosticCanonical") == canonical, f"{prefix}: consistency diagnostic canonical mismatch")
require(consistency.get("transportCanonical") == canonical, f"{prefix}: consistency transport canonical mismatch")
require(consistency.get("verdictCanonical") == canonical, f"{prefix}: consistency verdict canonical mismatch")
require(consistency.get("bundleCanonical") == canonical, f"{prefix}: consistency bundle canonical mismatch")
require(transport_canonical == canonical, f"{prefix}: transport canonical mismatch")
require(verdict.get("canonicalDeviceId") == canonical, f"{prefix}: verdict canonical mismatch")
require(bundle_diagnostic_canonical == canonical, f"{prefix}: support bundle diagnostic canonical mismatch")
require(bundle_transport_canonical == canonical, f"{prefix}: support bundle transport canonical mismatch")
require(bundle_verdict_canonical == canonical, f"{prefix}: support bundle verdict canonical mismatch")
require(support_bundle.get("cloudConfigFetchedAtMillis") is not None, f"{prefix}: cloud config fetchedAt missing")
require(bool(cloud_raw), f"{prefix}: cloud config raw missing")
require("androidId" in support_bundle.get("effectiveDisabledSignals", []), f"{prefix}: effectiveDisabledSignals missing androidId")
require("androidId" in consistency.get("effectiveDisabledSignals", []), f"{prefix}: consistency effectiveDisabledSignals missing androidId")
require(consistency.get("cloudConfigRawPresent") is True, f"{prefix}: consistency cloudConfigRawPresent is false")
require(cloud_raw_canonical == canonical, f"{prefix}: cloud config raw canonical mismatch")
require(formal_verdict_canonical == canonical, f"{prefix}: formal verdict canonical mismatch")
require(bool(formal_verdict_fingerprint), f"{prefix}: formal verdict deviceFingerprint missing")
require(formal_signature_verified, f"{prefix}: formal verdict signature verification missing")

clean_hits = suspicious_hits(
    diagnostic.get("localRiskSignals", []),
    diagnostic.get("nativeRiskTags", []),
    diagnostic.get("nativeFindingIds", []),
    diagnostic.get("serverRiskTags", []),
)
clean_expected = os.environ.get("EXPECT_CLEAN_DEVICE") == "1"
require(not clean_expected or not clean_hits, f"{prefix}: clean-device regression detected: {', '.join(clean_hits)}")

payload = {
    "cycle": prefix,
    "preDevice": os.environ["PRE_DEVICE_LINE"],
    "preSenseDeviceKind": "canonical" if os.environ["PRE_DEVICE_LINE"].startswith("DeviceId: L") else "temporary",
    "boxId": os.environ["BOX_LINE"].removeprefix("BoxId: "),
    "formalVerdictBoxId": os.environ["FORMAL_BOX_ID"],
    "canonicalDeviceId": canonical,
    "supportBundleSummary": os.environ["SUPPORT_BUNDLE_TEXT"],
    "consistencySummary": os.environ["CONSISTENCY_TEXT"],
    "verdictSummary": os.environ["VERDICT_TEXT"],
    "formalVerdictSummary": os.environ["FORMAL_VERDICT_SUMMARY"],
    "diagnosticJson": diagnostic,
    "transportJson": transport,
    "consistencyJson": consistency,
    "supportBundleJson": support_bundle,
    "verdictJson": verdict,
    "formalVerdictJson": formal_verdict,
    "jsonChecks": {
        "diagnosticCanonical": diagnostic.get("canonicalDeviceId"),
        "transportCanonical": transport_canonical,
        "bundleDiagnosticCanonical": bundle_diagnostic_canonical,
        "bundleTransportCanonical": bundle_transport_canonical,
        "bundleVerdictCanonical": bundle_verdict_canonical,
        "verdictCanonical": verdict.get("canonicalDeviceId"),
        "formalVerdictCanonical": formal_verdict_canonical,
        "formalVerdictFingerprintPresent": bool(formal_verdict_fingerprint),
        "formalVerdictSignatureVerified": formal_signature_verified,
        "cloudConfigRawCanonical": cloud_raw_canonical,
        "cloudConfigFetchedAtPresent": support_bundle.get("cloudConfigFetchedAtMillis") is not None,
        "cloudConfigRawPresent": bool(cloud_raw),
        "effectiveDisabledSignals": support_bundle.get("effectiveDisabledSignals", []),
        "cleanDeviceExpected": clean_expected,
        "cleanDeviceSuspiciousHits": clean_hits,
        "preSenseDeviceAccepted": os.environ["PRE_DEVICE_LINE"].startswith(("DeviceId: T", "DeviceId: L")),
        "preSenseCanonicalRestored": os.environ["PRE_DEVICE_LINE"].startswith("DeviceId: L"),
    },
}
path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
PY

  {
    echo "[$prefix]"
    echo "preDevice=$pre_device_line"
    echo "boxId=$box_line"
    echo "canonical=$canonical_id"
    echo "formalVerdictBoxId=$formal_box_id"
    echo "supportBundle=$final_support_bundle_text"
    echo "consistency=$final_consistency_text"
    echo "verdict=$verdict_text"
    echo "formalVerdict=$formal_verdict_summary"
    echo "diagnosticJson=$diagnostic_json_path"
    echo "transportJson=$transport_json_path"
    echo "supportBundleJson=$support_bundle_json_path"
    echo "verdictJson=$verdict_json_path"
    echo "formalVerdictJson=$formal_verdict_json_path"
    echo
  } > "$OUTPUT_DIR/$prefix-summary.txt"

  printf '%s\n' "$canonical_id"
}

echo "[Leona device E2E] serial    : $ADB_SERIAL"
echo "[Leona device E2E] output dir: $OUTPUT_DIR"
wait_for_device
init_screen_metrics
setup_port_reverse

canonical_first="$(run_cycle first)"
canonical_second="$(run_cycle second)"

if [[ "$canonical_first" != "$canonical_second" ]]; then
  echo "Canonical device id changed across reinstall: $canonical_first != $canonical_second" >&2
  exit 1
fi

python3 - "$OUTPUT_DIR" "$ADB_SERIAL" "$canonical_first" "$LEONA_EXPECT_CLEAN_DEVICE" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
serial = sys.argv[2]
canonical = sys.argv[3]
expect_clean = sys.argv[4] == "1"
first = json.loads((out / "first-report.json").read_text())
second = json.loads((out / "second-report.json").read_text())

def compact(text):
    return "; ".join(line.strip() for line in str(text).splitlines() if line.strip())

combined = {
    "deviceSerial": serial,
    "canonicalStableAcrossReinstall": canonical,
    "passes": {
        "temporaryBeforeSense": first["preDevice"].startswith("DeviceId: T") and second["preDevice"].startswith("DeviceId: T"),
        "preSenseDeviceAccepted": first["jsonChecks"]["preSenseDeviceAccepted"] and second["jsonChecks"]["preSenseDeviceAccepted"],
        "preSenseCanonicalRestored": first["jsonChecks"]["preSenseCanonicalRestored"] or second["jsonChecks"]["preSenseCanonicalRestored"],
        "canonicalAfterSense": first["canonicalDeviceId"].startswith("L") and second["canonicalDeviceId"].startswith("L"),
        "consistencyAligned": bool(first["consistencyJson"]["aligned"]) and bool(second["consistencyJson"]["aligned"]),
        "jsonSurfaceAligned": all(
            cycle["jsonChecks"][name] == cycle["canonicalDeviceId"]
            for cycle in (first, second)
            for name in (
                "diagnosticCanonical",
                "transportCanonical",
                "bundleDiagnosticCanonical",
                "bundleTransportCanonical",
                "bundleVerdictCanonical",
                "verdictCanonical",
                "formalVerdictCanonical",
                "cloudConfigRawCanonical",
            )
        ),
        "formalVerdictSignatureVerified": all(
            cycle["jsonChecks"]["formalVerdictSignatureVerified"]
            for cycle in (first, second)
        ),
        "formalVerdictFingerprintPresent": all(
            cycle["jsonChecks"]["formalVerdictFingerprintPresent"]
            for cycle in (first, second)
        ),
        "cloudConfigEvidencePresent": all(
            cycle["jsonChecks"]["cloudConfigFetchedAtPresent"] and cycle["jsonChecks"]["cloudConfigRawPresent"]
            and "androidId" in cycle["jsonChecks"]["effectiveDisabledSignals"]
            for cycle in (first, second)
        ),
        "reinstallStable": first["canonicalDeviceId"] == second["canonicalDeviceId"] == canonical,
        "cleanDeviceRegressionFree": all(
            not cycle["jsonChecks"]["cleanDeviceSuspiciousHits"]
            for cycle in (first, second)
        ) if expect_clean else None,
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
            f"- preSenseDeviceAccepted: `{combined['passes']['preSenseDeviceAccepted']}`",
            f"- preSenseCanonicalRestored: `{combined['passes']['preSenseCanonicalRestored']}`",
            f"- canonicalAfterSense: `{combined['passes']['canonicalAfterSense']}`",
            f"- consistencyAligned: `{combined['passes']['consistencyAligned']}`",
            f"- jsonSurfaceAligned: `{combined['passes']['jsonSurfaceAligned']}`",
            f"- formalVerdictSignatureVerified: `{combined['passes']['formalVerdictSignatureVerified']}`",
            f"- formalVerdictFingerprintPresent: `{combined['passes']['formalVerdictFingerprintPresent']}`",
            f"- cloudConfigEvidencePresent: `{combined['passes']['cloudConfigEvidencePresent']}`",
            f"- reinstallStable: `{combined['passes']['reinstallStable']}`",
            f"- cleanDeviceRegressionFree: `{combined['passes']['cleanDeviceRegressionFree'] if expect_clean else 'skipped'}`",
            "",
            "## Cycles",
            "",
            *[
                "\n".join(
                    [
                        f"### {cycle['cycle']}",
                        f"- preDevice: `{cycle['preDevice']}`",
                        f"- preSenseDeviceKind: `{cycle['preSenseDeviceKind']}`",
                        f"- boxId: `{cycle['boxId']}`",
                        f"- formalVerdictBoxId: `{cycle['formalVerdictBoxId']}`",
                        f"- canonicalDeviceId: `{cycle['canonicalDeviceId']}`",
                        f"- supportBundleSummary: `{cycle['supportBundleSummary']}`",
                        f"- consistencySummary: `{cycle['consistencySummary']}`",
                        f"- verdictSummary: `{cycle['verdictSummary']}`",
                        f"- formalVerdictSummary: `{compact(cycle['formalVerdictSummary'])}`",
                        f"- cleanDeviceSuspiciousHits: `{','.join(cycle['jsonChecks']['cleanDeviceSuspiciousHits']) or '-'}`",
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
