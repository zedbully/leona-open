#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${ADB_SERIAL:=emulator-5554}"
: "${OUTPUT_DIR:=/tmp/leona-attestation-e2e-$(date +%Y%m%d-%H%M%S)}"
: "${APP_ID:=io.leonasec.leona.sample}"
: "${APP_ACTIVITY:=.MainActivity}"
: "${LEONA_HOST_BASE_URL:=http://127.0.0.1:8080}"
: "${LEONA_REPORTING_ENDPOINT:=http://10.0.2.2:8080}"
: "${LEONA_CLOUD_CONFIG_ENDPOINT:=}"
: "${LEONA_DEMO_BACKEND_BASE_URL:=}"
: "${LEONA_SAMPLE_ATTESTATION_MODE:=debug_fake}"
: "${LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER:=1234567890123}"
: "${LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP:=false}"
: "${LEONA_SDK_VERSION:=0.1.0-alpha.1}"
: "${SENSE_TIMEOUT_SEC:=30}"

if [[ -z "${LEONA_API_KEY:-}" ]]; then
  echo "LEONA_API_KEY is required" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

SUPPORTED_ATTESTATION_MODES=(debug_fake oem_debug_fake)

attestation_expectations() {
  case "$LEONA_SAMPLE_ATTESTATION_MODE" in
    debug_fake)
      EXPECTED_ATTESTATION_FORMAT="play_integrity"
      EXPECTED_ATTESTATION_PROVIDER="play_integrity"
      EXPECTED_ATTESTATION_STATUS="play_integrity/MEETS_DEVICE_INTEGRITY"
      EXPECTED_ATTESTATION_CODE="PLAY_INTEGRITY_VERIFIED"
      EXPECTED_DEVICE_BINDING_STATUS="bound-software/play_integrity/MEETS_DEVICE_INTEGRITY"
      ;;
    oem_debug_fake)
      EXPECTED_ATTESTATION_FORMAT="oem_attestation"
      EXPECTED_ATTESTATION_PROVIDER="sample_mainland_debug"
      EXPECTED_ATTESTATION_STATUS="oem_attestation/oem_attested"
      EXPECTED_ATTESTATION_CODE="OEM_ATTESTATION_VERIFIED"
      EXPECTED_DEVICE_BINDING_STATUS="bound-software/oem_attestation/oem_attested"
      ;;
    *)
      echo "Unsupported automated attestation mode: $LEONA_SAMPLE_ATTESTATION_MODE" >&2
      echo "Supported modes: ${SUPPORTED_ATTESTATION_MODES[*]}" >&2
      exit 1
      ;;
  esac
}

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "Missing required command: $cmd" >&2
    exit 1
  }
}

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
import re, sys, xml.etree.ElementTree as ET
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
  local deadline=$(( $(date +%s) + SENSE_TIMEOUT_SEC ))
  while [[ $(date +%s) -lt $deadline ]]; do
    dump_ui sense-state >/dev/null 2>&1 || true
    local text
    text="$(ui_value "$OUTPUT_DIR/sense-state.xml" "$APP_ID:id/boxId")"
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

verify_server_handshake_surface() {
  local request_path="$OUTPUT_DIR/handshake-request.json"
  local response_path="$OUTPUT_DIR/handshake-response.json"
  local headers_path="$OUTPUT_DIR/handshake-response.headers"

  LEONA_SDK_VERSION="$LEONA_SDK_VERSION" node - <<'NODE' > "$request_path"
const crypto = require('crypto');
const installId = `attestation-e2e-${Date.now()}`;
const sdkVersion = process.env.LEONA_SDK_VERSION || '0.1.0-alpha.1';
const { publicKey: xPub } = crypto.generateKeyPairSync('x25519');
const xDer = xPub.export({ format: 'der', type: 'spki' });
const clientPublicKey = xDer.subarray(-32).toString('base64url');
const { publicKey: ecPub, privateKey: ecPriv } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const bindingPublicKey = ecPub.export({ format: 'der', type: 'spki' }).toString('base64url');
const challenge = crypto.createHash('sha256').update(`${installId}\n${sdkVersion}\n${clientPublicKey}`, 'utf8').digest('hex');
const attestationMode = (process.env.LEONA_SAMPLE_ATTESTATION_MODE || 'debug_fake').trim().toLowerCase();
let attestationFormat = 'play_integrity';
let attestationToken;
if (attestationMode === 'oem_debug_fake') {
  attestationFormat = 'oem_attestation';
  attestationToken = JSON.stringify({
    version: 1,
    provider: 'sample_mainland_debug',
    trustTier: 'oem_attested',
    issuedAtMillis: Date.now(),
    challenge,
    installId,
    packageName: 'io.leonasec.leona.sample',
    evidenceLabels: ['debug_fake', 'non_gms_sample'],
    claims: { manufacturer: 'Google', model: 'Android SDK built for x86_64', sdkInt: '34' },
    mode: 'oem_debug_fake',
  });
} else {
  attestationToken = JSON.stringify({
    requestDetails: { requestHash: challenge, timestampMillis: Date.now() },
    appIntegrity: { appRecognitionVerdict: 'PLAY_RECOGNIZED' },
    deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_DEVICE_INTEGRITY'] },
    mode: 'debug_fake',
    installId,
    cloudProjectNumber: 1234567890123,
  });
}
const tokenHash = crypto.createHash('sha256').update(attestationToken, 'utf8').digest('hex');
const canonical = `${installId}\n${sdkVersion}\n${clientPublicKey}\n${bindingPublicKey}\n0\n${attestationFormat}\n${tokenHash}`;
const signer = crypto.createSign('sha256');
signer.update(canonical, 'utf8');
signer.end();
const signature = signer.sign(ecPriv).toString('base64url');
process.stdout.write(JSON.stringify({
  clientPublicKey,
  installId,
  sdkVersion,
  deviceBinding: {
    keyAlgorithm: 'EC_P256',
    publicKey: bindingPublicKey,
    signatureAlgorithm: 'SHA256withECDSA',
    signature,
    hardwareBacked: false,
    attestationFormat,
    attestationToken,
  },
}, null, 2));
NODE

  curl -sS -D "$headers_path" -o "$response_path" \
    -H 'Content-Type: application/json' \
    -H "X-Leona-App-Key: $LEONA_API_KEY" \
    --data @"$request_path" \
    "$LEONA_HOST_BASE_URL/v1/handshake"

  EXPECTED_DEVICE_BINDING_STATUS="$EXPECTED_DEVICE_BINDING_STATUS" \
  EXPECTED_ATTESTATION_PROVIDER="$EXPECTED_ATTESTATION_PROVIDER" \
  EXPECTED_ATTESTATION_STATUS="$EXPECTED_ATTESTATION_STATUS" \
  EXPECTED_ATTESTATION_CODE="$EXPECTED_ATTESTATION_CODE" \
  python3 - "$response_path" <<'PY'
import json, os, sys
path = sys.argv[1]
data = json.load(open(path, encoding='utf-8'))
expected_status = os.environ['EXPECTED_DEVICE_BINDING_STATUS']
expected = {
    'provider': os.environ['EXPECTED_ATTESTATION_PROVIDER'],
    'status': os.environ['EXPECTED_ATTESTATION_STATUS'],
    'code': os.environ['EXPECTED_ATTESTATION_CODE'],
    'retryable': False,
}
if data.get('deviceBindingStatus') != expected_status:
    raise SystemExit(f"deviceBindingStatus mismatch: {data.get('deviceBindingStatus')}")
attestation = data.get('attestation') or {}
for key, value in expected.items():
    if attestation.get(key) != value:
        raise SystemExit(f"attestation.{key} mismatch: {attestation.get(key)!r} != {value!r}")
PY
}

install_sample() {
  LEONA_API_KEY="$LEONA_API_KEY" \
  LEONA_REPORTING_ENDPOINT="$LEONA_REPORTING_ENDPOINT" \
  LEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
  LEONA_DEMO_BACKEND_BASE_URL="$LEONA_DEMO_BACKEND_BASE_URL" \
  LEONA_SAMPLE_ATTESTATION_MODE="$LEONA_SAMPLE_ATTESTATION_MODE" \
  LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER="$LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER" \
  LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP="$LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP" \
  LEONA_TASK=installDebug \
  "$ROOT_DIR/scripts/run-live-sample.sh"
}

launch_sample() {
  adb -s "$ADB_SERIAL" shell am force-stop "$APP_ID"
  adb -s "$ADB_SERIAL" logcat -c
  adb -s "$ADB_SERIAL" shell am start -n "$APP_ID/$APP_ACTIVITY" >/dev/null
  sleep 3
}

validate_android_surface() {
  local box_line transport_summary support_summary

  tap_view_with_scroll "sense-button" "$APP_ID:id/buttonSense" 1
  box_line="$(poll_for_boxid)"
  transport_summary="$(read_view_with_scroll "transport-summary" "$APP_ID:id/transportSummary" 1)"
  support_summary="$(read_view_with_scroll "support-summary" "$APP_ID:id/supportBundleSummary" 1)"

  require_contains "$transport_summary" "sessionBindingStatus=$EXPECTED_DEVICE_BINDING_STATUS" 'transportSummary'
  require_contains "$transport_summary" "serverAttestationProvider=$EXPECTED_ATTESTATION_PROVIDER" 'transportSummary'
  require_contains "$transport_summary" "serverAttestationStatus=$EXPECTED_ATTESTATION_STATUS" 'transportSummary'
  require_contains "$transport_summary" "serverAttestationCode=$EXPECTED_ATTESTATION_CODE" 'transportSummary'
  require_contains "$transport_summary" 'serverAttestationRetryable=false' 'transportSummary'
  require_contains "$support_summary" "transportBindingStatus=$EXPECTED_DEVICE_BINDING_STATUS" 'supportBundleSummary'
  require_contains "$support_summary" "serverAttestationProvider=$EXPECTED_ATTESTATION_PROVIDER" 'supportBundleSummary'
  require_contains "$support_summary" "serverAttestationStatus=$EXPECTED_ATTESTATION_STATUS" 'supportBundleSummary'
  require_contains "$support_summary" "serverAttestationCode=$EXPECTED_ATTESTATION_CODE" 'supportBundleSummary'

  local transport_json_path support_bundle_json_path
  transport_json_path="$(capture_json_section "transport" "$APP_ID:id/buttonToggleTransportJson" "$APP_ID:id/transportJson")"
  support_bundle_json_path="$(capture_json_section "support-bundle" "$APP_ID:id/buttonToggleSupportBundle" "$APP_ID:id/supportBundleJson")"

  BOX_LINE="$box_line" \
  LEONA_SAMPLE_ATTESTATION_MODE="$LEONA_SAMPLE_ATTESTATION_MODE" \
  TRANSPORT_SUMMARY="$transport_summary" \
  SUPPORT_SUMMARY="$support_summary" \
  TRANSPORT_JSON_PATH="$transport_json_path" \
  SUPPORT_BUNDLE_JSON_PATH="$support_bundle_json_path" \
  HANDSHAKE_JSON_PATH="$OUTPUT_DIR/handshake-response.json" \
  python3 - "$OUTPUT_DIR/attestation-e2e-report.json" <<'PY'
import json, os, sys
from pathlib import Path

report_path = Path(sys.argv[1])
handshake = json.loads(Path(os.environ["HANDSHAKE_JSON_PATH"]).read_text(encoding="utf-8"))
transport = json.loads(Path(os.environ["TRANSPORT_JSON_PATH"]).read_text(encoding="utf-8"))
support_bundle = json.loads(Path(os.environ["SUPPORT_BUNDLE_JSON_PATH"]).read_text(encoding="utf-8"))

def require(condition: bool, message: str):
    if not condition:
        raise SystemExit(message)

session = transport.get("session") or {}
server_attestation = session.get("serverAttestation") or {}
bundle_transport = ((support_bundle.get("secureTransport") or {}).get("session") or {})
bundle_attestation = bundle_transport.get("serverAttestation") or {}
handshake_attestation = handshake.get("attestation") or {}

require(session.get("deviceBindingStatus") == handshake.get("deviceBindingStatus"), "transport session.deviceBindingStatus mismatch")
require(bundle_transport.get("deviceBindingStatus") == handshake.get("deviceBindingStatus"), "support bundle session.deviceBindingStatus mismatch")

for key in ("provider", "status", "code", "retryable"):
    require(server_attestation.get(key) == handshake_attestation.get(key), f"transport serverAttestation.{key} mismatch")
    require(bundle_attestation.get(key) == handshake_attestation.get(key), f"support bundle serverAttestation.{key} mismatch")

require(transport.get("lastHandshakeError") is None, "lastHandshakeError should be null on success")

payload = {
    "attestationMode": os.environ.get("LEONA_SAMPLE_ATTESTATION_MODE", ""),
    "boxId": os.environ["BOX_LINE"].removeprefix("BoxId: "),
    "serverHandshake": handshake,
    "transportSummary": os.environ["TRANSPORT_SUMMARY"],
    "supportBundleSummary": os.environ["SUPPORT_SUMMARY"],
    "transportJson": transport,
    "supportBundleJson": support_bundle,
    "checks": {
        "transportBindingStatus": session.get("deviceBindingStatus"),
        "supportBundleBindingStatus": bundle_transport.get("deviceBindingStatus"),
        "transportServerAttestation": server_attestation,
        "supportBundleServerAttestation": bundle_attestation,
    },
}
report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
PY
}

echo "[Leona attestation E2E] serial      : $ADB_SERIAL"
echo "[Leona attestation E2E] output dir  : $OUTPUT_DIR"
echo "[Leona attestation E2E] host base   : $LEONA_HOST_BASE_URL"
echo "[Leona attestation E2E] app base    : $LEONA_REPORTING_ENDPOINT"
echo "[Leona attestation E2E] mode        : $LEONA_SAMPLE_ATTESTATION_MODE"

require_cmd adb
require_cmd curl
require_cmd python3
require_cmd node

attestation_expectations
wait_for_device
init_screen_metrics
verify_server_handshake_surface
adb -s "$ADB_SERIAL" uninstall "$APP_ID" >/dev/null 2>&1 || true
install_sample
launch_sample
validate_android_surface

printf '\n[Leona attestation E2E] handshake response: %s\n' "$OUTPUT_DIR/handshake-response.json"
printf '[Leona attestation E2E] report:             %s\n' "$OUTPUT_DIR/attestation-e2e-report.json"
