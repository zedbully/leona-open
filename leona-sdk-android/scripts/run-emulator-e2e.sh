#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${ADB_SERIAL:=emulator-5554}"
: "${OUTPUT_DIR:=/tmp/leona-e2e-$(date +%Y%m%d-%H%M%S)}"
: "${LEONA_REPORTING_ENDPOINT:=http://10.0.2.2:8080}"
: "${LEONA_FORMAL_VERDICT_BASE_URL:=http://127.0.0.1:8080}"
: "${LEONA_CLOUD_CONFIG_ENDPOINT:=http://10.0.2.2:8090/v1/mobile-config}"
: "${LEONA_DEMO_BACKEND_BASE_URL:=http://10.0.2.2:8090}"
: "${LEONA_ADMIN_BASE_URL:=http://127.0.0.1:8083}"
: "${LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY:=0}"
: "${LEONA_SAMPLE_ATTESTATION_MODE:=oem_debug_fake}"
: "${SENSE_TIMEOUT_SEC:=30}"
: "${VERDICT_TIMEOUT_SEC:=20}"
: "${APP_ID:=io.leonasec.leona.sample}"
: "${APP_ACTIVITY:=.MainActivity}"

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
  local reset_to_top="${4:-1}"
  local output_path="$OUTPUT_DIR/$base.json"

  tap_view_with_scroll "$base-toggle" "$toggle_id" "$reset_to_top"
  local value
  value="$(read_view_with_scroll "$base-text" "$text_id" 0)"
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

poll_for_new_boxid() {
  local old_box_id="$1"
  local deadline=$(( $(date +%s) + SENSE_TIMEOUT_SEC ))
  while [[ $(date +%s) -lt $deadline ]]; do
    dump_ui sense-state >/dev/null 2>&1 || true
    local text
    text="$(ui_value "$OUTPUT_DIR/sense-state.xml" 'io.leonasec.leona.sample:id/boxId')"
    if [[ "$text" == BoxId:\ * && "$text" != "BoxId: (not yet run)" ]]; then
      local current="${text#BoxId: }"
      if [[ "$current" != "$old_box_id" ]]; then
        echo "$text"
        return 0
      fi
    fi
    if [[ "$text" == BoxId\ error:* ]]; then
      echo "$text" >&2
      return 1
    fi
    sleep 2
  done
  echo "Timed out waiting for a new BoxId" >&2
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
init_screen_metrics

adb -s "$ADB_SERIAL" uninstall "$APP_ID" >/dev/null 2>&1 || true

LEONA_API_KEY="${LEONA_API_KEY:-}" \
LEONA_REPORTING_ENDPOINT="$LEONA_REPORTING_ENDPOINT" \
LEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
LEONA_DEMO_BACKEND_BASE_URL="$LEONA_DEMO_BACKEND_BASE_URL" \
LEONA_ADMIN_BASE_URL="$LEONA_ADMIN_BASE_URL" \
LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY="$LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY" \
LEONA_SAMPLE_ATTESTATION_MODE="$LEONA_SAMPLE_ATTESTATION_MODE" \
LEONA_TASK=installDebug \
"$ROOT_DIR/scripts/run-live-sample.sh"

adb -s "$ADB_SERIAL" shell am force-stop "$APP_ID"
adb -s "$ADB_SERIAL" logcat -c
adb -s "$ADB_SERIAL" shell am start -n "$APP_ID/$APP_ACTIVITY" >/dev/null
sleep 3

pre_device_line="$(read_view_with_scroll pre-device "$APP_ID:id/deviceId" 1)"
if [[ -n "$LEONA_CLOUD_CONFIG_ENDPOINT" ]]; then
  if [[ "$pre_device_line" != DeviceId:\ T* && "$pre_device_line" != DeviceId:\ L* ]]; then
    echo "Expected device id before sense() to be temporary or canonical, got: $pre_device_line" >&2
    exit 1
  fi
elif [[ "$pre_device_line" != DeviceId:\ T* ]]; then
  echo "Expected temporary device id before sense(), got: $pre_device_line" >&2
  exit 1
fi

tap_view_with_scroll home "$APP_ID:id/buttonSense" 1
box_line="$(poll_for_boxid)"
box_id="${box_line#BoxId: }"

transport_json_path="$(capture_json_section post-transport "$APP_ID:id/buttonToggleTransportJson" "$APP_ID:id/transportJson" 0)"

post_verdict_xml="$(locate_view_xml post-sense "$APP_ID:id/buttonVerdict" 0)"
button_enabled="$(ui_enabled "$post_verdict_xml" "$APP_ID:id/buttonVerdict")"
if [[ "$button_enabled" != "true" ]]; then
  echo "Verdict button is not enabled after sense(): $button_enabled" >&2
  exit 1
fi

tap_view_with_scroll post-verdict "$APP_ID:id/buttonVerdict" 0
verdict_text="$(poll_for_verdict)"

support_bundle_json_path="$(capture_json_section final-support-bundle "$APP_ID:id/buttonToggleSupportBundle" "$APP_ID:id/supportBundleJson" 0)"
verdict_json_path="$(capture_json_section final-verdict "$APP_ID:id/buttonToggleVerdictJson" "$APP_ID:id/verdictJson" 0)"

validation_exports="$(
  TRANSPORT_JSON_PATH="$transport_json_path" \
  SUPPORT_BUNDLE_JSON_PATH="$support_bundle_json_path" \
  VERDICT_JSON_PATH="$verdict_json_path" \
  LEONA_CLOUD_CONFIG_ENDPOINT="$LEONA_CLOUD_CONFIG_ENDPOINT" \
  VERDICT_TEXT="$verdict_text" \
  python3 <<'PY'
import json
import os
import shlex

def load(path_env: str):
    with open(os.environ[path_env], "r", encoding="utf-8") as fh:
        return json.load(fh)

def first_non_blank(*values):
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None

def nested(obj, *keys):
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur

def verdict_canonical(obj):
    return first_non_blank(
        obj.get("canonicalDeviceId"),
        nested(obj, "device", "canonicalDeviceId"),
        nested(obj, "device", "deviceId"),
        nested(obj, "identity", "canonicalDeviceId"),
        nested(obj, "identity", "deviceId"),
        nested(obj, "deviceIdentity", "canonicalDeviceId"),
        nested(obj, "deviceIdentity", "deviceId"),
        nested(obj, "deviceIdentity", "resolvedDeviceId"),
    )

def cloud_canonical(obj):
    return first_non_blank(
        nested(obj, "cloudConfigRaw", "canonicalDeviceId"),
        nested(obj, "cloudConfigRaw", "device", "canonicalDeviceId"),
        nested(obj, "cloudConfigRaw", "device", "deviceId"),
        nested(obj, "cloudConfigRaw", "identity", "canonicalDeviceId"),
        nested(obj, "cloudConfigRaw", "identity", "deviceId"),
        nested(obj, "cloudConfigRaw", "deviceIdentity", "canonicalDeviceId"),
        nested(obj, "cloudConfigRaw", "deviceIdentity", "deviceId"),
        nested(obj, "cloudConfigRaw", "deviceIdentity", "resolvedDeviceId"),
    )

transport = load("TRANSPORT_JSON_PATH")
support = load("SUPPORT_BUNDLE_JSON_PATH")
verdict = load("VERDICT_JSON_PATH")

canonical = first_non_blank(
    nested(support, "diagnosticSnapshot", "canonicalDeviceId"),
    nested(support, "diagnosticSnapshot", "deviceId"),
    cloud_canonical(support),
    nested(support, "secureTransport", "session", "canonicalDeviceId"),
    verdict_canonical(verdict),
    nested(transport, "session", "canonicalDeviceId"),
)
if not canonical:
    raise SystemExit("Unable to resolve canonical device id from support/transport/verdict json")

if not canonical.startswith("L"):
    raise SystemExit(f"Expected canonical device id to start with L, got: {canonical}")

transport_canonical = nested(transport, "session", "canonicalDeviceId")
if transport_canonical and transport_canonical != canonical:
    raise SystemExit(f"transport canonical mismatch: {transport_canonical} != {canonical}")

binding_present = nested(transport, "deviceBinding", "present")
if binding_present is not True:
    raise SystemExit(f"device binding missing from transport snapshot: {binding_present}")

last_handshake_error = transport.get("lastHandshakeError")
if isinstance(last_handshake_error, str) and last_handshake_error.strip() not in ("", "-"):
    raise SystemExit(f"transport lastHandshakeError not cleared: {last_handshake_error}")

effective_disabled = sorted(support.get("effectiveDisabledSignals") or [])
cloud_raw = support.get("cloudConfigRaw")
cloud_fetched_at = support.get("cloudConfigFetchedAtMillis")
bundle_transport_canonical = nested(support, "secureTransport", "session", "canonicalDeviceId")
bundle_verdict_canonical = nested(support, "serverVerdict", "canonicalDeviceId")
bundle_diagnostic_canonical = first_non_blank(
    nested(support, "diagnosticSnapshot", "canonicalDeviceId"),
    nested(support, "diagnosticSnapshot", "deviceId"),
    cloud_canonical(support),
)
verdict_canonical_value = verdict_canonical(verdict)

if bundle_diagnostic_canonical != canonical:
    raise SystemExit(f"support bundle diagnostic canonical mismatch: {bundle_diagnostic_canonical} != {canonical}")
if bundle_transport_canonical and bundle_transport_canonical != canonical:
    raise SystemExit(f"support bundle transport canonical mismatch: {bundle_transport_canonical} != {canonical}")
if bundle_verdict_canonical and bundle_verdict_canonical != canonical:
    raise SystemExit(f"support bundle verdict canonical mismatch: {bundle_verdict_canonical} != {canonical}")
if verdict_canonical_value and verdict_canonical_value != canonical:
    raise SystemExit(f"verdict canonical mismatch: {verdict_canonical_value} != {canonical}")

if os.environ.get("LEONA_CLOUD_CONFIG_ENDPOINT", "").strip():
    if "androidId" not in effective_disabled:
        raise SystemExit(f"effectiveDisabledSignals missing androidId: {effective_disabled}")
    if cloud_fetched_at is None:
        raise SystemExit("cloudConfigFetchedAtMillis missing")
    if not cloud_raw:
        raise SystemExit("cloudConfigRaw missing")

verdict_text = os.environ.get("VERDICT_TEXT", "")
if canonical not in verdict_text:
    raise SystemExit(f"verdictResult missing canonical device id: {canonical}")

support_summary = "\n".join([
    f"canonical={bundle_diagnostic_canonical or '-'}",
    f"effectiveDisabled={','.join(effective_disabled) if effective_disabled else '-'}",
    f"cloudFetchedAt={cloud_fetched_at if cloud_fetched_at is not None else '-'}",
    f"cloudRawPresent={'true' if cloud_raw else 'false'}",
    f"transportCanonical={bundle_transport_canonical or '-'}",
    f"verdictCanonical={bundle_verdict_canonical or '-'}",
    f"transportBindingStatus={nested(support, 'secureTransport', 'session', 'deviceBindingStatus') or '-'}",
    f"serverAttestationProvider={nested(support, 'secureTransport', 'session', 'serverAttestation', 'provider') or '-'}",
    f"serverAttestationStatus={nested(support, 'secureTransport', 'session', 'serverAttestation', 'status') or '-'}",
    f"serverAttestationCode={nested(support, 'secureTransport', 'session', 'serverAttestation', 'code') or '-'}",
])

transport_summary = "\n".join([
    f"engine={transport.get('engineAvailable')}",
    f"bindingPresent={binding_present}",
    f"bindingHardwareBacked={nested(transport, 'deviceBinding', 'hardwareBacked')}",
    f"bindingSha256={nested(transport, 'deviceBinding', 'publicKeySha256') or '-'}",
    f"session={nested(transport, 'session', 'sessionIdHint') or '-'}",
    f"expiresAt={nested(transport, 'session', 'expiresAtMillis') or '-'}",
    f"canonical={transport_canonical or '-'}",
    f"bindingStatus={nested(transport, 'session', 'deviceBindingStatus') or '-'}",
    f"serverAttestationProvider={nested(transport, 'session', 'serverAttestation', 'provider') or '-'}",
    f"serverAttestationStatus={nested(transport, 'session', 'serverAttestation', 'status') or '-'}",
    f"serverAttestationCode={nested(transport, 'session', 'serverAttestation', 'code') or '-'}",
    f"lastHandshakeError={last_handshake_error or '-'}",
])

print(f"export CANONICAL_ID={shlex.quote(canonical)}")
print(f"export FINAL_DEVICE_LINE={shlex.quote('DeviceId: ' + canonical)}")
print(f"export FINAL_SUPPORT_BUNDLE_TEXT={shlex.quote(support_summary)}")
print(f"export FINAL_TRANSPORT_TEXT={shlex.quote(transport_summary)}")
PY
)"
eval "$validation_exports"

formal_secret="$(build_config_value LEONA_DEMO_VERDICT_SECRET_KEY)"
if [[ -z "$formal_secret" ]]; then
  echo "Formal verdict secret missing from BuildConfig; enable LEONA_AUTO_CREATE_LOCAL_SERVER_APP_KEY=1 or pass LEONA_SERVER_SECRET_KEY." >&2
  exit 1
fi

adb -s "$ADB_SERIAL" shell am force-stop "$APP_ID"
adb -s "$ADB_SERIAL" shell am start -n "$APP_ID/$APP_ACTIVITY" >/dev/null
sleep 3
tap_view_with_scroll formal-sense "$APP_ID:id/buttonSense" 1
formal_box_line="$(poll_for_boxid)"
formal_box_id="${formal_box_line#BoxId: }"
formal_verdict_json_path="$OUTPUT_DIR/formal-verdict.json"
formal_verdict_summary="$(query_formal_verdict "$formal_box_id" "$formal_secret" "$formal_verdict_json_path")"

FORMAL_VERDICT_JSON_PATH="$formal_verdict_json_path" \
CANONICAL_ID="$CANONICAL_ID" \
python3 <<'PY'
import json
import os

with open(os.environ["FORMAL_VERDICT_JSON_PATH"], "r", encoding="utf-8") as fh:
    verdict = json.load(fh)
canonical = os.environ["CANONICAL_ID"]
formal = (verdict.get("canonicalDeviceId") or "").strip()
if not formal:
    raise SystemExit("formal verdict canonicalDeviceId missing")
if formal != canonical:
    raise SystemExit(f"formal verdict canonical mismatch: {formal} != {canonical}")
if not (verdict.get("deviceFingerprint") or "").strip():
    raise SystemExit("formal verdict deviceFingerprint missing")
PY

echo
printf '[Leona E2E] BoxId: %s\n' "$box_id"
printf '[Leona E2E] Formal Verdict BoxId: %s\n' "$formal_box_id"
printf '[Leona E2E] Device(before): %s\n' "$pre_device_line"
printf '[Leona E2E] Device(after): %s\n' "$FINAL_DEVICE_LINE"
printf '[Leona E2E] Transport:\n%s\n' "$FINAL_TRANSPORT_TEXT"
printf '[Leona E2E] Support bundle:\n%s\n' "$FINAL_SUPPORT_BUNDLE_TEXT"
printf '[Leona E2E] Verdict:\n%s\n' "$verdict_text"
printf '[Leona E2E] Formal verdict:\n%s\n' "$formal_verdict_summary"
