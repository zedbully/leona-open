#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

: "${APP_ID:=io.leonasec.leona.sample}"
: "${APP_ACTIVITY:=.MainActivity}"
: "${OUTPUT_DIR:=/tmp/leona-installed-sample-logcat-smoke-$(date +%Y%m%d-%H%M%S)}"
: "${LEONA_LOGCAT_TIMEOUT_SEC:=90}"
: "${LEONA_SKIP_LOGCAT_CLEAR:=0}"
: "${LEONA_SKIP_FORCE_STOP:=0}"
: "${LEONA_REQUIRED_EVENTS:=started,pre,sense,post,complete}"

E2E_AUTO_RUN_EXTRA="io.leonasec.leona.sample.extra.E2E_AUTO_RUN"
E2E_TOKEN_EXTRA="io.leonasec.leona.sample.extra.E2E_TOKEN"

if [[ -z "${LEONA_E2E_TOKEN:-}" ]]; then
  echo "LEONA_E2E_TOKEN is required. Reuse the token that was built into the installed debug sample APK." >&2
  exit 2
fi

if ! command -v adb >/dev/null 2>&1; then
  echo "adb was not found in PATH." >&2
  exit 2
fi

validate_adb_serial() {
  local candidate="$1"
  local state
  state="$(adb devices | awk -v serial="$candidate" '$1 == serial { print $2; exit }')"
  if [[ "$state" != "device" ]]; then
    echo "Android device $candidate is not connected in 'device' state. Current devices:" >&2
    adb devices >&2
    exit 2
  fi
}

select_adb_serial() {
  if [[ -n "${ADB_SERIAL:-}" ]]; then
    validate_adb_serial "$ADB_SERIAL"
    printf '%s\n' "$ADB_SERIAL"
    return 0
  fi
  if [[ -n "${ANDROID_SERIAL:-}" ]]; then
    validate_adb_serial "$ANDROID_SERIAL"
    printf '%s\n' "$ANDROID_SERIAL"
    return 0
  fi

  local devices=()
  local serial
  while IFS= read -r serial; do
    [[ -n "$serial" ]] && devices+=("$serial")
  done < <(adb devices | awk 'NR > 1 && $2 == "device" { print $1 }')

  if [[ "${#devices[@]}" -eq 0 ]]; then
    echo "No connected Android device found. Set ADB_SERIAL when using a specific device." >&2
    exit 2
  fi
  if [[ "${#devices[@]}" -gt 1 ]]; then
    echo "Multiple Android devices are connected. Set ADB_SERIAL explicitly:" >&2
    printf '  %s\n' "${devices[@]}" >&2
    exit 2
  fi

  printf '%s\n' "${devices[0]}"
}

ADB_SERIAL="$(select_adb_serial)"
mkdir -p "$OUTPUT_DIR"

wait_for_device() {
  adb -s "$ADB_SERIAL" wait-for-device >/dev/null
}

require_installed_sample() {
  local package_path
  package_path="$(adb -s "$ADB_SERIAL" shell pm path "$APP_ID" 2>/dev/null | tr -d '\r' || true)"
  if [[ "$package_path" != package:* ]]; then
    echo "$APP_ID is not installed on $ADB_SERIAL. Install a debug sample APK first; this smoke test does not install or replace apps." >&2
    exit 2
  fi
}

cleanup_logcat() {
  if [[ -n "${LOGCAT_PID:-}" ]]; then
    kill "$LOGCAT_PID" >/dev/null 2>&1 || true
    wait "$LOGCAT_PID" >/dev/null 2>&1 || true
  fi
}

launch_sample_e2e() {
  if [[ "$LEONA_SKIP_FORCE_STOP" != "1" ]]; then
    adb -s "$ADB_SERIAL" shell am force-stop "$APP_ID" >/dev/null
  fi
  adb -s "$ADB_SERIAL" shell am start \
    -n "$APP_ID/$APP_ACTIVITY" \
    --ez "$E2E_AUTO_RUN_EXTRA" true \
    --es "$E2E_TOKEN_EXTRA" "$LEONA_E2E_TOKEN" >/dev/null
}

sanitize_logcat() {
  local log_file="$1"

  python3 - "$log_file" <<'PY'
import base64
import hashlib
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
secret_patterns = [
    re.compile(r"(?i)(api[_-]?key|secret|token|bearer)(['\":= ]+)([^\s,'\"}]+)"),
    re.compile(r"LEONA_[A-Z0-9_]+=[^\s]+"),
]
SENSITIVE_KEYS = {
    "canonicalDeviceId",
    "deviceId",
    "resolvedDeviceId",
    "id",
    "installId",
    "fingerprintHash",
    "reportingEndpoint",
    "cloudConfigEndpoint",
    "demoBackendEndpoint",
}

def digest(value):
    text = str(value or "").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else ""

def hint(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return f"<redacted:{digest(text)[:8]}>"
    return f"{text[:4]}...{text[-4:]}"

def redact_text(value):
    text = str(value)
    for pattern in secret_patterns:
        text = pattern.sub(lambda match: match.group(1) + match.group(2) + "<redacted>", text)
    return text

def sanitize_payload(value):
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            if re.search(r"(?i)(api.*key|secret|token|authorization)", str(key)):
                sanitized[key] = "<redacted>"
            elif key in SENSITIVE_KEYS and isinstance(item, str):
                sanitized[key + "Hint"] = hint(item)
                sanitized[key + "Sha256"] = digest(item)
            else:
                sanitized[key] = sanitize_payload(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_payload(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
chunks = {}
for offset, line in enumerate(lines):
    text = line.strip()
    if not text.startswith("{"):
        continue
    try:
        item = json.loads(text)
    except json.JSONDecodeError:
        continue
    if item.get("marker") != "leona-e2e-chunk":
        continue
    try:
        run_id = str(item["runId"])
        event = str(item["event"])
        total = int(item["total"])
        index = int(item["index"])
    except (KeyError, TypeError, ValueError):
        continue
    bucket = chunks.setdefault((run_id, event), {"run_id": run_id, "event": event, "total": total, "parts": {}, "offsets": []})
    bucket["total"] = max(int(bucket["total"]), total)
    bucket["parts"][index] = str(item.get("data") or "")
    bucket["offsets"].append(offset)

for _, bucket in chunks.items():
    run_id = bucket["run_id"]
    event = bucket["event"]
    total = int(bucket["total"])
    parts = bucket["parts"]
    if any(index not in parts for index in range(total)):
        continue
    try:
        envelope = json.loads(base64.b64decode("".join(parts[index] for index in range(total))).decode("utf-8"))
    except Exception:
        continue
    envelope["payload"] = sanitize_payload(envelope.get("payload") or {})
    encoded = base64.b64encode(
        json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    replacement = json.dumps({
        "marker": "leona-e2e-chunk",
        "runId": run_id,
        "event": event,
        "index": 0,
        "total": 1,
        "data": encoded,
    }, ensure_ascii=False, separators=(",", ":"))
    for offset in bucket["offsets"]:
        lines[offset] = ""
    lines[min(bucket["offsets"])] = replacement

lines = [redact_text(line) for line in lines if line != ""]
path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
PY
}

parse_logcat_e2e() {
  local log_file="$1"
  local report_path="$OUTPUT_DIR/events.json"
  local summary_path="$OUTPUT_DIR/summary.env"

  REPORT_PATH="$report_path" \
  SUMMARY_PATH="$summary_path" \
  REQUIRED_EVENTS="$LEONA_REQUIRED_EVENTS" \
  python3 - "$log_file" <<'PY'
import base64
import hashlib
import json
import os
import shlex
import sys
from pathlib import Path

log_path = Path(sys.argv[1])
report_path = Path(os.environ["REPORT_PATH"])
summary_path = Path(os.environ["SUMMARY_PATH"])
required = [
    item.strip()
    for item in os.environ.get("REQUIRED_EVENTS", "").split(",")
    if item.strip()
]

chunks_by_run = {}
for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
    text = line.strip()
    if not text.startswith("{"):
        continue
    try:
        item = json.loads(text)
    except json.JSONDecodeError:
        continue
    if item.get("marker") != "leona-e2e-chunk":
        continue
    run_id = str(item.get("runId") or "")
    event = str(item.get("event") or "")
    if not run_id or not event:
        continue
    try:
        index = int(item["index"])
        total = int(item["total"])
    except (KeyError, TypeError, ValueError):
        continue
    bucket = chunks_by_run.setdefault(run_id, {}).setdefault(
        event,
        {"total": total, "parts": {}},
    )
    bucket["total"] = max(int(bucket["total"]), total)
    bucket["parts"][index] = str(item.get("data") or "")

events_by_run = {}
incomplete_by_run = {}
for run_id, events in chunks_by_run.items():
    decoded = {}
    incomplete = {}
    for event, bucket in events.items():
        total = int(bucket["total"])
        parts = bucket["parts"]
        missing = [index for index in range(total) if index not in parts]
        if missing:
            incomplete[event] = missing
            continue
        encoded = "".join(parts[index] for index in range(total))
        envelope = json.loads(base64.b64decode(encoded).decode("utf-8"))
        if envelope.get("marker") == "leona-e2e":
            decoded[event] = envelope.get("payload") or {}
    events_by_run[run_id] = decoded
    incomplete_by_run[run_id] = incomplete

selected_run_id = None
for run_id, events in events_by_run.items():
    if "complete" in events:
        selected_run_id = run_id
if selected_run_id is None:
    for run_id, events in events_by_run.items():
        if "error" in events:
            selected_run_id = run_id
if selected_run_id is None and events_by_run:
    selected_run_id = max(events_by_run, key=lambda key: len(events_by_run[key]))

if selected_run_id is None:
    raise SystemExit(
        "No LeonaE2E structured events were decoded. "
        "Check that the installed APK is a debug build compiled with the same LEONA_E2E_TOKEN."
    )

events = events_by_run[selected_run_id]
missing = [name for name in required if name not in events]
if "error" in events and "complete" not in events:
    error_class = str(events["error"].get("class") or "unknown")
    raise SystemExit(f"LeonaE2E app error before completion: {error_class}")
if missing:
    raise SystemExit(f"Missing required LeonaE2E events: {', '.join(missing)}")

def nested(obj, *keys):
    cur = obj
    for key in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur

def compact_list(value):
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    return []

def digest(value):
    text = str(value or "").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16] if text else ""

def hint(value):
    text = str(value or "").strip()
    if not text:
        return ""
    if len(text) <= 8:
        return f"<redacted:{digest(text)[:8]}>"
    return f"{text[:4]}...{text[-4:]}"

SENSITIVE_KEYS = {
    "canonicalDeviceId",
    "deviceId",
    "resolvedDeviceId",
    "id",
    "installId",
    "fingerprintHash",
    "reportingEndpoint",
    "cloudConfigEndpoint",
    "demoBackendEndpoint",
}

def sanitize_decoded(value, parent_key=""):
    if isinstance(value, dict):
        sanitized = {}
        for key, item in value.items():
            if key in SENSITIVE_KEYS and isinstance(item, str):
                sanitized[key + "Hint"] = hint(item)
                sanitized[key + "Sha256"] = digest(item)
            else:
                sanitized[key] = sanitize_decoded(item, key)
        return sanitized
    if isinstance(value, list):
        if parent_key == "mismatchedSurfaces":
            return [
                f"{str(item).split(':', 1)[0]}:{hint(str(item).split(':', 1)[1])}"
                if ":" in str(item) else str(item)
                for item in value
            ]
        return [sanitize_decoded(item, parent_key) for item in value]
    return value

sense = events.get("sense") or {}
post = events.get("post") or {}
complete = events.get("complete") or {}
demo = events.get("demoVerdict") or {}

box_id = str(sense.get("boxId") or post.get("boxId") or complete.get("boxId") or "")
formal_box_id = str(complete.get("formalBoxId") or events.get("formalSense", {}).get("boxId") or "")
canonical = str(
    complete.get("canonicalDeviceIdSha256")
    or complete.get("canonicalDeviceId")
    or nested(post, "diagnostic", "canonicalDeviceId")
    or post.get("canonicalDeviceId")
    or ""
)
canonical_hint = str(
    complete.get("canonicalDeviceIdHint")
    or nested(post, "diagnostic", "canonicalDeviceIdHint")
    or post.get("canonicalDeviceIdHint")
    or hint(canonical)
    or ""
)
canonical_hash = canonical if len(canonical) == 16 and all(c in "0123456789abcdef" for c in canonical.lower()) else digest(canonical)
risk_tags = sorted(set(
    compact_list(nested(post, "diagnostic", "localRiskSignals"))
    + compact_list(nested(post, "diagnostic", "serverRiskTags"))
    + compact_list(nested(post, "diagnostic", "nativeRiskTags"))
    + compact_list(nested(demo, "summary", "riskTags"))
))
native_findings = sorted(set(compact_list(nested(post, "diagnostic", "nativeFindingIds"))))

report = {
    "runId": selected_run_id,
    "boxId": box_id,
    "formalBoxId": formal_box_id,
    "canonicalDeviceIdHint": canonical_hint,
    "canonicalDeviceIdSha256": canonical_hash,
    "riskTags": risk_tags,
    "nativeFindingIds": native_findings,
    "events": sanitize_decoded(events),
    "incompleteEvents": incomplete_by_run.get(selected_run_id) or {},
}
report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
summary_path.write_text(
    f"run_id={shlex.quote(selected_run_id)}\n"
    f"box_id={shlex.quote(box_id)}\n"
    f"formal_box_id={shlex.quote(formal_box_id)}\n"
    f"canonical_device_id_hint={shlex.quote(canonical_hint)}\n"
    f"canonical_device_id_sha256={shlex.quote(canonical_hash)}\n"
    f"risk_tags={shlex.quote(','.join(risk_tags))}\n"
    f"native_finding_ids={shlex.quote(','.join(native_findings))}\n",
    encoding="utf-8",
)

print(json.dumps({
    "runId": selected_run_id,
    "boxId": box_id,
    "formalBoxId": formal_box_id,
    "canonicalDeviceIdHint": canonical_hint,
    "canonicalDeviceIdSha256": canonical_hash,
    "riskTags": risk_tags,
    "nativeFindingIds": native_findings,
    "report": str(report_path),
    "summary": str(summary_path),
}, ensure_ascii=False))
PY
}

wait_for_device
require_installed_sample

LOG_FILE="$OUTPUT_DIR/logcat.txt"
if [[ "$LEONA_SKIP_LOGCAT_CLEAR" != "1" ]]; then
  adb -s "$ADB_SERIAL" logcat -c
fi

trap cleanup_logcat EXIT
adb -s "$ADB_SERIAL" logcat -v raw -s LeonaE2E:I '*:S' > "$LOG_FILE" &
LOGCAT_PID="$!"

launch_sample_e2e

deadline=$(( $(date +%s) + LEONA_LOGCAT_TIMEOUT_SEC ))
while [[ "$(date +%s)" -lt "$deadline" ]]; do
  if grep -q '"event":"complete"' "$LOG_FILE" 2>/dev/null; then
    break
  fi
  if grep -q '"event":"error"' "$LOG_FILE" 2>/dev/null; then
    break
  fi
  if grep -q 'Ignoring unauthorized logcat E2E request' "$LOG_FILE" 2>/dev/null; then
    break
  fi
  sleep 1
done

cleanup_logcat
trap - EXIT

sanitize_logcat "$LOG_FILE"

if ! grep -q '"event":"complete"' "$LOG_FILE" 2>/dev/null; then
  if grep -q 'Ignoring unauthorized logcat E2E request' "$LOG_FILE" 2>/dev/null; then
    echo "The installed sample rejected the logcat E2E request. Rebuild/install it with the same LEONA_E2E_TOKEN." >&2
  else
    echo "Timed out waiting for LeonaE2E completion. Raw log: $LOG_FILE" >&2
  fi
fi

SUMMARY_JSON="$(parse_logcat_e2e "$LOG_FILE")"

echo "[Leona installed sample smoke] serial : $ADB_SERIAL"
echo "[Leona installed sample smoke] app    : $APP_ID/$APP_ACTIVITY"
echo "[Leona installed sample smoke] output : $OUTPUT_DIR"
printf '%s\n' "$SUMMARY_JSON"
