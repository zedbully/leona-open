#!/usr/bin/env bash
set -euo pipefail

: "${DEMO_BACKEND_BASE_URL:=http://localhost:8090}"
: "${LEONA_APP_ID:=sample-app}"
: "${LEONA_DISABLED_SIGNAL_EXPECT:=androidId}"
: "${LEONA_DISABLE_COLLECTION_WINDOW_EXPECT:=120000}"

TMP_DIR="$(mktemp -d /tmp/leona-cloud-config.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

request_config() {
  local name="$1"
  local fingerprint="$2"
  local device_id="$3"
  local install_id="$4"

  curl -fsS \
    -D "$TMP_DIR/$name.headers" \
    -o "$TMP_DIR/$name.json" \
    -H "X-Leona-App-Id: $LEONA_APP_ID" \
    -H "X-Leona-Device-Id: $device_id" \
    -H "X-Leona-Install-Id: $install_id" \
    -H "X-Leona-Fingerprint: $fingerprint" \
    "$DEMO_BACKEND_BASE_URL/v1/mobile-config"
}

echo "[Leona cloud-config] backend: $DEMO_BACKEND_BASE_URL"
curl -fsS "$DEMO_BACKEND_BASE_URL/health" > "$TMP_DIR/health.json"

request_config a "fingerprint-alpha" "Tdevice-alpha-1" "install-alpha-1"
request_config b "fingerprint-alpha" "Tdevice-alpha-2" "install-alpha-2"
request_config c "fingerprint-bravo" "Tdevice-bravo-1" "install-bravo-1"

python3 - "$TMP_DIR" "$LEONA_DISABLED_SIGNAL_EXPECT" "$LEONA_DISABLE_COLLECTION_WINDOW_EXPECT" <<'PY'
import json
import pathlib
import re
import sys

tmp = pathlib.Path(sys.argv[1])
expected_signals = [v.strip() for v in sys.argv[2].split(",") if v.strip()]
expected_window = int(sys.argv[3])

def load_json(name: str):
    return json.loads((tmp / f"{name}.json").read_text())

def header_value(name: str, header: str):
    text = (tmp / f"{name}.headers").read_text()
    match = re.search(rf"^{re.escape(header)}:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else None

def canonical(obj):
    for value in (
        obj.get("canonicalDeviceId"),
        obj.get("device", {}).get("canonicalDeviceId"),
        obj.get("identity", {}).get("canonicalDeviceId"),
        obj.get("deviceIdentity", {}).get("canonicalDeviceId"),
        obj.get("deviceIdentity", {}).get("resolvedDeviceId"),
    ):
        if value:
            return value
    raise SystemExit("canonicalDeviceId missing from response body")

a = load_json("a")
b = load_json("b")
c = load_json("c")

canon_a = canonical(a)
canon_b = canonical(b)
canon_c = canonical(c)

assert canon_a == canon_b, f"same fingerprint should keep canonical stable: {canon_a} != {canon_b}"
assert canon_a != canon_c, f"different fingerprints should diverge: {canon_a} == {canon_c}"

for obj in (a, b, c):
    for expected_signal in expected_signals:
        assert expected_signal in obj.get("disabledSignals", []), f"disabledSignals missing {expected_signal}"
    assert obj.get("disableCollectionWindowMs") == expected_window, (
        f"disableCollectionWindowMs mismatch: {obj.get('disableCollectionWindowMs')} != {expected_window}"
    )
    assert obj.get("policy", {}).get("disableCollectionWindowMs") == expected_window
    assert obj.get("config", {}).get("disableCollectionWindowMs") == expected_window

header_canon = header_value("a", "X-Leona-Canonical-Device-Id")
header_signals = header_value("a", "X-Leona-Disabled-Signals")
header_window = header_value("a", "X-Leona-Disable-Collection-Window-Ms")

assert header_canon == canon_a, f"header canonical mismatch: {header_canon} != {canon_a}"
assert header_signals is not None
for expected_signal in expected_signals:
    assert expected_signal in [v.strip() for v in header_signals.split(",")]
assert header_window == str(expected_window), f"header window mismatch: {header_window} != {expected_window}"

print("[Leona cloud-config] stable canonical for same fingerprint :", canon_a)
print("[Leona cloud-config] divergent canonical for new fingerprint:", canon_c)
print("[Leona cloud-config] disabled signals present              :", ",".join(expected_signals) or "-")
print("[Leona cloud-config] collection window ms                 :", expected_window)
PY
