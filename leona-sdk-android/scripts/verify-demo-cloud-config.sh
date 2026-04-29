#!/usr/bin/env bash
set -euo pipefail

: "${DEMO_BACKEND_BASE_URL:=http://localhost:8090}"
: "${LEONA_TENANT:=sample-tenant}"
: "${LEONA_OTHER_TENANT:=sample-tenant-b}"
: "${LEONA_APP_ID:=sample-app}"
: "${LEONA_OTHER_APP_ID:=sample-app-b}"
: "${LEONA_DISABLED_SIGNAL_EXPECT:=androidId}"
: "${LEONA_DISABLE_COLLECTION_WINDOW_EXPECT:=120000}"

TMP_DIR="$(mktemp -d /tmp/leona-cloud-config.XXXXXX)"
trap 'rm -rf "$TMP_DIR"' EXIT

request_config() {
  local name="$1"
  local tenant="$2"
  local app_id="$3"
  local fingerprint="$4"
  local device_id="$5"
  local install_id="$6"
  local provided_canonical="${7:-}"

  local -a headers=(
    -H "X-Leona-Tenant: $tenant"
    -H "X-Leona-App-Id: $app_id"
    -H "X-Leona-Device-Id: $device_id"
    -H "X-Leona-Install-Id: $install_id"
    -H "X-Leona-Fingerprint: $fingerprint"
  )
  if [[ -n "$provided_canonical" ]]; then
    headers+=( -H "X-Leona-Canonical-Device-Id: $provided_canonical" )
  fi

  curl -fsS \
    -D "$TMP_DIR/$name.headers" \
    -o "$TMP_DIR/$name.json" \
    "${headers[@]}" \
    "$DEMO_BACKEND_BASE_URL/v1/mobile-config"
}

echo "[Leona cloud-config] backend: $DEMO_BACKEND_BASE_URL"
curl -fsS "$DEMO_BACKEND_BASE_URL/health" > "$TMP_DIR/health.json"

request_config a "$LEONA_TENANT" "$LEONA_APP_ID" "fingerprint-alpha" "Tdevice-alpha-1" "install-alpha-1"
request_config b "$LEONA_TENANT" "$LEONA_APP_ID" "fingerprint-alpha" "Tdevice-alpha-2" "install-alpha-2"
request_config c "$LEONA_TENANT" "$LEONA_APP_ID" "fingerprint-bravo" "Tdevice-bravo-1" "install-bravo-1"
request_config d "$LEONA_OTHER_TENANT" "$LEONA_APP_ID" "fingerprint-alpha" "Tdevice-alpha-1" "install-alpha-1"
request_config e "$LEONA_TENANT" "$LEONA_OTHER_APP_ID" "fingerprint-alpha" "Tdevice-alpha-1" "install-alpha-1"
request_config f "$LEONA_TENANT" "$LEONA_APP_ID" "fingerprint-provided" "Tdevice-provided-1" "install-provided-1" "Lserver-issued"
request_config g "$LEONA_TENANT" "$LEONA_APP_ID" "" "Tdevice-provided-1" "install-provided-2"
request_config h "$LEONA_TENANT" "$LEONA_APP_ID" "" "" "install-only"
request_config i "$LEONA_OTHER_TENANT" "$LEONA_APP_ID" "" "" "install-only"
request_config j "$LEONA_TENANT" "$LEONA_OTHER_APP_ID" "" "" "install-only"

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
d = load_json("d")
e = load_json("e")
f = load_json("f")
g = load_json("g")
h = load_json("h")
i = load_json("i")
j = load_json("j")

canon_a = canonical(a)
canon_b = canonical(b)
canon_c = canonical(c)
canon_d = canonical(d)
canon_e = canonical(e)
canon_f = canonical(f)
canon_g = canonical(g)
canon_h = canonical(h)
canon_i = canonical(i)
canon_j = canonical(j)

assert canon_a == canon_b, f"same tenant/app/fingerprint should keep canonical stable: {canon_a} != {canon_b}"
assert canon_a != canon_c, f"different fingerprint should diverge: {canon_a} == {canon_c}"
assert canon_a == canon_d, f"fingerprint canonical should remain tenant-independent: {canon_a} != {canon_d}"
assert canon_a == canon_e, f"fingerprint canonical should remain app-independent: {canon_a} != {canon_e}"
assert canon_f == "Lserver-issued", f"provided canonical should echo back: {canon_f}"
assert canon_g == canon_f, f"device fallback should backfill provided canonical: {canon_g} != {canon_f}"
assert canon_h != canon_i, f"install-only canonical should isolate tenant: {canon_h} == {canon_i}"
assert canon_h != canon_j, f"install-only canonical should isolate app: {canon_h} == {canon_j}"

for obj in (a, b, c, d, e, f, g, h, i, j):
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

print("[Leona cloud-config] stable canonical same tenant/app/fingerprint:", canon_a)
print("[Leona cloud-config] divergent canonical new fingerprint          :", canon_c)
print("[Leona cloud-config] shared canonical other tenant/app fingerprint:", canon_d, canon_e)
print("[Leona cloud-config] provided canonical echoed/backfilled        :", canon_f)
print("[Leona cloud-config] install-only tenant/app isolation           :", canon_h, canon_i, canon_j)
print("[Leona cloud-config] disabled signals present                   :", ",".join(expected_signals) or "-")
print("[Leona cloud-config] collection window ms                      :", expected_window)
PY
