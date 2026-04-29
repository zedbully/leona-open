#!/usr/bin/env bash
set -euo pipefail
umask 077

: "${OUTPUT_DIR:=/tmp/leona-device-posture-$(date +%Y%m%d-%H%M%S)}"

if ! command -v adb >/dev/null 2>&1; then
  echo "adb was not found in PATH." >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 was not found in PATH." >&2
  exit 2
fi

hash_text() {
  python3 - "$1" <<'PY'
import hashlib
import sys

value = sys.argv[1]
print(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16] if value else "")
PY
}

validate_adb_serial() {
  local candidate="$1"
  local state
  state="$(adb devices | awk -v serial="$candidate" '$1 == serial { print $2; exit }')"
  if [[ "$state" != "device" ]]; then
    echo "The selected Android device is not connected in 'device' state." >&2
    echo "Selected serial hash: $(hash_text "$candidate")" >&2
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
    echo "Multiple Android devices are connected. Set ADB_SERIAL explicitly." >&2
    echo "Connected device serial hashes:" >&2
    for serial in "${devices[@]}"; do
      printf '  %s\n' "$(hash_text "$serial")" >&2
    done
    exit 2
  fi

  printf '%s\n' "${devices[0]}"
}

run_shell() {
  adb -s "$ADB_SERIAL" shell "$@" 2>/dev/null | tr -d '\r' || true
}

ADB_SERIAL="$(select_adb_serial)"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/leona-device-posture.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT
mkdir -p "$OUTPUT_DIR"

PROPS=(
  ro.product.brand
  ro.product.manufacturer
  ro.product.model
  ro.product.device
  ro.product.name
  ro.product.product.device
  ro.product.system.device
  ro.product.vendor.device
  ro.product.board
  ro.hardware
  ro.soc.manufacturer
  ro.soc.model
  ro.build.version.release
  ro.build.version.sdk
  ro.build.version.security_patch
  ro.build.id
  ro.build.display.id
  ro.build.type
  ro.build.tags
  ro.build.flavor
  ro.build.fingerprint
  ro.build.description
  ro.system.build.fingerprint
  ro.vendor.build.fingerprint
  ro.bootimage.build.fingerprint
  ro.odm.build.fingerprint
  ro.product.first_api_level
  ro.vendor.api_level
  ro.treble.enabled
  ro.gsid.image_running
  ro.boot.verifiedbootstate
  ro.boot.vbmeta.device_state
  ro.boot.flash.locked
  ro.boot.veritymode
  ro.boot.bootloader
  ro.boot.serialno
  ro.serialno
)

{
  for prop in "${PROPS[@]}"; do
    printf '%s\t%s\n' "$prop" "$(run_shell getprop "$prop" | head -n 1)"
  done
} > "$TMP_DIR/props.tsv"

run_shell settings get secure android_id | head -n 1 > "$TMP_DIR/android_id.txt"
run_shell pm list packages | sed 's/^package://' > "$TMP_DIR/packages.txt"

REPORT_PATH="$OUTPUT_DIR/device-posture.json" \
SUMMARY_PATH="$OUTPUT_DIR/device-posture.env" \
ADB_SERIAL_HASH="$(hash_text "$ADB_SERIAL")" \
python3 - "$TMP_DIR/props.tsv" "$TMP_DIR/android_id.txt" "$TMP_DIR/packages.txt" <<'PY'
import hashlib
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

props_path = Path(sys.argv[1])
android_id_path = Path(sys.argv[2])
packages_path = Path(sys.argv[3])
report_path = Path(os.environ["REPORT_PATH"])
summary_path = Path(os.environ["SUMMARY_PATH"])

def digest(value: str, length: int = 16) -> str:
    value = (value or "").strip()
    if not value or value.lower() in {"unknown", "null"}:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:length]

def read_props():
    props = {}
    for line in props_path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, _, value = line.partition("\t")
        props[key] = value.strip()
    return props

def read_lines(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and line.strip().lower() != "null"
    ]

props = read_props()
android_id = android_id_path.read_text(encoding="utf-8", errors="replace").strip()
packages = sorted(set(read_lines(packages_path)))

hashed_prop_names = {
    "ro.build.fingerprint",
    "ro.build.description",
    "ro.system.build.fingerprint",
    "ro.vendor.build.fingerprint",
    "ro.bootimage.build.fingerprint",
    "ro.odm.build.fingerprint",
    "ro.boot.bootloader",
    "ro.boot.serialno",
    "ro.serialno",
}

plain_prop_names = [
    "ro.product.brand",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.device",
    "ro.product.name",
    "ro.product.product.device",
    "ro.product.system.device",
    "ro.product.vendor.device",
    "ro.product.board",
    "ro.hardware",
    "ro.soc.manufacturer",
    "ro.soc.model",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.id",
    "ro.build.display.id",
    "ro.build.type",
    "ro.build.tags",
    "ro.build.flavor",
    "ro.product.first_api_level",
    "ro.vendor.api_level",
    "ro.treble.enabled",
    "ro.gsid.image_running",
    "ro.boot.verifiedbootstate",
    "ro.boot.vbmeta.device_state",
    "ro.boot.flash.locked",
    "ro.boot.veritymode",
]

root_manager_patterns = {
    "magisk": [
        r"^com\.topjohnwu\.magisk$",
        r"^io\.github\.huskydg\.magisk$",
        r"^io\.github\.vvb2060\.magisk$",
    ],
    "kernelsu": [
        r"^me\.weishu\.kernelsu$",
        r"^com\.rifsxd\.ksunext$",
        r"^io\.github\.rifsxd\.kernelsu$",
    ],
    "apatch": [
        r"^me\.bmax\.apatch$",
        r"^io\.github\.bmax121\.apatch$",
    ],
    "supersu": [
        r"^eu\.chainfire\.supersu$",
        r"^com\.noshufou\.android\.su$",
        r"^com\.koushikdutta\.superuser$",
    ],
    "kingroot": [
        r"^com\.kingroot\.kinguser$",
        r"^com\.kingo\.root$",
    ],
    "root_adjacent_framework": [
        r"^org\.lsposed\.manager$",
        r"^de\.robv\.android\.xposed\.installer$",
    ],
}

detected_root_families = {}
for family, patterns in root_manager_patterns.items():
    compiled = [re.compile(pattern) for pattern in patterns]
    matches = [pkg for pkg in packages if any(pattern.search(pkg) for pattern in compiled)]
    if matches:
        detected_root_families[family] = [digest(pkg) for pkg in matches]

def prop(name: str) -> str:
    return props.get(name, "").strip()

text_blob = " ".join(
    prop(name).lower()
    for name in [
        "ro.product.brand",
        "ro.product.manufacturer",
        "ro.product.model",
        "ro.product.device",
        "ro.product.name",
        "ro.build.display.id",
        "ro.build.flavor",
        "ro.build.tags",
        "ro.build.type",
    ]
)

signals = []

def add_signal(name: str, condition: bool) -> None:
    if condition and name not in signals:
        signals.append(name)

add_signal("verified_boot.orange", prop("ro.boot.verifiedbootstate").lower() == "orange")
add_signal("verified_boot.red", prop("ro.boot.verifiedbootstate").lower() == "red")
add_signal("vbmeta.unlocked", prop("ro.boot.vbmeta.device_state").lower() == "unlocked")
add_signal("bootloader.unlocked", prop("ro.boot.flash.locked") == "0")
add_signal("verity.eio_or_disabled", prop("ro.boot.veritymode").lower() in {"eio", "disabled"})
add_signal("build.test_keys", "test-keys" in prop("ro.build.tags").lower())
add_signal("build.dev_keys", "dev-keys" in prop("ro.build.tags").lower())
add_signal("build.userdebug_or_eng", prop("ro.build.type").lower() in {"userdebug", "eng"})
add_signal("gsi.running", prop("ro.gsid.image_running").lower() in {"1", "true", "yes"})
add_signal("treble.enabled", prop("ro.treble.enabled").lower() in {"1", "true", "yes"})
for marker, signal in [
    ("lineage", "rom.lineage_like"),
    ("crdroid", "rom.crdroid_like"),
    ("pixelextended", "rom.pixel_extended_like"),
    ("pixelexperience", "rom.pixel_experience_like"),
    ("graphene", "rom.grapheneos_like"),
    ("calyx", "rom.calyxos_like"),
    ("evolution", "rom.evolution_x_like"),
    ("aosp", "rom.aosp_like"),
]:
    add_signal(signal, marker in text_blob)
add_signal("root_manager.package_present", bool(detected_root_families))

posture = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    "adbSerialHash": os.environ.get("ADB_SERIAL_HASH", ""),
    "androidIdHash": digest(android_id),
    "redaction": {
        "policy": "No full ADB serial, Android ID, build fingerprint, bootloader version, or root-manager package name is exported.",
        "hash": "sha256 truncated to 16 hex characters for correlation only.",
        "rawValuesNotExported": sorted(hashed_prop_names | {"settings.secure.android_id", "adb serial", "root manager package names"}),
    },
    "device": {name: prop(name) for name in plain_prop_names if prop(name)},
    "sensitiveHashes": {
        name: digest(prop(name))
        for name in sorted(hashed_prop_names)
        if digest(prop(name))
    },
    "rootManagerSummary": {
        "knownPackageCount": sum(len(values) for values in detected_root_families.values()),
        "detectedFamilies": sorted(detected_root_families),
        "packageNameHashesByFamily": detected_root_families,
    },
    "derivedEvidence": sorted(signals),
}

report_path.write_text(json.dumps(posture, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
summary_path.write_text(
    "generated_at={}\n"
    "adb_serial_hash={}\n"
    "android_id_hash={}\n"
    "fingerprint_hash={}\n"
    "verified_boot_state={}\n"
    "vbmeta_device_state={}\n"
    "flash_locked={}\n"
    "build_type={}\n"
    "build_tags={}\n"
    "root_manager_known_package_count={}\n"
    "root_manager_detected_families={}\n"
    "derived_evidence={}\n".format(
        shlex.quote(posture["generatedAt"]),
        shlex.quote(posture["adbSerialHash"]),
        shlex.quote(posture["androidIdHash"]),
        shlex.quote(posture["sensitiveHashes"].get("ro.build.fingerprint", "")),
        shlex.quote(prop("ro.boot.verifiedbootstate")),
        shlex.quote(prop("ro.boot.vbmeta.device_state")),
        shlex.quote(prop("ro.boot.flash.locked")),
        shlex.quote(prop("ro.build.type")),
        shlex.quote(prop("ro.build.tags")),
        shlex.quote(str(posture["rootManagerSummary"]["knownPackageCount"])),
        shlex.quote(",".join(posture["rootManagerSummary"]["detectedFamilies"])),
        shlex.quote(",".join(posture["derivedEvidence"])),
    ),
    encoding="utf-8",
)

print(json.dumps({
    "outputDir": str(report_path.parent),
    "report": str(report_path),
    "summary": str(summary_path),
    "adbSerialHash": posture["adbSerialHash"],
    "derivedEvidence": posture["derivedEvidence"],
    "rootManagerFamilies": posture["rootManagerSummary"]["detectedFamilies"],
}, ensure_ascii=False))
PY

echo "[Leona device posture] output: $OUTPUT_DIR"
