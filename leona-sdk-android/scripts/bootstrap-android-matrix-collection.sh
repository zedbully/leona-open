#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${LEONA_ANDROID_MATRIX_BOOTSTRAP_OUT:-$(mktemp -d /tmp/leona-android-matrix-bootstrap.XXXXXX)}"
APK_PATH="${LEONA_APK:-${ROOT_DIR}/sample-app/build/outputs/apk/debug/sample-app-debug.apk}"
TRIGGER_SENSE="${LEONA_TRIGGER_SENSE:-none}"
INSTALL_APK="${LEONA_INSTALL_APK:-0}"
RUN_SECONDS="${LEONA_RUN_SECONDS:-8}"
SENSE_WAIT_SECONDS="${LEONA_SENSE_WAIT_SECONDS:-18}"
DISCOVERY_OUT="${OUT_DIR}/discovery"

mkdir -p "${OUT_DIR}"

hash_text() {
  python3 - "$1" <<'PY'
import hashlib
import sys
print(hashlib.sha256(sys.argv[1].encode("utf-8")).hexdigest()[:16])
PY
}

write_summary() {
  local status="$1"
  local reason="$2"
  python3 - "${OUT_DIR}" "${status}" "${reason}" <<'PY'
import json
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
status = sys.argv[2]
reason = sys.argv[3]

collections = []
for child in sorted(out_dir.iterdir()):
    if not child.is_dir() or child.name == "discovery":
        continue
    matrix_row = child / "matrix-row.md"
    posture_json = child / "posture" / "device-posture.json"
    collection_report = child / "cloud-collection" / "report.md"
    collections.append({
        "targetHash": child.name,
        "postureCollected": posture_json.exists(),
        "collectionReport": str(collection_report) if collection_report.exists() else "",
        "matrixRow": str(matrix_row) if matrix_row.exists() else "",
    })

payload = {
    "status": status,
    "reason": reason,
    "reportDir": str(out_dir),
    "secretValuesPrinted": False,
    "rawSerialsPrinted": False,
    "collections": collections,
}
(out_dir / "summary.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

lines = [
    "# Leona Android Matrix Bootstrap Collection",
    "",
    f"- status: {status}",
    f"- reason: {reason}",
    f"- reportDir: `{out_dir}`",
    "- secret values printed: no",
    "- raw ADB serials printed: no",
    "",
    "## Collections",
    "",
]
if collections:
    for item in collections:
        lines.append(
            f"- targetHash={item['targetHash']}: posture={str(item['postureCollected']).lower()}, "
            f"matrixRow={'yes' if item['matrixRow'] else 'no'}"
        )
else:
    lines.append("- none")
(out_dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

if ! command -v adb >/dev/null 2>&1; then
  write_summary "blocked" "adb-not-found"
  echo "[android-matrix-bootstrap] blocked: ${OUT_DIR}/summary.md"
  exit 2
fi

LEONA_ANDROID_MATRIX_DISCOVERY_OUT="${DISCOVERY_OUT}" \
  "${ROOT_DIR}/scripts/discover-android-matrix-environment.sh" >/dev/null 2>&1 || true

devices=()
while IFS= read -r serial; do
  [[ -n "${serial}" ]] && devices+=("${serial}")
done < <(adb devices | awk 'NR > 1 && $2 == "device" { print $1 }')
if [[ "${#devices[@]}" -eq 0 ]]; then
  write_summary "blocked" "no-adb-device"
  echo "[android-matrix-bootstrap] blocked: ${OUT_DIR}/summary.md"
  exit 2
fi

if [[ ! -f "${APK_PATH}" ]]; then
  write_summary "partial" "apk-not-found-posture-only"
else
  :
fi

for serial in "${devices[@]}"; do
  serial_hash="$(hash_text "${serial}")"
  target_dir="${OUT_DIR}/${serial_hash}"
  mkdir -p "${target_dir}"

  ADB_SERIAL="${serial}" \
  OUTPUT_DIR="${target_dir}/posture" \
    "${ROOT_DIR}/scripts/collect-device-posture.sh" \
      >"${target_dir}/posture.log" 2>&1 || true

  if [[ -f "${APK_PATH}" ]]; then
    LEONA_APK="${APK_PATH}" \
    ANDROID_SERIAL="${serial}" \
    LEONA_COLLECTION_OUT="${target_dir}/cloud-collection" \
    LEONA_INSTALL_APK="${INSTALL_APK}" \
    LEONA_TRIGGER_SENSE="${TRIGGER_SENSE}" \
    LEONA_RUN_SECONDS="${RUN_SECONDS}" \
    LEONA_SENSE_WAIT_SECONDS="${SENSE_WAIT_SECONDS}" \
      "${ROOT_DIR}/scripts/run-cloud-device-collection.sh" \
        >"${target_dir}/cloud-collection.log" 2>&1 || true
    cp "${target_dir}/cloud-collection/matrix-row.md" "${target_dir}/matrix-row.md" 2>/dev/null || true
  fi
done

write_summary "pass-with-collection-artifacts" "adb-targets-collected"
echo "[android-matrix-bootstrap] pass-with-collection-artifacts: ${OUT_DIR}/summary.md"
