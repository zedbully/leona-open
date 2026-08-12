#!/usr/bin/env bash
set -euo pipefail

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-${ADB_SERIAL:-}}"
APK="${LEONA_APK:-}"
PACKAGE="${LEONA_PACKAGE:-io.leonasec.leona.sample}"
OUT_DIR="${LEONA_STABILITY_OUT:-/tmp/leona-device-id-stability-$(date +%Y%m%d-%H%M%S)}"
COLLECTION_SCRIPT="${LEONA_COLLECTION_SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run-cloud-device-collection.sh}"
CLOUD_TEST_TOKEN="${LEONA_CLOUD_TEST_TOKEN:-}"
PHASES="${LEONA_STABILITY_PHASES:-initial,clear_data,reinstall,reboot}"
SENSE_WAIT_SECONDS="${LEONA_SENSE_WAIT_SECONDS:-18}"

adb_cmd() {
  if [[ -n "${SERIAL}" ]]; then
    "${ADB}" -s "${SERIAL}" "$@"
  else
    "${ADB}" "$@"
  fi
}

sha256_text() {
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  else
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  fi
}

boxid_hint() {
  local value="$1"
  printf '<redacted:%s>' "$(sha256_text "${value}" | cut -c1-16)"
}

extract_first_json_value() {
  local key="$1"
  local file="$2"
  grep -Eo "\"${key}\":\"[^\"]+\"" "${file}" 2>/dev/null | head -1 | cut -d'"' -f4 || true
}

redact_phase_boxids() {
  local phase_dir="$1"
  local logcat="${phase_dir}/logcat.leona.txt"
  [[ -f "${logcat}" ]] || return 0

  local box_id hint escaped
  while IFS= read -r box_id; do
    [[ -n "${box_id}" ]] || continue
    hint="$(boxid_hint "${box_id}")"
    escaped="$(printf '%s' "${box_id}" | sed 's/[\/&]/\\&/g')"
    for file in "${phase_dir}/logcat.leona.txt" "${phase_dir}/matrix-row.md" "${phase_dir}/report.md"; do
      [[ -f "${file}" ]] && sed -i.bak "s/${escaped}/${hint}/g" "${file}" && rm -f "${file}.bak"
    done
  done < <(grep -Eo '"boxId":"[^"]+"' "${logcat}" 2>/dev/null | cut -d'"' -f4 | sort -u)
}

write_blocked_report() {
  local reason="$1"
  mkdir -p "${OUT_DIR}"
  cat > "${OUT_DIR}/stability-summary.md" <<EOF
# Leona Device ID Stability

- status: blocked
- reason: ${reason}
- trigger mode: direct cloudTest receiver only
- UI fallback: not used
- package: ${PACKAGE}
- adb target: ${SERIAL:-not specified}

## Privacy

- BoxId values: not generated
- canonicalDeviceId: not generated
- fingerprintHash: not generated
- raw serial/android_id/fingerprint: not collected by this wrapper
EOF
  echo "Blocked: ${reason}" >&2
  echo "Report: ${OUT_DIR}/stability-summary.md" >&2
}

require_ready() {
  if [[ -z "${APK}" || ! -f "${APK}" ]]; then
    write_blocked_report "LEONA_APK must point to an existing cloudTest APK."
    exit 2
  fi
  if [[ -z "${CLOUD_TEST_TOKEN}" ]]; then
    write_blocked_report "LEONA_CLOUD_TEST_TOKEN is required; existing APK/token pairing was not provided."
    exit 2
  fi
  if [[ ! -x "${COLLECTION_SCRIPT}" ]]; then
    write_blocked_report "collection script is not executable: ${COLLECTION_SCRIPT}"
    exit 2
  fi
  if ! adb_cmd get-state >/dev/null 2>&1; then
    write_blocked_report "ADB device is not ready; set ANDROID_SERIAL/ADB_SERIAL when multiple devices are online."
    exit 3
  fi
}

run_collection_phase() {
  local phase="$1"
  local install_mode="$2"
  local phase_dir="${OUT_DIR}/${phase}"
  mkdir -p "${phase_dir}"
  LEONA_APK="${APK}" \
    ANDROID_SERIAL="${SERIAL}" \
    LEONA_PACKAGE="${PACKAGE}" \
    LEONA_COLLECTION_OUT="${phase_dir}" \
    LEONA_INSTALL_APK="${install_mode}" \
    LEONA_TRIGGER_SENSE=direct \
    LEONA_CLOUD_TEST_TOKEN="${CLOUD_TEST_TOKEN}" \
    LEONA_SENSE_WAIT_SECONDS="${SENSE_WAIT_SECONDS}" \
    "${COLLECTION_SCRIPT}"
  redact_phase_boxids "${phase_dir}"
}

phase_clear_data() {
  adb_cmd shell pm clear "${PACKAGE}" > "${OUT_DIR}/clear-data.log" 2>&1 || true
}

phase_reinstall() {
  adb_cmd uninstall "${PACKAGE}" > "${OUT_DIR}/uninstall.log" 2>&1 || true
}

phase_reboot() {
  local reverse_mappings
  # ADB reverse state is device-runtime state and is normally lost across a
  # reboot. Preserve only the socket mappings in memory so a localhost-backed
  # reporting endpoint remains reachable without recording a raw serial.
  reverse_mappings="$(adb_cmd reverse --list 2>/dev/null \
    | awk 'NF >= 2 {print $(NF-1) "\t" $NF}' || true)"
  adb_cmd reboot
  adb_cmd wait-for-device
  local deadline=$((SECONDS + ${LEONA_POST_REBOOT_WAIT_SECONDS:-180}))
  while (( SECONDS < deadline )); do
    if [[ "$(adb_cmd shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] \
      && adb_cmd shell pm path android >/dev/null 2>&1; then
      break
    fi
    sleep 3
  done
  if [[ "$(adb_cmd shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]]; then
    echo "Device did not finish booting after reboot." >&2
    return 4
  fi
  while IFS=$'\t' read -r remote local; do
    [[ -n "${remote}" && -n "${local}" ]] || continue
    adb_cmd reverse "${remote}" "${local}"
  done <<< "${reverse_mappings}"
  sleep "${LEONA_POST_REBOOT_SETTLE_SECONDS:-12}"
}

summarize() {
  local summary="${OUT_DIR}/stability-summary.md"
  local rows="${OUT_DIR}/phase-results.tsv"
  {
    echo -e "phase\tboxIdHint\tcanonicalHint\tcanonicalSha256\tfingerprintHashSha256\tfingerprintSchemaVersion\tfingerprintSource\tidentityAnchorSource\tstatus"
    local phase phase_dir logcat box_id box_id_sha box_hint canonical_hint canonical_sha fingerprint_sha fingerprint_schema fingerprint_source anchor_source status
    IFS=',' read -ra phase_array <<< "${PHASES}"
    for phase in "${phase_array[@]}"; do
      phase_dir="${OUT_DIR}/${phase}"
      logcat="${phase_dir}/logcat.leona.txt"
      box_id="$(extract_first_json_value boxId "${logcat}")"
      box_id_sha="$(extract_first_json_value boxIdSha256 "${logcat}")"
      if [[ "${box_id_sha}" =~ ^[0-9a-f]{64}$ ]]; then
        box_hint="sha256:${box_id_sha}"
      elif [[ "${box_id}" == '<box-id-redacted>' || "${box_id}" == '<box-i...ted>' ]]; then
        box_hint="redacted"
      else
        box_hint="$([[ -n "${box_id}" ]] && boxid_hint "${box_id}" || true)"
      fi
      canonical_hint="$(extract_first_json_value canonicalDeviceIdHint "${logcat}")"
      canonical_sha="$(extract_first_json_value canonicalDeviceIdSha256 "${logcat}")"
      fingerprint_sha="$(extract_first_json_value fingerprintHashSha256 "${logcat}")"
      fingerprint_schema="$(extract_first_json_value fingerprintSchemaVersion "${logcat}")"
      fingerprint_source="$(extract_first_json_value fingerprintSource "${logcat}")"
      anchor_source="$(extract_first_json_value identityAnchorSource "${logcat}")"
      status="$([[ -n "${fingerprint_sha}" && -n "${fingerprint_schema}" && -n "${fingerprint_source}" && -n "${anchor_source}" ]] && echo pass || echo blocked)"
      echo -e "${phase}\t${box_hint:-not_generated}\t${canonical_hint:-not_generated}\t${canonical_sha:-not_generated}\t${fingerprint_sha:-not_generated}\t${fingerprint_schema:-not_generated}\t${fingerprint_source:-not_generated}\t${anchor_source:-not_generated}\t${status}"
    done
  } > "${rows}"

  local fingerprint_unique_count fingerprint_generated_count canonical_unique_count canonical_generated_count box_id_unique_count box_id_generated_count fingerprint_conclusion canonical_note box_id_note
  fingerprint_generated_count="$(awk -F'\t' 'NR > 1 && $5 != "not_generated" {count++} END {print count+0}' "${rows}")"
  fingerprint_unique_count="$(awk -F'\t' 'NR > 1 && $5 != "not_generated" {seen[$5]=1} END {count=0; for (k in seen) count++; print count}' "${rows}")"
  canonical_generated_count="$(awk -F'\t' 'NR > 1 && $4 != "not_generated" {count++} END {print count+0}' "${rows}")"
  canonical_unique_count="$(awk -F'\t' 'NR > 1 && $4 != "not_generated" {seen[$4]=1} END {count=0; for (k in seen) count++; print count}' "${rows}")"
  box_id_generated_count="$(awk -F'\t' 'NR > 1 && $2 != "not_generated" {count++} END {print count+0}' "${rows}")"
  box_id_unique_count="$(awk -F'\t' 'NR > 1 && $2 != "not_generated" {seen[$2]=1} END {count=0; for (k in seen) count++; print count}' "${rows}")"
  if [[ "${fingerprint_generated_count}" == "0" ]]; then
    fingerprint_conclusion="blocked: no direct sense run generated fingerprint hash evidence."
  elif [[ "${fingerprint_unique_count}" == "1" ]]; then
    fingerprint_conclusion="stable: all generated redacted fingerprintHash SHA-256 values match."
  else
    fingerprint_conclusion="unstable: generated redacted fingerprintHash SHA-256 values differ across phases."
  fi
  if [[ "${canonical_generated_count}" == "0" ]]; then
    canonical_note="not observed"
  elif [[ "${canonical_unique_count}" == "1" ]]; then
    canonical_note="unchanged"
  else
    canonical_note="changed (observation only; server canonical identity is not a fingerprint-stability verdict)"
  fi
  if [[ "${box_id_generated_count}" == "0" ]]; then
    box_id_note="not observed"
  elif [[ "${box_id_unique_count}" == "1" ]]; then
    box_id_note="unchanged"
  else
    box_id_note="changed (observation only; opaque BoxId churn is not a fingerprint-stability verdict)"
  fi

  cat > "${summary}" <<EOF
# Leona Fingerprint Stability

- fingerprint stability status: ${fingerprint_conclusion}
- server canonical observation: ${canonical_note}
- BoxId observation: ${box_id_note}
- device serial hash: $(sha256_text "$(adb_cmd get-serialno 2>/dev/null | tr -d '\r' || true)")
- package: ${PACKAGE}
- trigger mode: direct cloudTest receiver
- UI fallback: not used
- phases: ${PHASES}
- output: ${OUT_DIR}

## Results

$(awk -F'\t' 'NR == 1 {next} {printf "- %s: fingerprint sha256 %s; schema %s; source %s; anchor source %s; BoxId %s; canonical %s / sha256 %s; status %s\n", $1, $5, $6, $7, $8, $2, $3, $4, $9}' "${rows}")

## Interpretation boundary

- This report evaluates only local fingerprintHash stability using its separately redacted SHA-256 value.
- BoxId and canonicalDeviceId are reported as redacted observations only; their churn is not used to classify fingerprint stability.
- SDK diagnostics collect evidence only. Any canonical identity or business verdict remains server-owned.

## Privacy

- fingerprintHash: separately redacted SHA-256 only; raw value is not written to this report
- BoxId values: redacted to hints in shareable reports/log filters
- canonicalDeviceId values: hint/hash only
- raw serial/android_id/fingerprint: hash-only through collection script
- full logcat: not collected unless LEONA_KEEP_FULL_LOGCAT=1 is explicitly set
EOF
}

require_ready
mkdir -p "${OUT_DIR}"

IFS=',' read -ra phase_array <<< "${PHASES}"
for phase in "${phase_array[@]}"; do
  case "${phase}" in
    initial)
      run_collection_phase "${phase}" 1
      ;;
    clear_data)
      phase_clear_data
      run_collection_phase "${phase}" 0
      ;;
    reinstall)
      phase_reinstall
      run_collection_phase "${phase}" 1
      ;;
    reboot)
      phase_reboot
      run_collection_phase "${phase}" 0
      ;;
    *)
      echo "Unknown phase: ${phase}" >&2
      exit 2
      ;;
  esac
done

summarize
echo "Stability summary: ${OUT_DIR}/stability-summary.md"
