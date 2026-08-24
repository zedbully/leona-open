#!/usr/bin/env bash
set -euo pipefail

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-${ADB_SERIAL:-}}"
APK="${LEONA_APK:-}"
PACKAGE="${LEONA_PACKAGE:-io.leonasec.leona.sample}"
OUT_DIR="${LEONA_CLOCK_OUT:-/tmp/leona-clock-skew-regression-$(date +%Y%m%d-%H%M%S)}"
COLLECTION_SCRIPT="${LEONA_COLLECTION_SCRIPT:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/run-cloud-device-collection.sh}"
CLOUD_TEST_TOKEN="${LEONA_CLOUD_TEST_TOKEN:-}"
PHASES="${LEONA_CLOCK_PHASES:-baseline,clear_data}"
SENSE_WAIT_SECONDS="${LEONA_SENSE_WAIT_SECONDS:-22}"

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
  if (( ${#value} <= 12 )); then
    printf '<redacted:%s>' "$(sha256_text "${value}" | cut -c1-16)"
  else
    printf '%s...%s' "${value:0:6}" "${value: -4}"
  fi
}

serial_hint() {
  if [[ -n "${SERIAL}" ]]; then
    printf 'sha256:%s' "$(sha256_text "${SERIAL}")"
  else
    printf 'not specified'
  fi
}

extract_first_json_value() {
  local key="$1"
  local file="$2"
  grep -Eo "\"${key}\":\"[^\"]+\"" "${file}" 2>/dev/null | head -1 | cut -d'"' -f4 || true
}

classify_error() {
  local logcat="$1"
  if [[ ! -f "${logcat}" ]]; then
    printf 'no_logcat'
  elif grep -Eiq 'LEONA_TIMESTAMP_SKEW|timestamp_skew|timestamp outside acceptable window|clock[-_ ]?skew' "${logcat}"; then
    printf 'timestamp_skew'
  elif grep -Eiq 'SocketTimeout|timed out|ETIMEDOUT' "${logcat}"; then
    printf 'network_timeout'
  elif grep -Eiq 'LEONA_AUTH|auth_failed|HTTP 401| 401 ' "${logcat}"; then
    printf 'auth_failed'
  elif grep -Eiq 'HTTP 5[0-9][0-9]|server_5xx| 5[0-9][0-9] ' "${logcat}"; then
    printf 'server_5xx'
  else
    printf 'no_boxid'
  fi
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

device_epoch_seconds() {
  adb_cmd shell date +%s 2>/dev/null | tr -d '\r' | head -1 | grep -Eo '^[0-9]+' || true
}

capture_clock_snapshot() {
  local out="$1"
  local host_epoch device_epoch offset_ms auto_time auto_time_zone timezone wallclock
  host_epoch="$(date +%s)"
  device_epoch="$(device_epoch_seconds)"
  auto_time="$(adb_cmd shell settings get global auto_time 2>/dev/null | tr -d '\r' || true)"
  auto_time_zone="$(adb_cmd shell settings get global auto_time_zone 2>/dev/null | tr -d '\r' || true)"
  timezone="$(adb_cmd shell getprop persist.sys.timezone 2>/dev/null | tr -d '\r' || true)"
  wallclock="$(adb_cmd shell date 2>/dev/null | tr -d '\r' || true)"
  if [[ -n "${device_epoch}" ]]; then
    offset_ms="$(( (device_epoch - host_epoch) * 1000 ))"
  else
    offset_ms="unknown"
  fi
  cat > "${out}" <<EOF
host_epoch_seconds=${host_epoch}
device_epoch_seconds=${device_epoch:-unknown}
device_minus_host_ms=${offset_ms}
global_auto_time=${auto_time:-unknown}
global_auto_time_zone=${auto_time_zone:-unknown}
persist_sys_timezone=${timezone:-unknown}
device_wallclock=${wallclock:-unknown}
EOF
}

write_blocked_report() {
  local reason="$1"
  mkdir -p "${OUT_DIR}"
  cat > "${OUT_DIR}/clock-skew-summary.md" <<EOF
# Leona Clock Skew Regression

- status: blocked
- reason: ${reason}
- trigger mode: direct cloudTest receiver only
- UI fallback: not used
- package: ${PACKAGE}
- adb target: $(serial_hint)

## Privacy

- BoxId values: not generated
- raw serial/android_id/fingerprint: not collected by this wrapper
EOF
  echo "Blocked: ${reason}" >&2
  echo "Report: ${OUT_DIR}/clock-skew-summary.md" >&2
}

require_ready() {
  if [[ -z "${APK}" || ! -f "${APK}" ]]; then
    write_blocked_report "LEONA_APK must point to an existing cloudTest APK."
    exit 2
  fi
  if [[ -z "${CLOUD_TEST_TOKEN}" ]]; then
    write_blocked_report "LEONA_CLOUD_TEST_TOKEN is required for direct cloudTest sense()."
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
  capture_clock_snapshot "${phase_dir}/clock.env"
  LEONA_APK="${APK}" \
    ANDROID_SERIAL="${SERIAL}" \
    LEONA_PACKAGE="${PACKAGE}" \
    LEONA_COLLECTION_OUT="${phase_dir}" \
    LEONA_INSTALL_APK="${install_mode}" \
    LEONA_TRIGGER_SENSE=direct \
    LEONA_CLOUD_TEST_TOKEN="${CLOUD_TEST_TOKEN}" \
    LEONA_SENSE_WAIT_SECONDS="${SENSE_WAIT_SECONDS}" \
    "${COLLECTION_SCRIPT}" || true
  redact_phase_boxids "${phase_dir}"
}

summarize() {
  local rows="${OUT_DIR}/clock-results.tsv"
  local summary="${OUT_DIR}/clock-skew-summary.md"
  {
    echo -e "phase\tdeviceMinusHostMs\tboxIdHint\tcanonicalHint\tcanonicalSha256\tstatus\terrorClass"
    local phase phase_dir logcat clock box_id box_hint canonical_hint canonical_sha status error_class offset
    IFS=',' read -ra phase_array <<< "${PHASES}"
    for phase in "${phase_array[@]}"; do
      phase_dir="${OUT_DIR}/${phase}"
      logcat="${phase_dir}/logcat.leona.txt"
      clock="${phase_dir}/clock.env"
      box_id="$(extract_first_json_value boxId "${logcat}")"
      box_hint="$([[ -n "${box_id}" ]] && boxid_hint "${box_id}" || true)"
      canonical_hint="$(extract_first_json_value canonicalDeviceIdHint "${logcat}")"
      canonical_sha="$(extract_first_json_value canonicalDeviceIdSha256 "${logcat}")"
      offset="$(grep '^device_minus_host_ms=' "${clock}" 2>/dev/null | cut -d= -f2- || true)"
      if [[ -n "${box_id}" ]]; then
        status="pass"
        error_class="none"
      else
        status="blocked"
        error_class="$(classify_error "${logcat}")"
      fi
      echo -e "${phase}\t${offset:-unknown}\t${box_hint:-not_generated}\t${canonical_hint:-not_generated}\t${canonical_sha:-not_generated}\t${status}\t${error_class}"
    done
  } > "${rows}"

  local blocked_count conclusion
  blocked_count="$(awk -F'\t' 'NR > 1 && $6 != "pass" {count++} END {print count+0}' "${rows}")"
  if [[ "${blocked_count}" == "0" ]]; then
    conclusion="pass: all direct sense phases generated BoxId despite observed clock offset."
  else
    conclusion="blocked: one or more phases failed to generate BoxId; inspect errorClass and logcat.leona.txt."
  fi

  cat > "${summary}" <<EOF
# Leona Clock Skew Regression

- status: ${conclusion}
- device serial hash: $(sha256_text "$(adb_cmd get-serialno 2>/dev/null | tr -d '\r' || true)")
- package: ${PACKAGE}
- trigger mode: direct cloudTest receiver
- UI fallback: not used
- phases: ${PHASES}
- output: ${OUT_DIR}

## Results

$(awk -F'\t' 'NR == 1 {next} {printf "- %s: device-host offset %s ms, BoxId %s, canonical %s / sha256 %s, status %s, error %s\n", $1, $2, $3, $4, $5, $6, $7}' "${rows}")

## Interpretation

- `timestamp_skew` is a transport/authentication diagnostic, not device risk evidence.
- Public hosted reporting should not depend on APK device-wall-clock signing.
- Private signed reporting should refresh session/handshake when the server returns a clear timestamp-skew marker.

## Privacy

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
    baseline)
      run_collection_phase "${phase}" auto
      ;;
    clear_data)
      adb_cmd shell pm clear "${PACKAGE}" > "${OUT_DIR}/clear-data.log" 2>&1 || true
      run_collection_phase "${phase}" 0
      ;;
    reinstall)
      adb_cmd uninstall "${PACKAGE}" > "${OUT_DIR}/uninstall.log" 2>&1 || true
      run_collection_phase "${phase}" 1
      ;;
    *)
      echo "Unknown phase: ${phase}" >&2
      exit 2
      ;;
  esac
done

summarize
echo "Clock skew summary: ${OUT_DIR}/clock-skew-summary.md"
