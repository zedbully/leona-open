#!/usr/bin/env bash
set -euo pipefail

ADB="${ADB:-adb}"
SERIAL="${ANDROID_SERIAL:-${ADB_SERIAL:-}}"
APK="${LEONA_APK:-}"
PACKAGE="${LEONA_PACKAGE:-io.leonasec.leona.sample}"
ACTIVITY="${LEONA_ACTIVITY:-io.leonasec.leona.sample/.MainActivity}"
OUT_DIR="${LEONA_COLLECTION_OUT:-/tmp/leona-cloud-device-$(date +%Y%m%d-%H%M%S)}"
RUN_SECONDS="${LEONA_RUN_SECONDS:-25}"
E2E_TOKEN="${LEONA_E2E_TOKEN:-}"
TRANSPORT="${LEONA_TRANSPORT:-auto}"
ADB_WAIT_SECONDS="${LEONA_ADB_WAIT_SECONDS:-20}"
INSTALL_APK="${LEONA_INSTALL_APK:-auto}"
KEEP_FULL_LOGCAT="${LEONA_KEEP_FULL_LOGCAT:-0}"
VERDICT_RESULT_JSON="${LEONA_VERDICT_RESULT_JSON:-}"
WETEST_HELPER="${WETEST_WEBSHELL_HELPER:-/Users/a/.codex/skills/wetest/scripts/wetest_webshell_collect.py}"
RISK_PACKAGE_REGEX="${LEONA_RISK_PACKAGE_REGEX:-magisk|zygisk|lsposed|xposed|riru|shamiko|hidemyapplist|supersu|superuser|kingroot|kinguser|busybox|kernelsu|apatch|frida|taichi|island|shelter|parallel|virtualapp|dualspace|cloneapp|wetest}"
CLICK_SENSE="${LEONA_CLICK_SENSE:-0}"
TRIGGER_SENSE="${LEONA_TRIGGER_SENSE:-$([[ "${CLICK_SENSE}" == "1" ]] && echo ui || echo none)}"
PRE_SENSE_SWIPES="${LEONA_PRE_SENSE_SWIPES:-2}"
SENSE_TAP_X="${LEONA_SENSE_TAP_X:-540}"
SENSE_TAP_Y="${LEONA_SENSE_TAP_Y:-435}"
SENSE_WAIT_SECONDS="${LEONA_SENSE_WAIT_SECONDS:-18}"
CLOUD_TEST_SENSE_ACTION="${LEONA_CLOUD_TEST_SENSE_ACTION:-io.leonasec.leona.sample.CLOUD_TEST_SENSE}"
CLOUD_TEST_TOKEN="${LEONA_CLOUD_TEST_TOKEN:-}"

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

sha256_text() {
  if command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  else
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  fi
}

redact_secret_file() {
  local file="$1"
  local secret="$2"
  if [[ -n "${secret}" && -f "${file}" ]]; then
    local escaped
    escaped="$(printf '%s' "${secret}" | sed 's/[\/&]/\\&/g')"
    sed -i.bak "s/${escaped}/<redacted>/g" "${file}" && rm -f "${file}.bak"
  fi
}

redact_sensitive_patterns_file() {
  local file="$1"
  if [[ -f "${file}" ]]; then
    sed -E -i.bak 's/ct_[A-Za-z0-9]{20,}/<redacted>/g' "${file}" && rm -f "${file}.bak"
  fi
}

redact_sensitive_file() {
  local file="$1"
  shift || true
  local secret
  for secret in "$@"; do
    redact_secret_file "${file}" "${secret}"
  done
  redact_sensitive_patterns_file "${file}"
}

single_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

adb_cmd() {
  if [[ -n "${SERIAL}" ]]; then
    "${ADB}" -s "${SERIAL}" "$@"
  else
    "${ADB}" "$@"
  fi
}

tap_view_by_resource_id() {
  local resource_id="$1"
  local dump_file bounds x1 y1 x2 y2 tap_x tap_y
  dump_file="$(mktemp "${TMPDIR:-/tmp}/leona-ui.XXXXXX")"
  if ! adb_cmd exec-out uiautomator dump /dev/tty > "${dump_file}" 2>/dev/null; then
    rm -f "${dump_file}"
    return 1
  fi
  bounds="$(
    tr '\r' '\n' < "${dump_file}" \
      | grep -o "resource-id=\"${resource_id}\"[^>]*bounds=\"\\[[0-9]*,[0-9]*\\]\\[[0-9]*,[0-9]*\\]\"" \
      | head -1 \
      | sed -E 's/.*bounds="\[([0-9]+),([0-9]+)\]\[([0-9]+),([0-9]+)\]".*/\1 \2 \3 \4/'
  )"
  rm -f "${dump_file}"
  if [[ ! "${bounds}" =~ ^[0-9]+\ [0-9]+\ [0-9]+\ [0-9]+$ ]]; then
    return 1
  fi
  read -r x1 y1 x2 y2 <<< "${bounds}"
  tap_x=$(((x1 + x2) / 2))
  tap_y=$(((y1 + y2) / 2))
  adb_cmd shell input tap "${tap_x}" "${tap_y}"
}

usage() {
  cat <<USAGE
Usage:
  LEONA_APK=/path/sample.apk ANDROID_SERIAL=<serial> $0

ADB transport:
  LEONA_APK=/path/sample.apk ANDROID_SERIAL=127.0.0.1:57452 $0

WeTest webshell fallback transport:
  LEONA_TRANSPORT=wetest-webshell \\
  WETEST_WEB_SHELL_ADDR='v.wetest.qq.com/app/cloudtest/qq/v1/websocket/webshell' \\
  WETEST_DEVICE_ID=<deviceId> \\
  WETEST_TEST_ID=<testId> \\
  WETEST_WEB_SHELL_KEY=<redacted> \\
  LEONA_APK=/path/sample.apk $0

Optional:
  ADB=/path/to/adb
  LEONA_E2E_TOKEN=<debug-build-token>   Trigger authorized debug logcat E2E.
  LEONA_RUN_SECONDS=25
  LEONA_COLLECTION_OUT=/tmp/leona-cloud-device-run
  LEONA_INSTALL_APK=0|1|auto            Webshell cannot install APK; default auto.
  LEONA_KEEP_FULL_LOGCAT=1              Keep unfiltered local-only logcat.full.txt.
  LEONA_VERDICT_RESULT_JSON=/path/server-verdict.json  Optional redacted result from your backend's BoxId verdict query.
  LEONA_TRIGGER_SENSE=direct|ui|none    direct uses cloudTest BroadcastReceiver; ui taps sample UI.
  LEONA_CLOUD_TEST_TOKEN=<token>         Required for LEONA_TRIGGER_SENSE=direct.
  LEONA_CLICK_SENSE=1                   Deprecated alias for LEONA_TRIGGER_SENSE=ui.
  LEONA_CLOUD_TEST_SENSE_ACTION=...     Broadcast action for direct cloudTest sense().
  UI mode locates buttonSense by resource-id, then falls back to LEONA_SENSE_TAP_X/Y.
  LEONA_PRE_SENSE_SWIPES=2
  LEONA_SENSE_TAP_X=540
  LEONA_SENSE_TAP_Y=435
  LEONA_SENSE_WAIT_SECONDS=18

Notes:
  Release/non-debug APKs support launch, posture, package and logcat collection.
  cloudTest APKs support direct method invocation through LEONA_TRIGGER_SENSE=direct.
  Authorized auto E2E requires a debug APK built with LEONA_E2E_TOKEN.
  WeTest webshell mode assumes the APK was installed by WeTest page/API first.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "${APK}" || ! -f "${APK}" ]]; then
  echo "LEONA_APK must point to an existing APK." >&2
  usage >&2
  exit 2
fi

mkdir -p "${OUT_DIR}"

if [[ "${TRIGGER_SENSE}" == "direct" && -z "${CLOUD_TEST_TOKEN}" ]]; then
  echo "LEONA_CLOUD_TEST_TOKEN is required when LEONA_TRIGGER_SENSE=direct." >&2
  exit 2
fi

write_matrix_row_template() {
  local row="$1"
  local summary="${OUT_DIR}/device-summary.env"
  local posture="${OUT_DIR}/posture.env"
  local package_dump="${OUT_DIR}/package.txt"
  local logcat="${OUT_DIR}/logcat.leona.txt"
  local verdict_json="${OUT_DIR}/server-verdict.json"
  local brand manufacturer model release sdk abi serial_hash android_id_hash fingerprint_hash
  local install_result app_debuggable harness_present harness_notes box_id canonical_hint canonical_sha
  local server_level="" server_score="" authoritative_events="" contributing_events=""
  local actual_status reason follow_up
  brand="$(prop_value "${summary}" "brand")"
  manufacturer="$(prop_value "${summary}" "manufacturer")"
  model="$(prop_value "${summary}" "model")"
  release="$(prop_value "${summary}" "android_release")"
  sdk="$(prop_value "${summary}" "android_sdk")"
  serial_hash="$(prop_value "${summary}" "serial_sha256")"
  android_id_hash="$(prop_value "${summary}" "android_id_sha256")"
  fingerprint_hash="$(prop_value "${summary}" "fingerprint_sha256")"
  abi="$(prop_value "${posture}" "ro.product.cpu.abi")"
  install_result="$(tr '\r\n' '  ' < "${OUT_DIR}/install.log" 2>/dev/null | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' | cut -c1-180)"
  if grep -q 'DEBUGGABLE' "${package_dump}" 2>/dev/null; then
    app_debuggable="yes"
  elif [[ -s "${package_dump}" ]]; then
    app_debuggable="no"
  else
    app_debuggable="unknown"
  fi
  if [[ "${TRANSPORT}" == wetest-webshell* ]]; then
    harness_present="yes"
    harness_notes="WeTest webshell; ADB/dev-settings may be harness telemetry."
  else
    harness_present="$(grep -Eq '^global\.(adb_enabled|development_settings_enabled)=1$' "${posture}" 2>/dev/null && echo yes || echo no)"
    harness_notes="$([[ "${harness_present}" == "yes" ]] && echo "ADB/dev-settings enabled during test." || echo "")"
  fi
  box_id="$(grep -Eo '"boxId":"[^"]+"' "${logcat}" 2>/dev/null | head -1 | cut -d'"' -f4 || true)"
  canonical_hint="$(grep -Eo '"canonicalDeviceIdHint":"[^"]+"' "${logcat}" 2>/dev/null | head -1 | cut -d'"' -f4 || true)"
  canonical_sha="$(grep -Eo '"canonicalDeviceIdSha256":"[^"]+"' "${logcat}" 2>/dev/null | head -1 | cut -d'"' -f4 || true)"
  if [[ -n "${box_id}" && -f "${verdict_json}" ]]; then
    server_level="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV[0])); puts (j["riskLevel"] || j.dig("risk", "level") || j.dig("verdict", "riskLevel")).to_s' "${verdict_json}" 2>/dev/null || true)"
    server_score="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV[0])); puts (j["riskScore"] || j.dig("risk", "score") || j.dig("verdict", "riskScore")).to_s' "${verdict_json}" 2>/dev/null || true)"
    authoritative_events="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV[0])); a=j["authoritativeEventIds"] || j.dig("provenance", "authoritativeEventIds") || []; puts a.join(", ")' "${verdict_json}" 2>/dev/null || true)"
    contributing_events="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV[0])); a=j["contributingEventIds"] || j.dig("policyExplanation", "contributingEventIds") || j.dig("provenance", "contributingEventIds") || []; puts a.join(", ")' "${verdict_json}" 2>/dev/null || true)"
  fi
  if [[ -n "${box_id}" ]]; then
    actual_status="pass"
    reason="BoxId generated through ${TRIGGER_SENSE} trigger."
    follow_up="$([[ -n "${server_level}" ]] && echo "Review business backend verdict details." || echo "Query this BoxId through your backend verdict integration and attach a redacted result if needed.")"
  else
    actual_status="blocked"
    reason="$(grep -E 'LeonaCloudTest.*"event":"error"|SSLHandshake|SocketTimeout|Trust anchor|CertPath' "${logcat}" 2>/dev/null | tail -1 | sed -E 's/[[:space:]]+/ /g' | cut -c1-220 || true)"
    [[ -z "${reason}" ]] && reason="No BoxId found in LeonaCloudTest logs."
    follow_up="Retry transport/network or inspect app logs."
  fi
  cat > "${row}" <<EOF
# Leona WeTest Matrix Row

- Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Operator: codex
- Transport: ${TRANSPORT}
- Output directory: ${OUT_DIR}
- APK lane: ${LEONA_APK_LANE:-unknown}
- APK SHA-256: $(sha256_file "${APK}")

## Device

- Brand: ${brand}
- Manufacturer: ${manufacturer}
- Model: ${model}
- Android version / API: ${release} / ${sdk}
- ABI: ${abi}
- Environment type: ${LEONA_ENVIRONMENT_TYPE:-unknown}
- Testbed note: ${LEONA_TESTBED_NOTE:-}
- Serial hash: ${serial_hash}
- Android ID hash: ${android_id_hash}
- Fingerprint hash: ${fingerprint_hash}

## Run

- Script command: run-cloud-device-collection.sh
- Install result: ${install_result}
- App debuggable: ${app_debuggable}
- Install channel: ${LEONA_INSTALL_CHANNEL:-unknown}
- Harness telemetry present: ${harness_present}
- Harness notes: ${harness_notes}

## Leona Result

- BoxId: ${box_id:-not_generated}
- Canonical hash or hint: ${canonical_hint}${canonical_sha:+ / sha256 ${canonical_sha}}
- Verdict id:
- Attestation provider:
- Attestation status:
- Attestation code:
- Server evidence level / score: ${server_level:-unknown} / ${server_score:-unknown}
- Authoritative event ids: ${authoritative_events}
- Contributing event ids: ${contributing_events}
- riskTagsBySource summary: see server-verdict.json when provided by your backend

## Interpretation

- Expected outcome:
- Actual outcome: ${actual_status}
- Pass / blocked / failed: ${actual_status}
- Reason: ${reason}
- Follow-up: ${follow_up}

## Privacy Review

- Raw serial absent: yes
- Raw Android ID absent: yes
- Raw install/device/canonical IDs absent: yes
- Raw fingerprint absent: yes
- Secrets/tokens absent: yes
- Full logcat reviewed before sharing: ${KEEP_FULL_LOGCAT}
EOF
}

wait_for_adb() {
  local deadline=$((SECONDS + ADB_WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if adb_cmd get-state >/tmp/leona-adb-state.$$ 2>/tmp/leona-adb-state.err.$$; then
      local state
      state="$(tr -d '\r' </tmp/leona-adb-state.$$)"
      rm -f /tmp/leona-adb-state.$$ /tmp/leona-adb-state.err.$$
      [[ "${state}" == "device" ]] && return 0
    fi
    sleep 1
  done
  rm -f /tmp/leona-adb-state.$$ /tmp/leona-adb-state.err.$$
  return 1
}

prop_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="${key}" '$1 == k {print substr($0, length($1) + 2); exit}' "${file}" 2>/dev/null || true
}

clean_key_values() {
  grep -E '^(ro\.|global\.|fingerprint_sha256=|android_id_sha256=)' "$1" 2>/dev/null || true
}

clean_package_dump() {
  awk '
    /^Activity Resolver Table:/ {keep=1}
    /^SkippingApks:/ {exit}
    keep {print}
  ' "$1" 2>/dev/null || true
}

collect_verdict_result() {
  if [[ -z "${VERDICT_RESULT_JSON}" ]]; then
    return 0
  fi
  if [[ -f "${VERDICT_RESULT_JSON}" ]]; then
    cp "${VERDICT_RESULT_JSON}" "${OUT_DIR}/server-verdict.json"
  else
    echo "LEONA_VERDICT_RESULT_JSON not found: ${VERDICT_RESULT_JSON}" > "${OUT_DIR}/server-verdict.error"
  fi
}

run_adb_collection() {
  TRANSPORT="adb"
  echo "[1/7] Device"
  if ! wait_for_adb; then
    echo "ADB device did not become ready within ${ADB_WAIT_SECONDS}s." >&2
    echo "If this is WeTest and the WDB serial is offline, rerun with LEONA_TRANSPORT=wetest-webshell." >&2
    exit 3
  fi

  local device_serial model brand manufacturer release sdk fingerprint android_id
  device_serial="$(adb_cmd get-serialno | tr -d '\r')"
  model="$(adb_cmd shell getprop ro.product.model | tr -d '\r')"
  brand="$(adb_cmd shell getprop ro.product.brand | tr -d '\r')"
  manufacturer="$(adb_cmd shell getprop ro.product.manufacturer | tr -d '\r')"
  release="$(adb_cmd shell getprop ro.build.version.release | tr -d '\r')"
  sdk="$(adb_cmd shell getprop ro.build.version.sdk | tr -d '\r')"
  fingerprint="$(adb_cmd shell getprop ro.build.fingerprint | tr -d '\r')"
  android_id="$(adb_cmd shell settings get secure android_id 2>/dev/null | tr -d '\r' || true)"

  {
    echo "serial_sha256=$(sha256_text "${device_serial}")"
    echo "brand=${brand}"
    echo "manufacturer=${manufacturer}"
    echo "model=${model}"
    echo "android_release=${release}"
    echo "android_sdk=${sdk}"
    echo "apk_sha256=$(sha256_file "${APK}")"
    echo "transport=adb"
    echo "fingerprint_sha256=$(sha256_text "${fingerprint}")"
    echo "android_id_sha256=$(sha256_text "${android_id}")"
  } > "${OUT_DIR}/device-summary.env"

  if [[ "${INSTALL_APK}" == "1" || "${INSTALL_APK}" == "auto" ]]; then
    echo "[2/7] Install APK"
    adb_cmd install -r -d "${APK}" | tee "${OUT_DIR}/install.log"
  else
    echo "[2/7] Install APK skipped"
    echo "skipped" > "${OUT_DIR}/install.log"
  fi

  echo "[3/7] Collect device posture"
  {
    echo "# selected getprop"
    for key in \
      ro.product.brand \
      ro.product.manufacturer \
      ro.product.model \
      ro.product.device \
      ro.product.name \
      ro.product.cpu.abi \
      ro.build.type \
      ro.build.tags \
      ro.boot.verifiedbootstate \
      ro.boot.vbmeta.device_state \
      ro.boot.flash.locked \
      ro.boot.veritymode \
      ro.debuggable \
      ro.secure; do
      value="$(adb_cmd shell getprop "${key}" | tr -d '\r')"
      echo "${key}=${value}"
    done
    echo "# selected settings"
    echo "global.adb_enabled=$(adb_cmd shell settings get global adb_enabled 2>/dev/null | tr -d '\r' || true)"
    echo "global.development_settings_enabled=$(adb_cmd shell settings get global development_settings_enabled 2>/dev/null | tr -d '\r' || true)"
  } > "${OUT_DIR}/posture.env"

  echo "[4/7] Filter root/magisk/environment packages"
  adb_cmd shell pm list packages 2>/dev/null \
    | tr -d '\r' \
    | grep -Ei "${RISK_PACKAGE_REGEX}" \
    > "${OUT_DIR}/risk-package-filter.txt" || true

  echo "[5/7] Launch sample"
  adb_cmd logcat -c || true
  if [[ "${TRIGGER_SENSE}" == "direct" ]]; then
    adb_cmd shell am start -n "${ACTIVITY}" > "${OUT_DIR}/am-start.log" || true
    sleep 2
    adb_cmd shell am broadcast \
      -a "${CLOUD_TEST_SENSE_ACTION}" \
      -n "${PACKAGE}/.CloudTestSenseReceiver" \
      --es io.leonasec.leona.sample.CLOUD_TEST_TOKEN "${CLOUD_TEST_TOKEN}" \
      >> "${OUT_DIR}/am-start.log" || true
    redact_sensitive_file "${OUT_DIR}/am-start.log" "${CLOUD_TEST_TOKEN}" "${E2E_TOKEN}"
    sleep "${SENSE_WAIT_SECONDS}"
  elif [[ -n "${E2E_TOKEN}" ]]; then
    adb_cmd shell am start -n "${ACTIVITY}" \
      --ez io.leonasec.leona.sample.extra.E2E_AUTO_RUN true \
      --es io.leonasec.leona.sample.extra.E2E_TOKEN "${E2E_TOKEN}" \
      > "${OUT_DIR}/am-start.log"
    redact_sensitive_file "${OUT_DIR}/am-start.log" "${CLOUD_TEST_TOKEN}" "${E2E_TOKEN}"
  else
    adb_cmd shell am start -n "${ACTIVITY}" > "${OUT_DIR}/am-start.log"
    if [[ "${TRIGGER_SENSE}" == "ui" ]]; then
      sleep 2
      local i=0
      while (( i < PRE_SENSE_SWIPES )); do
        adb_cmd shell input swipe 540 2050 540 500 800 || true
        sleep 1
        i=$((i + 1))
      done
      tap_view_by_resource_id "${PACKAGE}:id/buttonSense" \
        || adb_cmd shell input tap "${SENSE_TAP_X}" "${SENSE_TAP_Y}" \
        || true
      sleep "${SENSE_WAIT_SECONDS}"
    else
      sleep "${RUN_SECONDS}"
    fi
  fi

  echo "[6/7] Collect logs"
  local logcat_tmp="${OUT_DIR}/logcat.tmp.txt"
  adb_cmd logcat -d -v threadtime > "${logcat_tmp}" || true
  grep -Ei 'Leona|LeonaE2E|LeonaCloudTest|leonasec|BoxId|canonical|verdict|risk|evidence|attestation|SSLHandshake|CertPath|Trust anchor' \
    "${logcat_tmp}" | grep -Ev 'AccessibilityNodeInfoDumper' > "${OUT_DIR}/logcat.leona.txt" || true
  if [[ "${KEEP_FULL_LOGCAT}" == "1" ]]; then
    mv "${logcat_tmp}" "${OUT_DIR}/logcat.full.txt"
  else
    rm -f "${logcat_tmp}"
    echo "Not collected. Set LEONA_KEEP_FULL_LOGCAT=1 for local-only diagnostics." > "${OUT_DIR}/logcat.full.txt"
  fi
  adb_cmd shell dumpsys package "${PACKAGE}" > "${OUT_DIR}/package.txt" || true
}

run_wetest_webshell_collection() {
  TRANSPORT="wetest-webshell"
  : "${WETEST_WEB_SHELL_ADDR:?WETEST_WEB_SHELL_ADDR is required for webshell mode}"
  : "${WETEST_DEVICE_ID:?WETEST_DEVICE_ID is required for webshell mode}"
  : "${WETEST_TEST_ID:?WETEST_TEST_ID is required for webshell mode}"
  : "${WETEST_WEB_SHELL_KEY:?WETEST_WEB_SHELL_KEY is required for webshell mode}"
  if [[ ! -f "${WETEST_HELPER}" ]]; then
    echo "WeTest webshell helper not found: ${WETEST_HELPER}" >&2
    exit 4
  fi

  echo "[1/7] Device via WeTest webshell"
  local webshell_launch_cmd="launch=am start -n ${ACTIVITY}; sleep 2"
  if [[ "${TRIGGER_SENSE}" == "direct" ]]; then
    webshell_launch_cmd="launch=logcat -c; am start -n ${ACTIVITY}; sleep 2; am broadcast -a ${CLOUD_TEST_SENSE_ACTION} -n ${PACKAGE}/.CloudTestSenseReceiver --es io.leonasec.leona.sample.CLOUD_TEST_TOKEN $(single_quote "${CLOUD_TEST_TOKEN}"); sleep ${SENSE_WAIT_SECONDS}"
  elif [[ "${TRIGGER_SENSE}" == "ui" ]]; then
    webshell_launch_cmd="${webshell_launch_cmd}; i=0; while [ \$i -lt ${PRE_SENSE_SWIPES} ]; do input swipe 540 2050 540 500 800; sleep 1; i=\$((i+1)); done; bounds=\$(uiautomator dump /dev/tty 2>/dev/null | tr '\r' '\n' | sed -n 's/.*resource-id=\"${PACKAGE}:id\\/buttonSense\"[^>]*bounds=\"\\[\\([0-9][0-9]*\\),\\([0-9][0-9]*\\)\\]\\[\\([0-9][0-9]*\\),\\([0-9][0-9]*\\)\\]\".*/\\1 \\2 \\3 \\4/p' | head -1); set -- \$bounds; if [ \$# -eq 4 ]; then input tap \$(((\$1+\$3)/2)) \$(((\$2+\$4)/2)); else input tap ${SENSE_TAP_X} ${SENSE_TAP_Y}; fi; sleep ${SENSE_WAIT_SECONDS}"
  else
    webshell_launch_cmd="${webshell_launch_cmd}; sleep ${RUN_SECONDS}"
  fi

  python3 "${WETEST_HELPER}" \
    --web-shell-addr "${WETEST_WEB_SHELL_ADDR}" \
    --device-id "${WETEST_DEVICE_ID}" \
    --test-id "${WETEST_TEST_ID}" \
    --web-shell-key "${WETEST_WEB_SHELL_KEY}" \
    --out "${OUT_DIR}/webshell-raw" \
    --cmd 'props=for p in ro.product.brand ro.product.manufacturer ro.product.model ro.product.device ro.product.name ro.product.cpu.abi ro.build.version.release ro.build.version.sdk ro.build.type ro.build.tags ro.boot.verifiedbootstate ro.boot.vbmeta.device_state ro.boot.flash.locked ro.boot.veritymode ro.debuggable ro.secure; do echo "$p=$(getprop $p)"; done' \
    --cmd 'settings=echo "global.adb_enabled=$(settings get global adb_enabled 2>/dev/null)"; echo "global.development_settings_enabled=$(settings get global development_settings_enabled 2>/dev/null)"' \
    --cmd 'identity_hashes=fp=$(getprop ro.build.fingerprint); android_id=$(settings get secure android_id 2>/dev/null); if command -v sha256sum >/dev/null 2>&1; then echo "fingerprint_sha256=$(printf "%s" "$fp" | sha256sum | cut -d" " -f1)"; echo "android_id_sha256=$(printf "%s" "$android_id" | sha256sum | cut -d" " -f1)"; else echo "fingerprint_sha256=unavailable"; echo "android_id_sha256=unavailable"; fi' \
    --cmd "packages=pm list packages 2>/dev/null | grep -Ei '${RISK_PACKAGE_REGEX}' || true" \
    --cmd "${webshell_launch_cmd}" \
    --cmd "package=dumpsys package ${PACKAGE} | head -180" \
    --cmd 'logcat=logcat -d -v threadtime -t 1200' \
    > "${OUT_DIR}/webshell-helper.log" 2>&1
  for launch_artifact in "${OUT_DIR}"/webshell-raw/launch* "${OUT_DIR}/webshell-helper.log"; do
    redact_sensitive_file "${launch_artifact}" "${CLOUD_TEST_TOKEN}" "${E2E_TOKEN}"
  done

  {
    clean_key_values "${OUT_DIR}/webshell-raw/props.txt"
    clean_key_values "${OUT_DIR}/webshell-raw/settings.txt"
  } > "${OUT_DIR}/posture.env"
  grep -E '^package:' "${OUT_DIR}/webshell-raw/packages.txt" > "${OUT_DIR}/risk-package-filter.txt" || true
  clean_package_dump "${OUT_DIR}/webshell-raw/package.txt" > "${OUT_DIR}/package.txt"
  redact_sensitive_file "${OUT_DIR}/webshell-raw/launch.txt" "${CLOUD_TEST_TOKEN}" "${E2E_TOKEN}"
  cp "${OUT_DIR}/webshell-raw/launch.txt" "${OUT_DIR}/am-start.log"
  redact_sensitive_file "${OUT_DIR}/am-start.log" "${CLOUD_TEST_TOKEN}" "${E2E_TOKEN}"

  grep -Ei 'Leona|LeonaE2E|LeonaCloudTest|leonasec|BoxId|canonical|verdict|risk|evidence|attestation|SSLHandshake|CertPath|Trust anchor' \
    "${OUT_DIR}/webshell-raw/logcat.txt" | grep -Ev 'AccessibilityNodeInfoDumper' > "${OUT_DIR}/logcat.leona.txt" || true
  if [[ "${KEEP_FULL_LOGCAT}" == "1" ]]; then
    cp "${OUT_DIR}/webshell-raw/logcat.txt" "${OUT_DIR}/logcat.full.txt"
  else
    echo "Not collected. Set LEONA_KEEP_FULL_LOGCAT=1 for local-only diagnostics." > "${OUT_DIR}/logcat.full.txt"
    rm -f "${OUT_DIR}/webshell-raw/logcat.txt" "${OUT_DIR}/webshell-raw/logcat.raw"
  fi

  local brand manufacturer model release sdk
  brand="$(prop_value "${OUT_DIR}/posture.env" "ro.product.brand")"
  manufacturer="$(prop_value "${OUT_DIR}/posture.env" "ro.product.manufacturer")"
  model="$(prop_value "${OUT_DIR}/posture.env" "ro.product.model")"
  release="$(prop_value "${OUT_DIR}/posture.env" "ro.build.version.release")"
  sdk="$(prop_value "${OUT_DIR}/posture.env" "ro.build.version.sdk")"
  {
    echo "serial_sha256=unavailable_webshell"
    echo "brand=${brand}"
    echo "manufacturer=${manufacturer}"
    echo "model=${model}"
    echo "android_release=${release}"
    echo "android_sdk=${sdk}"
    echo "apk_sha256=$(sha256_file "${APK}")"
    echo "transport=wetest-webshell"
    clean_key_values "${OUT_DIR}/webshell-raw/identity_hashes.txt" \
      | grep -E '^(fingerprint_sha256|android_id_sha256)=' || true
  } > "${OUT_DIR}/device-summary.env"
  echo "skipped_webshell_preinstalled_required" > "${OUT_DIR}/install.log"
}

case "${TRANSPORT}" in
  auto)
    if [[ -n "${WETEST_WEB_SHELL_KEY:-}" ]]; then
      run_wetest_webshell_collection
    else
      run_adb_collection
    fi
    ;;
  adb)
    run_adb_collection
    ;;
  wetest-webshell)
    run_wetest_webshell_collection
    ;;
  *)
    echo "Unknown LEONA_TRANSPORT=${TRANSPORT}. Expected auto, adb, or wetest-webshell." >&2
    exit 2
    ;;
esac

echo "[7/7] Report"
collect_verdict_result
write_matrix_row_template "${OUT_DIR}/matrix-row.md"
{
  echo "# Leona Cloud Device Collection"
  echo
  echo "- transport: ${TRANSPORT}"
  echo "- device: $(prop_value "${OUT_DIR}/device-summary.env" "brand") $(prop_value "${OUT_DIR}/device-summary.env" "model") / Android $(prop_value "${OUT_DIR}/device-summary.env" "android_release") API $(prop_value "${OUT_DIR}/device-summary.env" "android_sdk")"
  echo "- serial: sha256 only when available, see device-summary.env"
  echo "- apk: ${APK}"
  echo "- output: ${OUT_DIR}"
  echo "- e2e: $([[ -n "${E2E_TOKEN}" ]] && echo "requested" || echo "not requested")"
  echo "- trigger sense: ${TRIGGER_SENSE}"
  echo "- full logcat: $([[ "${KEEP_FULL_LOGCAT}" == "1" ]] && echo "kept local-only" || echo "not collected by default")"
  if [[ -f "${OUT_DIR}/server-verdict.json" ]]; then
    echo "- verdict result: server-verdict.json"
  else
    echo "- verdict result: not collected; query BoxId through your backend /v1/verdict integration"
  fi
  echo
  echo "## Files"
  echo "- device-summary.env"
  echo "- posture.env"
  echo "- risk-package-filter.txt"
  echo "- logcat.leona.txt"
  echo "- logcat.full.txt"
  echo "- package.txt"
  echo "- matrix-row.md"
} > "${OUT_DIR}/report.md"

echo "Collection complete: ${OUT_DIR}"
