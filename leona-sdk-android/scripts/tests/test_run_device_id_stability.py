from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
import re


SCRIPT = Path(__file__).resolve().parents[1] / "run-device-id-stability.sh"


def extract_summarize() -> str:
    source = SCRIPT.read_text(encoding="utf-8")
    start = source.index("summarize() {")
    end = source.index("\n\nrequire_ready", start)
    return source[start:end]


class DeviceIdStabilityScriptTest(unittest.TestCase):
    def test_receiver_contract_is_fingerprint_specific_and_hash_only_terminal_safe(self) -> None:
        receiver = (
            Path(__file__).resolve().parents[2]
            / "sample-app/src/cloudTest/kotlin/io/leonasec/leona/sample/CloudTestSenseReceiver.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('put("fingerprintHashSha256", fingerprintDiagnosticSha256(diagnostic.fingerprintHash))', receiver)
        self.assertIn('put("serverInstallIdSha256", serverInstallIdSha256)', receiver)
        self.assertNotIn('put("boxId", boxId.toString())', receiver)
        self.assertNotIn('BOX_ID_REDACTED', receiver)
        self.assertNotIn('BOX_ID_NOT_GENERATED', receiver)
        self.assertEqual(3, receiver.count('put("boxIdSha256",'))
        self.assertIn('val boxIdSha256 = sha256Hex(boxId.toString())', receiver)
        self.assertIn('val terminalPayload = JSONObject()', receiver)
        self.assertIn('val fingerprintPayload = JSONObject()', receiver)
        self.assertIn('persistAndEmit(context, "sense", terminalPayload, terminalPayload)', receiver)
        self.assertIn('private fun fingerprintDiagnosticSha256(value: String?): Any', receiver)
        self.assertIn('private fun sha256Hex(value: String): String', receiver)
        self.assertIn('MessageDigest.getInstance("SHA-256")', receiver)
        self.assertIn('.joinToString("") { "%02x".format(it.toInt() and 0xff) }', receiver)
        self.assertIn('put("fingerprintSchemaVersion", diagnostic.fingerprintSchemaVersion.toString())', receiver)
        self.assertIn('put("fingerprintSource", diagnostic.fingerprintSource)', receiver)
        self.assertIn('put("identityAnchorSource", diagnostic.identityAnchorSource)', receiver)
        self.assertIn('emit("fingerprint_diagnostic", fingerprintPayload)', receiver)
        self.assertIn('emit("sense", terminalPayload)', receiver)

    def test_summary_classifies_fingerprint_independently_from_boxid_and_canonical_churn(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leona-stability-test-") as temp:
            root = Path(temp)
            for phase, box_id, canonical in (
                ("initial", "123e4567-e89b-42d3-a456-426614174000", "a" * 16),
                ("reinstall", "223e4567-e89b-42d3-a456-426614174000", "b" * 16),
            ):
                phase_dir = root / phase
                phase_dir.mkdir()
                (phase_dir / "logcat.leona.txt").write_text(
                    "\n".join((
                        '{"boxId":"%s","canonicalDeviceIdHint":"abcd...wxyz",' % box_id,
                        '"canonicalDeviceIdSha256":"%s","serverInstallIdSha256":"%s",' % (canonical, "b" * 16),
                        '"fingerprintHashSha256":"%s",' % ("a" * 64),
                        '"fingerprintSchemaVersion":"3","fingerprintSource":"native",'
                        '"identityAnchorSource":"install"}',
                    )),
                    encoding="utf-8",
                )
            program = f'''set -euo pipefail
OUT_DIR={str(root)!r}
PHASES='initial,reinstall'
PACKAGE=io.leonasec.leona.sample
SERIAL=''
sha256_text() {{ printf '%s' "$1" | shasum -a 256 | awk '{{print $1}}'; }}
adb_cmd() {{ printf 'serial'; }}
boxid_hint() {{ local value="$1"; printf '<redacted:%s>' "$(sha256_text "$value" | cut -c1-16)"; }}
extract_first_json_value() {{ local key="$1" file="$2"; grep -Eo "\\\"${{key}}\\\":\\\"[^\\\"]+\\\"" "$file" | head -1 | cut -d'"' -f4 || true; }}
{extract_summarize()}
summarize
'''
            result = subprocess.run(["bash", "-c", program], check=False, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            summary = (root / "stability-summary.md").read_text(encoding="utf-8")
            self.assertIn("fingerprint stability status: stable", summary)
            self.assertIn("server canonical observation: changed", summary)
            self.assertIn("BoxId observation: changed", summary)
            self.assertIn("their churn is not used to classify fingerprint stability", summary)
            self.assertNotIn("123e4567-e89b-42d3-a456-426614174000", summary)
            self.assertNotIn("canonical-one", summary)
            rows = (root / "phase-results.tsv").read_text(encoding="utf-8").splitlines()
            self.assertEqual(3, len(rows))
            for row in rows[1:]:
                columns = row.split("\t")
                self.assertEqual("pass", columns[9])
                self.assertRegex(columns[4], re.compile(r"[0-9a-f]{16}\Z"))
                self.assertRegex(columns[5], re.compile(r"[0-9a-f]{64}\Z"))

    def test_summary_accepts_hash_only_box_observations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leona-stability-hash-only-test-") as temp:
            root = Path(temp)
            for phase in ("initial", "reboot"):
                phase_dir = root / phase
                phase_dir.mkdir()
                (phase_dir / "logcat.leona.txt").write_text(
                    '{"boxIdSha256":"%s","canonicalDeviceIdHint":null,'
                    '"canonicalDeviceIdSha256":null,"fingerprintHashSha256":"%s",'
                    '"fingerprintSchemaVersion":"4","fingerprintSource":"virtual_instance_anchor_v4",'
                    '"identityAnchorSource":"virtual_instance_anchor"}\n'
                    % ("b" * 64, "a" * 64),
                    encoding="utf-8",
                )
            program = f'''set -euo pipefail
OUT_DIR={str(root)!r}
PHASES='initial,reboot'
PACKAGE=io.leonasec.leona.sample
SERIAL=''
sha256_text() {{ printf '%s' "$1" | shasum -a 256 | awk '{{print $1}}'; }}
adb_cmd() {{ printf 'serial'; }}
boxid_hint() {{ local value="$1"; printf '<redacted:%s>' "$(sha256_text "$value" | cut -c1-16)"; }}
extract_first_json_value() {{ local key="$1" file="$2"; grep -Eo "\\\"${{key}}\\\":\\\"[^\\\"]+\\\"" "$file" | head -1 | cut -d'"' -f4 || true; }}
{extract_summarize()}
summarize
'''
            result = subprocess.run(["bash", "-c", program], check=False, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            summary = (root / "stability-summary.md").read_text(encoding="utf-8")
            self.assertIn("fingerprint stability status: stable", summary)
            self.assertIn("BoxId observation: unchanged", summary)
            self.assertNotIn('"boxId":', summary)
            rows = (root / "phase-results.tsv").read_text(encoding="utf-8").splitlines()
            self.assertEqual("sha256:" + "b" * 64, rows[1].split("\t")[1])

    def test_reboot_phase_restores_adb_reverse_after_boot_completion(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("phase_reboot() {")
        end = source.index("\n}\n\nsummarize()", start)
        reboot = source[start:end]
        self.assertIn("adb_cmd reverse --list", reboot)
        self.assertIn("getprop sys.boot_completed", reboot)
        self.assertIn('adb_cmd reverse "${remote}" "${local}"', reboot)

    def test_flash_like_reset_is_explicit_hook_only_and_suppresses_hook_output(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        start = source.index("phase_flash_like_reset() {")
        end = source.index("\n}\n\nsummarize()", start)
        hook = source[start:end]
        self.assertIn('FLASH_LIKE_RESET_COMMAND="${LEONA_FLASH_LIKE_RESET_COMMAND:-}"', source)
        self.assertIn('FLASH_LIKE_RESET_ENABLED="${LEONA_FLASH_LIKE_RESET_ENABLED:-}"', source)
        self.assertIn('"${FLASH_LIKE_RESET_ENABLED}" != "1"', hook)
        self.assertIn('"${FLASH_LIKE_RESET_COMMAND}" != /*', hook)
        self.assertIn('"${FLASH_LIKE_RESET_COMMAND}" >/dev/null 2>&1', hook)
        self.assertNotIn("eval ", hook)
        self.assertIn("flash_like_reset)", source)
        self.assertIn('run_collection_phase "${phase}" 1', source)

    def test_blocked_report_redacts_adb_target_to_a_hash(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("serial_hint()", source)
        self.assertIn('printf \'sha256:%s\' "$(sha256_text "${SERIAL}")"', source)
        self.assertIn("- adb target: $(serial_hint)", source)
        self.assertNotIn("- adb target: ${SERIAL:-not specified}", source)


if __name__ == "__main__":
    unittest.main()
