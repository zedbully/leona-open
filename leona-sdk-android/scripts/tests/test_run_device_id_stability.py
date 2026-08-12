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
    def test_receiver_contract_is_fingerprint_specific_and_legacy_terminal_safe(self) -> None:
        receiver = (
            Path(__file__).resolve().parents[2]
            / "sample-app/src/cloudTest/kotlin/io/leonasec/leona/sample/CloudTestSenseReceiver.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('put("fingerprintHashSha256", fingerprintDiagnosticSha256(diagnostic.fingerprintHash))', receiver)
        self.assertEqual(1, receiver.count('put("boxId", boxId.toString())'))
        self.assertEqual(2, receiver.count('put("boxId", BOX_ID_REDACTED)'))
        self.assertIn('val persistedPayload = JSONObject()', receiver)
        self.assertIn('val fingerprintPayload = JSONObject()', receiver)
        self.assertIn('persistAndEmit(context, "sense", persistedPayload, terminalPayload)', receiver)
        self.assertIn('private fun fingerprintDiagnosticSha256(value: String?): Any', receiver)
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
                        '"canonicalDeviceIdSha256":"%s","fingerprintHashSha256":"%s",' % (canonical, "a" * 64),
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
                self.assertEqual("pass", columns[8])
                self.assertRegex(columns[4], re.compile(r"[0-9a-f]{64}\Z"))


if __name__ == "__main__":
    unittest.main()
