from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "run-cloud-device-collection.sh"


def extract_matrix_writer() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("write_matrix_row_template() {")
    end = text.index("\n\nwait_for_adb() {", start)
    return text[start:end]


def extract_redaction_functions() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("redact_secret_file() {")
    end = text.index("\n\nsingle_quote() {", start)
    return text[start:end]


def extract_json_field() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("json_field() {")
    end = text.index("\n\nnormalize_cloud_test_result() {", start)
    return text[start:end]


def extract_normalizer() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("normalize_cloud_test_result() {")
    end = text.index("\n\nadb_cmd() {", start)
    return text[start:end]


class CloudDeviceCollectionTest(unittest.TestCase):
    def test_webshell_contract_has_bounded_timeout_and_dedicated_result_channels(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('--command-timeout "${WETEST_COMMAND_TIMEOUT_SECONDS}"', source)
        self.assertIn("CLOUD_TEST_RUN_ID", source)
        self.assertIn("sense_result=cat /sdcard/Android/data/", source)
        self.assertIn("cloud_result=logcat -d -v raw -s LeonaCloudTest:I", source)

    def test_redacts_exact_and_terminal_wrapped_ansi_secret(self) -> None:
        secret = "synthetic-token-8F3K9P2Q"
        wrapped = "\r\n".join(secret[:9]) + "\x1b[31m" + "\r".join(secret[9:])
        with tempfile.TemporaryDirectory(prefix="leona-redaction-") as temp:
            artifact = Path(temp) / "webshell-helper.log"
            artifact.write_text(
                f"exact={secret}\nwrapped={wrapped}\n",
                encoding="utf-8",
            )
            program = f"""
set -euo pipefail
{extract_redaction_functions()}
redact_secret_file {str(artifact)!r} {secret!r}
"""
            result = subprocess.run(
                ["bash", "-c", program], check=False, capture_output=True, text=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
            output = artifact.read_text(encoding="utf-8")
            self.assertEqual(2, output.count("<redacted>"))
            self.assertNotIn(secret, output)
            for start in range(len(secret) - 7):
                self.assertNotIn(secret[start : start + 8], output)

    def test_redaction_fails_closed_for_residual_significant_fragment(self) -> None:
        secret = "synthetic-token-8F3K9P2Q"
        fragment = secret[4:12]
        with tempfile.TemporaryDirectory(prefix="leona-redaction-fragment-") as temp:
            artifact = Path(temp) / "webshell-helper.log"
            artifact.write_text(f"unrelated={fragment}\n", encoding="utf-8")
            program = f"""
set -euo pipefail
{extract_redaction_functions()}
redact_secret_file {str(artifact)!r} {secret!r}
"""
            result = subprocess.run(
                ["bash", "-c", program], check=False, capture_output=True, text=True
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("residual token fragment", result.stderr)
            output = artifact.read_text(encoding="utf-8")
            self.assertIn("<redaction-failed: residual token removed>", output)
            self.assertNotIn(fragment, output)

    def test_box_id_redaction_handles_uuid_and_lowercase_ulid(self) -> None:
        uuid_box_id = "123e4567-e89b-42d3-a456-426614174000"
        lowercase_ulid_box_id = "01kq5j7y7ns9x5c6m8f3w81b2z"
        with tempfile.TemporaryDirectory(prefix="leona-box-id-redaction-") as temp:
            artifact = Path(temp) / "cloud-result.txt"
            artifact.write_text(
                f'{{"boxId":"{uuid_box_id}"}}\n{{"boxId":"{lowercase_ulid_box_id}"}}\n',
                encoding="utf-8",
            )
            program = f"""
set -euo pipefail
{extract_redaction_functions()}
redact_box_ids_file {str(artifact)!r}
"""
            result = subprocess.run(
                ["bash", "-c", program], check=False, capture_output=True, text=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
            output = artifact.read_text(encoding="utf-8")
            self.assertEqual(2, output.count("<box-id-redacted>"))
            self.assertNotIn(uuid_box_id, output)
            self.assertNotIn(lowercase_ulid_box_id, output)

    def test_box_id_without_verdict_file_is_nounset_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leona-collection-matrix-writer-") as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"fixture-apk")
            for name in ("install.log", "package.txt", "posture.env", "device-summary.env"):
                (root / name).write_text("", encoding="utf-8")
            (root / "logcat.leona.txt").write_text(
                '{"boxId":"123e4567-e89b-12d3-a456-426614174000"}\n',
                encoding="utf-8",
            )
            (root / "sense-result.normalized.json").write_text(
                '{"apiKeyConfigured":true,"boxIdSha256":"' + "a" * 64 + '",'
                '"reportingEndpointConfigured":true,"runIdSha256":"' + "b" * 16 + '",'
                '"status":"success"}\n',
                encoding="utf-8",
            )
            row = root / "matrix-row.md"
            program = f"""
set -euo pipefail
OUT_DIR={str(root)!r}
APK={str(apk)!r}
TRANSPORT=adb
TRIGGER_SENSE=direct
KEEP_FULL_LOGCAT=0
CLOUD_TEST_RUN_ID_SHA256={'b' * 16!r}
prop_value() {{ printf ''; }}
sha256_file() {{ printf '%064d\n' 0; }}
{extract_json_field()}
{extract_matrix_writer()}
write_matrix_row_template {str(row)!r}
"""
            result = subprocess.run(
                ["bash", "-c", program],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            output = row.read_text(encoding="utf-8")
            self.assertIn("Pass / blocked / failed: pass", output)
            self.assertIn("Query this BoxId through your backend verdict integration", output)
            self.assertIn("BoxId: sha256:" + "a" * 64, output)
            self.assertNotIn("123e4567-e89b-12d3-a456-426614174000", output)

    def test_box_id_without_configured_reporting_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leona-collection-local-boxid-") as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"fixture-apk")
            for name in ("install.log", "package.txt", "posture.env", "device-summary.env"):
                (root / name).write_text("", encoding="utf-8")
            (root / "logcat.leona.txt").write_text(
                '{"boxId":"123e4567-e89b-12d3-a456-426614174000"}\n',
                encoding="utf-8",
            )
            (root / "sense-result.normalized.json").write_text(
                '{"apiKeyConfigured":false,"boxIdSha256":"' + "a" * 64 + '",'
                '"reportingEndpointConfigured":false,"runIdSha256":"' + "b" * 16 + '",'
                '"status":"success"}\n',
                encoding="utf-8",
            )
            row = root / "matrix-row.md"
            program = f"""
set -euo pipefail
OUT_DIR={str(root)!r}
APK={str(apk)!r}
TRANSPORT=adb
TRIGGER_SENSE=direct
KEEP_FULL_LOGCAT=0
CLOUD_TEST_RUN_ID_SHA256={'b' * 16!r}
prop_value() {{ printf ''; }}
sha256_file() {{ printf '%064d\n' 0; }}
{extract_json_field()}
{extract_matrix_writer()}
write_matrix_row_template {str(row)!r}
"""
            result = subprocess.run(
                ["bash", "-c", program], check=False, capture_output=True, text=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
            output = row.read_text(encoding="utf-8")
            self.assertIn("Pass / blocked / failed: blocked", output)

    def test_normalizer_skips_a_stale_run_and_accepts_current_correlation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leona-collection-correlated-") as temp:
            root = Path(temp)
            stale = root / "stale.json"
            current = root / "current.json"
            base = {
                "boxId": "123e4567-e89b-42d3-a456-426614174000",
                "canonicalDeviceIdHint": None,
                "canonicalDeviceIdSha256": None,
                "durationMs": 1,
                "reportingEndpointConfigured": True,
                "apiKeyConfigured": True,
            }
            stale.write_text(json.dumps({**base, "runIdSha256": "d" * 16}), encoding="utf-8")
            current.write_text(json.dumps({**base, "runIdSha256": "b" * 16}), encoding="utf-8")
            parser = SCRIPT.parent / "parse-cloud-test-sense-result.py"
            program = f"""
set -euo pipefail
OUT_DIR={str(root)!r}
CLOUD_TEST_RESULT_PARSER={str(parser)!r}
CLOUD_TEST_RUN_ID_SHA256={'b' * 16!r}
{extract_normalizer()}
normalize_cloud_test_result {str(stale)!r} {str(current)!r}
"""
            result = subprocess.run(
                ["bash", "-c", program], check=False, capture_output=True, text=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
            normalized = json.loads((root / "sense-result.normalized.json").read_text())
            self.assertEqual("b" * 16, normalized["runIdSha256"])
            self.assertNotIn(base["boxId"], (root / "sense-result.normalized.json").read_text())


if __name__ == "__main__":
    unittest.main()
