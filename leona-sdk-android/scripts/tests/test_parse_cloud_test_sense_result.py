from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "parse-cloud-test-sense-result.py"
BOX_ID = "123e4567-e89b-42d3-a456-426614174000"
ULID_BOX_ID = "01KQ5J7Y7NS9X5C6M8F3W81B2Z"
RUN_ID_SHA256 = "c" * 16


class ParseCloudTestSenseResultTest(unittest.TestCase):
    def run_parser(self, payload: object, *, now: int = 1_700_000_000, age: int = 1) -> subprocess.CompletedProcess[str]:
        temp = tempfile.TemporaryDirectory(prefix="leona-cloudtest-result-")
        self.addCleanup(temp.cleanup)
        artifact = Path(temp.name) / "leona-cloudtest-sense-result.json"
        artifact.write_text(json.dumps(payload), encoding="utf-8")
        os.utime(artifact, (now - age, now - age))
        return subprocess.run(
            [str(SCRIPT), "--input", str(artifact), "--now-epoch", str(now), "--format", "line"],
            check=False,
            capture_output=True,
            text=True,
        )

    def test_success_is_deterministic_and_never_echoes_box_id(self) -> None:
        result = self.run_parser({
            "boxId": BOX_ID,
            "canonicalDeviceIdHint": "abcd...wxyz",
            "canonicalDeviceIdSha256": "a" * 16,
            "durationMs": 23,
            "reportingEndpointConfigured": True,
            "apiKeyConfigured": True,
        })
        self.assertEqual(0, result.returncode, result.stderr)
        normalized = json.loads(result.stdout)
        self.assertEqual("success", normalized["status"])
        self.assertEqual(hashlib.sha256(BOX_ID.encode()).hexdigest(), normalized["boxIdSha256"])
        self.assertNotIn(BOX_ID, result.stdout)
        self.assertEqual("abcd...wxyz", normalized["canonicalDeviceIdHint"])
        self.assertTrue(normalized["reportingEndpointConfigured"])
        self.assertTrue(normalized["apiKeyConfigured"])

    def test_accepts_current_ulid_and_correlates_the_run(self) -> None:
        payload = {
            "boxId": ULID_BOX_ID,
            "canonicalDeviceIdHint": "abcd...wxyz",
            "canonicalDeviceIdSha256": "a" * 16,
            "durationMs": 23,
            "reportingEndpointConfigured": True,
            "apiKeyConfigured": True,
            "runIdSha256": RUN_ID_SHA256,
        }
        with tempfile.TemporaryDirectory(prefix="leona-cloudtest-correlated-") as temp:
            artifact = Path(temp) / "result.json"
            artifact.write_text(json.dumps(payload), encoding="utf-8")
            os.utime(artifact, (1_700_000_000, 1_700_000_000))
            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--input",
                    str(artifact),
                    "--now-epoch",
                    "1700000000",
                    "--expected-run-id-sha256",
                    RUN_ID_SHA256,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        normalized = json.loads(result.stdout)
        self.assertEqual(RUN_ID_SHA256, normalized["runIdSha256"])
        self.assertEqual(hashlib.sha256(ULID_BOX_ID.encode()).hexdigest(), normalized["boxIdSha256"])
        self.assertNotIn(ULID_BOX_ID, result.stdout)

    def test_rejects_stale_or_mismatched_run_correlation(self) -> None:
        payload = {
            "boxId": BOX_ID,
            "canonicalDeviceIdHint": None,
            "canonicalDeviceIdSha256": None,
            "durationMs": 1,
            "reportingEndpointConfigured": True,
            "apiKeyConfigured": True,
            "runIdSha256": "d" * 16,
        }
        with tempfile.TemporaryDirectory(prefix="leona-cloudtest-mismatch-") as temp:
            artifact = Path(temp) / "result.json"
            artifact.write_text(json.dumps(payload), encoding="utf-8")
            result = subprocess.run(
                [
                    str(SCRIPT),
                    "--input",
                    str(artifact),
                    "--max-age-seconds",
                    "-1",
                    "--expected-run-id-sha256",
                    RUN_ID_SHA256,
                ],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(2, result.returncode)
        self.assertNotIn(BOX_ID, result.stdout + result.stderr)

    def test_error_redacts_message_and_class(self) -> None:
        result = self.run_parser({"error": {
            "class": "java.net.SocketTimeoutException",
            "messageSha256": "b" * 16,
            "durationMs": 8,
            "reportingEndpointConfigured": True,
            "apiKeyConfigured": True,
        }})
        self.assertEqual(0, result.returncode, result.stderr)
        normalized = json.loads(result.stdout)
        self.assertEqual("error", normalized["status"])
        self.assertNotIn("SocketTimeoutException", result.stdout)

    def test_rejects_unknown_identity_field_without_echoing_value(self) -> None:
        raw_identity = "device-identity-value-should-not-escape"
        result = self.run_parser({
            "boxId": BOX_ID, "canonicalDeviceIdHint": "abcd...wxyz",
            "canonicalDeviceIdSha256": "a" * 16, "durationMs": 1, "serial": raw_identity,
        })
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertNotIn(raw_identity, result.stderr)

    def test_rejects_secret_like_input_without_echoing_value(self) -> None:
        secret = "ct_abcdefghijklmnopqrstuvwxyz123456"
        result = self.run_parser({"error": {"class": "java.lang.RuntimeException", "message": secret, "durationMs": 1}})
        self.assertEqual(2, result.returncode)
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_rejects_malformed_canonical_values_and_stale_artifacts(self) -> None:
        malformed = self.run_parser({"boxId": BOX_ID, "canonicalDeviceIdHint": "raw-canonical-device", "canonicalDeviceIdSha256": "a" * 16, "durationMs": 1})
        self.assertEqual(2, malformed.returncode)
        stale = self.run_parser({"boxId": BOX_ID, "canonicalDeviceIdHint": "abcd...wxyz", "canonicalDeviceIdSha256": "a" * 16, "durationMs": 1}, age=301)
        self.assertEqual(2, stale.returncode)

    def test_accepts_receiver_null_canonical_pair_and_empty_error_message(self) -> None:
        success = self.run_parser({"boxId": BOX_ID, "canonicalDeviceIdHint": None, "canonicalDeviceIdSha256": None, "durationMs": 1})
        self.assertEqual(0, success.returncode, success.stderr)
        self.assertIsNone(json.loads(success.stdout)["canonicalDeviceIdHint"])
        error = self.run_parser({"error": {"class": "java.lang.RuntimeException", "message": "", "durationMs": 1}})
        self.assertEqual(0, error.returncode, error.stderr)

    def test_extracts_one_terminal_event_from_bounded_log_capture(self) -> None:
        payload = {
            "boxId": BOX_ID,
            "canonicalDeviceIdHint": "abcd...wxyz",
            "canonicalDeviceIdSha256": "a" * 16,
            "durationMs": 23,
            "reportingEndpointConfigured": True,
            "apiKeyConfigured": True,
        }
        capture = "ignored command echo\n" + json.dumps({"event": "sense", "payload": payload}) + "\n"
        temp = tempfile.TemporaryDirectory(prefix="leona-cloudtest-log-")
        self.addCleanup(temp.cleanup)
        artifact = Path(temp.name) / "cloud_result.txt"
        artifact.write_text(capture, encoding="utf-8")
        os.utime(artifact, (1_700_000_000, 1_700_000_000))
        result = subprocess.run(
            [str(SCRIPT), "--input", str(artifact), "--now-epoch", "1700000000", "--format", "line"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("success", json.loads(result.stdout)["status"])
        self.assertNotIn(BOX_ID, result.stdout)

    def test_rejects_ambiguous_terminal_events(self) -> None:
        first = {"event": "sense", "payload": {
            "boxId": BOX_ID,
            "canonicalDeviceIdHint": None,
            "canonicalDeviceIdSha256": None,
            "durationMs": 1,
        }}
        second = {"event": "error", "payload": {
            "class": "java.lang.IllegalStateException",
            "message": "failed",
            "durationMs": 2,
        }}
        temp = tempfile.TemporaryDirectory(prefix="leona-cloudtest-ambiguous-")
        self.addCleanup(temp.cleanup)
        artifact = Path(temp.name) / "cloud_result.txt"
        artifact.write_text(json.dumps(first) + "\n" + json.dumps(second), encoding="utf-8")
        os.utime(artifact, (1_700_000_000, 1_700_000_000))
        result = subprocess.run(
            [str(SCRIPT), "--input", str(artifact), "--now-epoch", "1700000000"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(2, result.returncode)
        self.assertEqual("", result.stdout)

    def test_help_and_output_file_are_supported(self) -> None:
        help_result = subprocess.run([str(SCRIPT), "--help"], check=False, capture_output=True, text=True)
        self.assertEqual(0, help_result.returncode)
        self.assertIn("--max-age-seconds", help_result.stdout)
        with tempfile.TemporaryDirectory(prefix="leona-cloudtest-output-") as temp:
            root = Path(temp)
            artifact = root / "leona-cloudtest-sense-result.json"
            output = root / "normalized.json"
            artifact.write_text(json.dumps({"boxId": BOX_ID, "canonicalDeviceIdHint": "abcd...wxyz", "canonicalDeviceIdSha256": "a" * 16, "durationMs": 1}), encoding="utf-8")
            os.utime(artifact, (1_700_000_000, 1_700_000_000))
            result = subprocess.run([str(SCRIPT), "--input", str(artifact), "--output", str(output), "--now-epoch", "1700000000"], check=False, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stdout)
            self.assertEqual("success", json.loads(output.read_text(encoding="utf-8"))["status"])


if __name__ == "__main__":
    unittest.main()
