from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "run-native-runtime-matrix.py"
SPEC = importlib.util.spec_from_file_location("native_runtime_matrix", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NativeRuntimeMatrixContractTest(unittest.TestCase):
    def marker(self, *, api: int = 23, abi: str = "arm64-v8a") -> dict:
        return {
            "apiLevel": api,
            "abi": abi,
            "payloadBytes": 8,
            "payloadSha256": "a" * 64,
        }

    def test_valid_marker_is_admitted_only_for_exact_api_and_abi(self) -> None:
        ok, reason = MODULE.validate_smoke_marker(
            self.marker(), api=23, abi="arm64-v8a", apk_sha256="b" * 64, text="OK"
        )
        self.assertTrue(ok)
        self.assertEqual("native-load-init-collect", reason)

    def test_candidate_hash_drift_fails_closed(self) -> None:
        ok, reason = MODULE.validate_smoke_marker(
            self.marker(), api=23, abi="arm64-v8a", apk_sha256="not-a-sha", text="OK"
        )
        self.assertFalse(ok)
        self.assertEqual("candidate-apk-sha256-invalid", reason)

    def test_api_and_abi_mismatch_fail_closed(self) -> None:
        ok, reason = MODULE.validate_smoke_marker(
            self.marker(api=24), api=23, abi="arm64-v8a", apk_sha256="b" * 64, text="OK"
        )
        self.assertFalse(ok)
        self.assertEqual("api-mismatch", reason)
        ok, reason = MODULE.validate_smoke_marker(
            self.marker(abi="x86_64"), api=23, abi="arm64-v8a", apk_sha256="b" * 64, text="OK"
        )
        self.assertFalse(ok)
        self.assertEqual("abi-mismatch", reason)

    def test_missing_marker_and_native_crash_are_not_pass(self) -> None:
        ok, reason = MODULE.validate_smoke_marker(
            None, api=23, abi="arm64-v8a", apk_sha256="b" * 64, text="UnsatisfiedLinkError"
        )
        self.assertFalse(ok)
        self.assertEqual("native-load-or-crash-marker", reason)
        ok, reason = MODULE.validate_smoke_marker(
            None, api=23, abi="arm64-v8a", apk_sha256="b" * 64, text="stale marker absent"
        )
        self.assertFalse(ok)
        self.assertEqual("native-smoke-marker-missing", reason)

    def test_matrix_mixed_candidate_and_raw_identity_are_rejected(self) -> None:
        rows = [
            {"status": "PASS", "artifactHashes": {"sampleApkSha256": "a" * 64}},
            {"status": "PASS", "artifactHashes": {"sampleApkSha256": "b" * 64}},
        ]
        ok, reason = MODULE.validate_matrix_candidate(rows)
        self.assertFalse(ok)
        self.assertEqual("mixed-candidate", reason)
        rows[1]["artifactHashes"]["sampleApkSha256"] = "a" * 64
        rows[1]["serial"] = "emulator-5554"
        ok, reason = MODULE.validate_matrix_candidate(rows)
        self.assertFalse(ok)
        self.assertEqual("raw-identifier-present", reason)

    def test_unsupported_payload_bound_is_rejected(self) -> None:
        marker = self.marker()
        marker["payloadBytes"] = 131_073
        ok, reason = MODULE.validate_smoke_marker(
            marker, api=23, abi="arm64-v8a", apk_sha256="b" * 64, text="OK"
        )
        self.assertFalse(ok)
        self.assertEqual("payload-bound-invalid", reason)


if __name__ == "__main__":
    unittest.main()
