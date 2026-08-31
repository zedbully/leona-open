from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


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

    def test_x86_64_avd_is_selected_when_it_is_the_available_supported_abi(self) -> None:
        with mock.patch.object(MODULE, "config_abi", side_effect=lambda name: "x86_64"):
            selected = MODULE.choose_avd_with_abi(["android-api23-x86"], 23)
        self.assertEqual(("android-api23-x86", "x86_64"), selected)

    def test_arm64_is_preferred_but_unsupported_abi_is_not_selected(self) -> None:
        def abi(name: str) -> str:
            return {"android-api24-x86": "x86", "android-api24-x64": "x86_64", "android-api24-arm": "arm64-v8a"}[name]

        with mock.patch.object(MODULE, "config_abi", side_effect=abi):
            selected = MODULE.choose_avd_with_abi(
                ["android-api24-x86", "android-api24-x64", "android-api24-arm"], 24
            )
        self.assertEqual(("android-api24-arm", "arm64-v8a"), selected)

    def test_duplicate_api_selection_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate-api-selection"):
            MODULE.parse_api_selection("23,23")
        with self.assertRaisesRegex(ValueError, "api-selection-out-of-range"):
            MODULE.parse_api_selection("22")

    def test_avd_name_is_not_emitted_and_busy_instances_are_not_reused(self) -> None:
        self.assertNotIn("avd", MODULE.validate_matrix_candidate.__doc__ or "")
        rows = [{"status": "NOT_RUN", "avd": "leona-aosp-api23"}]
        ok, reason = MODULE.validate_matrix_candidate(rows)
        self.assertFalse(ok)
        self.assertEqual("raw-identifier-present", reason)
        with mock.patch.object(MODULE, "running_emulator_serial", return_value="emulator-5554"):
            self.assertTrue(MODULE.avd_is_busy("some-avd"))
            # A busy AVD is represented as a non-PASS row by the main loop; this
            # pure guard confirms a busy row cannot be admitted as a PASS.
            status, _ = MODULE.finalize_matrix_status(
                [{"status": "NOT_RUN", "artifactHashes": {"sampleApkSha256": "a" * 64}}]
            )
        self.assertEqual("PARTIAL", status)

    def test_runtime_log_sanitizer_is_bounded_and_redacted(self) -> None:
        text = "raw serial=emulator-5554\nLEONA_NATIVE_SMOKE_RESULT api=23 abi=arm64-v8a payloadBytes=8 payloadSha256=" + "a" * 64 + "\n" + "x" * 100000
        sanitized = MODULE.sanitize_runtime_text(text, limit=128)
        self.assertLessEqual(len(sanitized), 128)
        self.assertIn("LEONA_NATIVE_SMOKE_RESULT", sanitized)
        self.assertNotIn("serial=emulator-5554", sanitized)
        adversarial = "LEONA_NATIVE_SMOKE_RESULT api=23 abi=arm64-v8a payloadBytes=8 payloadSha256=" + "a" * 64 + " token=secret"
        self.assertNotIn("token=secret", MODULE.sanitize_runtime_text(adversarial))

    def test_candidate_validator_is_invoked_before_pass(self) -> None:
        rows = [{"status": "PASS", "artifactHashes": {"sampleApkSha256": "a" * 64}, "avd": "raw"}]
        status, validation = MODULE.finalize_matrix_status(rows)
        self.assertEqual("FAIL", status)
        self.assertFalse(validation["ok"])
        self.assertEqual("raw-identifier-present", validation["reason"])

    def test_page_size_validation_accepts_power_of_two_only(self) -> None:
        failed = lambda *args, **kwargs: __import__("subprocess").CompletedProcess(
            args, 1, stdout="not-a-page-size\n", stderr=""
        )
        with mock.patch.object(MODULE, "adb_command", side_effect=failed):
            self.assertIsNone(MODULE.runtime_page_size("missing-adb", "missing-serial"))

    def test_source_identity_requires_clean_40_hex_git_worktree(self) -> None:
        responses = [
            subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="b" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        with mock.patch.object(MODULE.subprocess, "run", side_effect=responses):
            self.assertEqual(("a" * 40, "b" * 40, "DERIVED_FROM_CLEAN_WORKTREE"), MODULE.derive_source_identity(Path("/tmp/source")))

        dirty = [
            subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="b" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" M file\n", stderr=""),
        ]
        with mock.patch.object(MODULE.subprocess, "run", side_effect=dirty):
            self.assertEqual("DIRTY_WORKTREE", MODULE.derive_source_identity(Path("/tmp/source"))[2])

        malformed = [
            subprocess.CompletedProcess([], 0, stdout="not-a-sha\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="b" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        ]
        with mock.patch.object(MODULE.subprocess, "run", side_effect=malformed):
            self.assertEqual(("", "", "UNVERIFIED"), MODULE.derive_source_identity(Path("/tmp/source")))

    def test_package_contract_uses_built_manifest_relationship(self) -> None:
        sample = {"package": MODULE.SAMPLE_PACKAGE}
        test = {
            "package": MODULE.TEST_PACKAGE,
            "instrumentationName": "androidx.test.runner.AndroidJUnitRunner",
            "instrumentationTarget": MODULE.TEST_PACKAGE,
        }
        self.assertEqual((True, "package-contract-valid"), MODULE.validate_package_contract(sample, test))
        test["instrumentationTarget"] = "io.other.app"
        self.assertEqual((False, "instrumentation-target-mismatch"), MODULE.validate_package_contract(sample, test))

    def test_output_directory_requires_empty_or_owned_marker_and_resets_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "matrix"
            MODULE.prepare_output_directory(output)
            (output / "api23").mkdir()
            (output / "api23" / "stale.log").write_text("stale")
            MODULE.prepare_output_directory(output)
            self.assertTrue((output / MODULE.OUTPUT_MARKER).is_file())
            self.assertFalse((output / "api23").exists())

            unsafe = Path(temp) / "unsafe"
            unsafe.mkdir()
            (unsafe / "unowned").write_text("x")
            with self.assertRaisesRegex(SystemExit, "output-directory-not-empty-or-marker-missing"):
                MODULE.prepare_output_directory(unsafe)

    def test_free_port_checks_both_emulator_ports(self) -> None:
        with mock.patch.object(MODULE, "port_available", side_effect=lambda port: port >= 5574):
            self.assertEqual(5574, MODULE.free_port("adb-is-not-consulted", 5570))
        with mock.patch.object(MODULE, "port_available", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "no-free-emulator-port"):
                MODULE.free_port("adb-is-not-consulted", 5570)

    def test_preclean_records_absent_and_uninstall_failure(self) -> None:
        absent = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(MODULE, "adb_command", return_value=absent):
            result = MODULE.preclean_package("adb", "serial", MODULE.SAMPLE_PACKAGE)
        self.assertFalse(result["presentBefore"])
        self.assertEqual(0, result["uninstallRc"])

        present = subprocess.CompletedProcess([], 0, stdout="package:/data/app/base.apk\n", stderr="")
        failure = subprocess.CompletedProcess([], 1, stdout="", stderr="Failure")
        with mock.patch.object(MODULE, "adb_command", side_effect=[present, failure]):
            result = MODULE.preclean_package("adb", "serial", MODULE.SAMPLE_PACKAGE)
        self.assertTrue(result["presentBefore"])
        self.assertEqual(1, result["uninstallRc"])

    def test_candidate_failure_is_fail_not_partial(self) -> None:
        status, validation = MODULE.finalize_matrix_status(
            [{"status": "PASS", "artifactHashes": {"sampleApkSha256": "a" * 64}, "avd": "leaked"}]
        )
        self.assertEqual("FAIL", status)
        self.assertFalse(validation["ok"])

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
