#!/usr/bin/env python3

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_DIR = Path(__file__).resolve().parents[3]
SCRIPT = REPO_DIR / "leona-sdk-android/scripts/verify-android-physical-oem-closure.py"
APK_HASH = "ab" * 32


class PhysicalOemClosureVerifierTest(unittest.TestCase):
    def write_inputs(
        self,
        root: Path,
        *,
        second_brand: str = "oem-b",
        physical_hash: str = APK_HASH,
        runtime_hash: str = APK_HASH,
        box_reference: str = "sha256:" + "cd" * 32,
    ) -> tuple[Path, Path]:
        physical_samples = [
            self.physical_sample("oem-a", "16 / 36", physical_hash, box_reference),
            self.physical_sample(second_brand, "12 / 31", physical_hash, "sha256:" + "ef" * 32),
        ]
        physical = root / "physical.json"
        physical.write_text(
            json.dumps(
                {
                    "status": "pass",
                    "sampleCount": len(physical_samples),
                    "samples": physical_samples,
                    "rawIdentifiersPrinted": False,
                    "secretValuesPrinted": False,
                }
            ),
            encoding="utf-8",
        )
        runtime = root / "runtime.json"
        runtime.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "samples": [
                        {
                            "apiLevel": api,
                            "result": "pass",
                            "senseTriggered": True,
                            "reportVerified": True,
                            "redacted": True,
                            "rawIdentifiersPrinted": False,
                            "apkSha256": runtime_hash,
                        }
                        for api in range(23, 37)
                    ],
                }
            ),
            encoding="utf-8",
        )
        return physical, runtime

    @staticmethod
    def physical_sample(brand: str, android_api: str, apk_hash: str, box_reference: str) -> dict[str, object]:
        return {
            "environmentType": "wetest-physical-oem",
            "brand": brand,
            "androidApi": android_api,
            "apkSha256": apk_hash,
            "boxIdHintOrHash": box_reference,
            "result": "pass",
            "triggerType": "direct",
            "senseTriggered": True,
            "reportVerified": True,
        }

    def run_verifier(self, physical: Path, runtime: Path, output: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--physical-summary",
                str(physical),
                "--runtime-evidence",
                str(runtime),
                "--output-dir",
                str(output),
            ],
            cwd=REPO_DIR,
            text=True,
            capture_output=True,
            check=False,
        )
        report = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        return result, report

    def test_two_oem_two_api_same_candidate_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            physical, runtime = self.write_inputs(root)
            result, report = self.run_verifier(physical, runtime, root / "out")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("pass", report["status"])
        self.assertEqual(2, report["distinctOemCount"])
        self.assertEqual(2, report["distinctPhysicalApiCount"])
        self.assertEqual(14, report["runtimeApiCount"])
        self.assertTrue(report["physicalRuntimeCandidateMatches"])
        self.assertFalse(report["commercialAdmissionClaimed"])

    def test_single_oem_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            physical, runtime = self.write_inputs(root, second_brand="oem-a")
            result, report = self.run_verifier(physical, runtime, root / "out")

        self.assertEqual(1, result.returncode)
        self.assertEqual("failed", report["status"])
        self.assertIn("physical closure requires at least two distinct OEMs", report["failures"])

    def test_candidate_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            physical, runtime = self.write_inputs(root, runtime_hash="12" * 32)
            result, report = self.run_verifier(physical, runtime, root / "out")

        self.assertEqual(1, result.returncode)
        self.assertFalse(report["physicalRuntimeCandidateMatches"])

    def test_raw_box_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            physical, runtime = self.write_inputs(root, box_reference="01ARZ3NDEKTSV4RRFFQ69G5FAV")
            result, report = self.run_verifier(physical, runtime, root / "out")

        self.assertEqual(1, result.returncode)
        self.assertEqual("failed", report["status"])
        self.assertTrue(any("sensitive-looking" in item for item in report["failures"]))


if __name__ == "__main__":
    unittest.main()
