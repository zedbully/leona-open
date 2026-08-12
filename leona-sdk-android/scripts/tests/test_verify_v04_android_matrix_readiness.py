from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SDK_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SDK_ROOT / "scripts" / "verify-v0.4-android-matrix-readiness.sh"


class AndroidMatrixReadinessHostedEvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="leona-matrix-hosted-evidence-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "runtime"
        self.apk_sha = "a" * 64
        for api in (23, 36):
            self.write_api(api, self.apk_sha)

    def write_api(self, api: int, apk_sha: str) -> None:
        api_dir = self.root / f"api-{api}"
        redacted = api_dir / "redacted"
        redacted.mkdir(parents=True, exist_ok=True)
        report = {
            "status": "pass",
            "sourceLabel": f"github-hosted-avd-api-{api}",
            "sampleCount": 1,
            "secretValuesPrinted": False,
            "rawIdentifiersPrinted": False,
            "samples": [{
                "environmentType": "github-hosted-avd",
                "androidApi": f"fixture / {api}",
                "result": "pass",
                "triggerType": "direct",
                "senseTriggered": True,
                "reportVerified": True,
                "apkSha256": apk_sha,
                "boxIdHintOrHash": "1234...abcd",
            }],
        }
        receipt = {
            "schemaVersion": 1,
            "status": "pass",
            "mode": "public_hosted",
            "apiKeyAccepted": True,
            "sdkInt": api,
            "businessDecisionProduced": False,
            "secretValuesPrinted": False,
            "rawIdentifiersPrinted": False,
            "requestBodySha256": "b" * 64,
            "payloadSha256": "c" * 64,
            "deviceContextSha256": "d" * 64,
        }
        provenance = {
            "schemaVersion": 1,
            "provider": "github-actions",
            "runnerManaged": True,
            "apiLevel": api,
            "architecture": "x86_64",
            "target": "default",
            "aospNoGms": True,
            "forbiddenGoogleRuntimePackageCount": 0,
            "triggerType": "direct",
            "artifactBoundary": "redacted-only",
            "businessDecisionOwner": "customer-backend",
            "sdkRole": "collect-and-report-evidence-only",
            "gitCommit": "e" * 40,
            "apkSha256": apk_sha,
        }
        (redacted / "summary.json").write_text(json.dumps(report), encoding="utf-8")
        (api_dir / "fixture-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        (api_dir / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")

    def run_gate(self) -> tuple[subprocess.CompletedProcess[str], dict]:
        output = Path(self.temp.name) / "matrix-output"
        env = os.environ.copy()
        env["LEONA_V04_ANDROID_MATRIX_OUT"] = str(output)
        env["LEONA_GITHUB_HOSTED_RUNTIME_ROOT"] = str(self.root)
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            cwd=SDK_ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        summary_path = output / "summary.json"
        summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
        return result, summary

    def test_valid_hosted_boundary_is_consumed_without_clearing_full_matrix(self) -> None:
        result, summary = self.run_gate()
        self.assertEqual(0, result.returncode, result.stderr)
        check = next(item for item in summary["checks"] if item["id"] == "github_hosted_boundary_runtime")
        self.assertEqual("pass", check["status"])
        self.assertFalse(check["countsTowardFullExternalMatrix"])
        self.assertFalse(check["commercialAdmissionClaimed"])
        self.assertEqual("local-pass-with-external-blockers", summary["status"])

    def test_candidate_drift_fails_before_matrix_summary(self) -> None:
        self.write_api(36, "f" * 64)
        result, summary = self.run_gate()
        self.assertNotEqual(0, result.returncode)
        self.assertEqual({}, summary)
        self.assertIn("github-hosted-runtime-evidence] fail", result.stdout)


if __name__ == "__main__":
    unittest.main()
