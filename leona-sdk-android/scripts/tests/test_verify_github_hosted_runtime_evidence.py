from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "verify-github-hosted-runtime-evidence.py"
SPEC = importlib.util.spec_from_file_location("github_runtime_verifier", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GitHubRuntimeEvidenceVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="leona-github-runtime-verifier-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.apk_sha = "a" * 64
        self.commit_sha = "b" * 40

    def write_api(
        self,
        api: int,
        *,
        direct: bool = True,
        same_apk: bool = True,
        decision: bool = False,
        box_id_value: str = "1234...abcd",
    ) -> None:
        api_dir = self.root / f"api-{api}"
        redacted = api_dir / "redacted"
        redacted.mkdir(parents=True)
        apk_sha = self.apk_sha if same_apk else "c" * 64
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
                "triggerType": "direct" if direct else "ui",
                "senseTriggered": True,
                "reportVerified": True,
                "apkSha256": apk_sha,
                "boxIdHintOrHash": box_id_value,
            }],
        }
        receipt = {
            "schemaVersion": 1,
            "status": "pass",
            "mode": "public_hosted",
            "apiKeyAccepted": True,
            "sdkInt": api,
            "businessDecisionProduced": decision,
            "secretValuesPrinted": False,
            "rawIdentifiersPrinted": False,
            "requestBodySha256": "d" * 64,
            "payloadSha256": "e" * 64,
            "deviceContextSha256": "f" * 64,
        }
        provenance = {
            "schemaVersion": 1,
            "provider": "github-actions",
            "runnerManaged": True,
            "apiLevel": api,
            "architecture": "x86_64",
            "target": "google_apis",
            "triggerType": "direct",
            "artifactBoundary": "redacted-only",
            "businessDecisionOwner": "customer-backend",
            "sdkRole": "collect-and-report-evidence-only",
            "gitCommit": self.commit_sha,
            "apkSha256": apk_sha,
        }
        (redacted / "summary.json").write_text(json.dumps(report), encoding="utf-8")
        (api_dir / "fixture-receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
        (api_dir / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")

    def verify(self, apis: list[int]) -> tuple[list[str], list[dict]]:
        failures: list[str] = []
        results = [MODULE.verify_api(self.root, api, failures) for api in apis]
        apk_hashes = {item["apkSha256"] for item in results if item["apkSha256"]}
        if len(apk_hashes) != 1:
            failures.append("all required APIs must use the exact same APK SHA-256")
        return failures, results

    def test_boundary_evidence_passes_for_same_candidate(self) -> None:
        self.write_api(23, box_id_value="sha256:" + "1" * 64)
        self.write_api(36, box_id_value="sha256:" + "2" * 64)
        failures, results = self.verify([23, 36])
        self.assertEqual([], failures)
        self.assertEqual(["pass", "pass"], [item["status"] for item in results])

    def test_non_direct_trigger_fails_closed(self) -> None:
        self.write_api(23, direct=False)
        failures, _results = self.verify([23])
        self.assertTrue(any("triggerType must be direct" in item for item in failures))

    def test_business_decision_from_fixture_fails_closed(self) -> None:
        self.write_api(23, decision=True)
        failures, _results = self.verify([23])
        self.assertTrue(any("must not produce a business decision" in item for item in failures))

    def test_candidate_hash_drift_fails_closed(self) -> None:
        self.write_api(23)
        self.write_api(36, same_apk=False)
        failures, _results = self.verify([23, 36])
        self.assertIn("all required APIs must use the exact same APK SHA-256", failures)

    def test_raw_box_id_scanner_fails_closed(self) -> None:
        self.write_api(23)
        (self.root / "api-23" / "raw-leak.txt").write_text(
            "boxId=123e4567-e89b-12d3-a456-426614174000\n", encoding="utf-8"
        )
        hits = MODULE.sensitive_hits(self.root, self.root / "verification")
        self.assertEqual(1, len(hits))


if __name__ == "__main__":
    unittest.main()
