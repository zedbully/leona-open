#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "verify-android-6-16-compatibility.py"
CONTRACT = Path(__file__).resolve().parents[2] / "compatibility" / "android-6-16-contract.json"
SPEC = importlib.util.spec_from_file_location("compatibility_verifier", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TEST_BOX_ID = "01ARZ3NDEK" + "TSV4RRFFQ69G5FAV"


class CompatibilityVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="leona-compat-test-")
        self.root = Path(self.temp.name)
        (self.root / "sdk").mkdir()
        (self.root / "sample-app").mkdir()
        (self.root / "gradle" / "wrapper").mkdir(parents=True)
        (self.root / "gradle" / "libs.versions.toml").write_text('agp = "9.3.2"\n', encoding="utf-8")
        (self.root / "gradle" / "wrapper" / "gradle-wrapper.properties").write_text(
            "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.6.0-bin.zip\n"
            "distributionSha256Sum=bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01\n",
            encoding="utf-8",
        )
        (self.root / "sdk" / "build.gradle.kts").write_text(
            "android {\n  compileSdk = 36\n  defaultConfig {\n    minSdk = 21\n  }\n}\n",
            encoding="utf-8",
        )
        (self.root / "sample-app" / "build.gradle.kts").write_text(
            "android {\n  compileSdk = 36\n  defaultConfig {\n    minSdk = 21\n    targetSdk = 36\n  }\n}\n",
            encoding="utf-8",
        )
        self.sdk = self.root / "android-sdk"
        (self.sdk / "platforms" / "android-36").mkdir(parents=True)
        (self.sdk / "platforms" / "android-36" / "android.jar").write_bytes(b"x" * 1_000_001)
        (self.sdk / "build-tools" / "36.0.0").mkdir(parents=True)
        (self.sdk / "build-tools" / "36.0.0" / "aapt2").write_text("ok", encoding="utf-8")
        self.now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.apk_sha256 = "b" * 64
        self.artifacts: list[Path] = []

    def tearDown(self) -> None:
        for artifact in self.artifacts:
            artifact.unlink(missing_ok=True)
        self.temp.cleanup()

    def run_verifier(self, manifest: dict | None = None, strict: bool = False, contract: Path = CONTRACT) -> tuple[int, dict]:
        output = self.root / ("out-strict" if strict else "out")
        runtime_path = None
        if manifest is not None:
            runtime_path = self.root / "runtime.json"
            runtime_path.write_text(json.dumps(manifest), encoding="utf-8")
        args = [
            "--contract", str(contract),
            "--project-root", str(self.root),
            "--android-sdk-root", str(self.sdk),
            "--output-dir", str(output),
            "--now", self.now,
        ]
        if runtime_path:
            args.extend(["--runtime-evidence", str(runtime_path)])
        if strict:
            args.append("--strict-runtime")
        with mock.patch("builtins.print"):
            code = MODULE.main(args)
        return code, json.loads((output / "summary.json").read_text(encoding="utf-8"))

    def complete_manifest(self) -> dict:
        samples = []
        versions = {
            23: "6.0", 24: "7.0", 25: "7.1", 26: "8.0", 27: "8.1", 28: "9",
            29: "10", 30: "11", 31: "12", 32: "12L", 33: "13", 34: "14", 35: "15", 36: "16",
        }
        for api, version in versions.items():
            artifact = Path(f"/tmp/leona-compat-test-api{api}-{self.root.name}.json")
            artifact.write_text(
                json.dumps(
                    {
                        "status": "pass",
                        "sampleCount": 1,
                        "rawIdentifiersPrinted": False,
                        "secretValuesPrinted": False,
                        "samples": [
                            {
                                "androidApi": f"{version} / {api}",
                                "collectedAt": self.now,
                                "result": "pass",
                                "triggerType": "direct",
                                "senseTriggered": True,
                                "reportVerified": True,
                                "apkSha256": self.apk_sha256,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            self.artifacts.append(artifact)
            samples.append(
                {
                    "apiLevel": api,
                    "androidVersion": version,
                    "collectedAt": self.now,
                    "evidenceClass": "current-direct-runtime",
                    "result": "pass",
                    "artifactType": "redacted-matrix-import-summary-v1",
                    "senseTriggered": True,
                    "reportVerified": True,
                    "apkSha256": self.apk_sha256,
                    "redacted": True,
                    "rawIdentifiersPrinted": False,
                    "artifactPath": str(artifact.resolve()),
                    "artifactSha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                }
            )
        return {"schemaVersion": 1, "samples": samples}

    def test_build_contract_passes_but_runtime_is_not_inferred(self) -> None:
        code, summary = self.run_verifier()
        self.assertEqual(0, code)
        self.assertEqual("build-pass-runtime-incomplete", summary["status"])
        self.assertFalse(summary["runtimeComplete"])

    def test_strict_complete_direct_matrix_passes(self) -> None:
        code, summary = self.run_verifier(self.complete_manifest(), strict=True)
        self.assertEqual(0, code)
        self.assertEqual("pass", summary["status"])
        self.assertEqual(list(range(23, 37)), summary["runtime"]["passingApis"])

    def test_strict_gap_fails(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"] = manifest["samples"][:-1]
        code, summary = self.run_verifier(manifest, strict=True)
        self.assertEqual(1, code)
        self.assertIn(36, summary["runtime"]["missingApis"])

    def test_non_strict_valid_partial_runtime_stays_incomplete(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"] = manifest["samples"][-1:]
        code, summary = self.run_verifier(manifest)
        self.assertEqual(0, code)
        self.assertEqual("build-pass-runtime-incomplete", summary["status"])
        self.assertEqual([36], summary["runtime"]["passingApis"])
        self.assertEqual(
            "incomplete",
            next(c for c in summary["checks"] if c["id"] == "runtime.direct-api23-36")["status"],
        )

    def test_duplicate_api_fails(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"].append(dict(manifest["samples"][0]))
        code, summary = self.run_verifier(manifest, strict=True)
        self.assertEqual(1, code)
        self.assertEqual("fail", next(c for c in summary["checks"] if c["id"] == "runtime.unique-api-rows")["status"])

    def test_false_runtime_pass_without_sense_fails(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"][0]["senseTriggered"] = False
        code, summary = self.run_verifier(manifest, strict=True)
        self.assertEqual(1, code)
        self.assertIn(23, summary["runtime"]["missingApis"])

    def test_bad_artifact_hash_fails(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"][0]["artifactSha256"] = "0" * 64
        code, summary = self.run_verifier(manifest, strict=True)
        self.assertEqual(1, code)
        self.assertIn(23, summary["runtime"]["missingApis"])

    def test_mixed_apk_candidates_fail_closed(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"][0]["apkSha256"] = "c" * 64
        artifact = Path(manifest["samples"][0]["artifactPath"])
        report = json.loads(artifact.read_text(encoding="utf-8"))
        report["samples"][0]["apkSha256"] = "c" * 64
        artifact.write_text(json.dumps(report), encoding="utf-8")
        manifest["samples"][0]["artifactSha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()

        code, summary = self.run_verifier(manifest, strict=True)

        self.assertEqual(1, code)
        self.assertFalse(summary["runtime"]["sameApkAcrossMatrix"])
        self.assertEqual(
            "fail",
            next(c for c in summary["checks"] if c["id"] == "runtime.same-apk-candidate")["status"],
        )

    def test_missing_apk_hash_fails(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"][0].pop("apkSha256")

        code, summary = self.run_verifier(manifest, strict=True)

        self.assertEqual(1, code)
        self.assertIn(23, summary["runtime"]["missingApis"])

    def test_hash_valid_non_direct_artifact_fails(self) -> None:
        manifest = self.complete_manifest()
        artifact = Path(manifest["samples"][0]["artifactPath"])
        report = json.loads(artifact.read_text(encoding="utf-8"))
        report["samples"][0]["triggerType"] = "ui"
        artifact.write_text(json.dumps(report), encoding="utf-8")
        manifest["samples"][0]["artifactSha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()

        code, summary = self.run_verifier(manifest, strict=True)

        self.assertEqual(1, code)
        self.assertIn(23, summary["runtime"]["missingApis"])

    def test_manifest_timestamp_must_match_hashed_artifact(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"][0]["collectedAt"] = "2026-08-09T00:00:00Z"

        code, summary = self.run_verifier(manifest, strict=True)

        self.assertEqual(1, code)
        self.assertIn(23, summary["runtime"]["missingApis"])

    def test_stale_collection_timestamp_fails(self) -> None:
        manifest = self.complete_manifest()
        stale = "2020-01-01T00:00:00Z"
        artifact = Path(manifest["samples"][0]["artifactPath"])
        report = json.loads(artifact.read_text(encoding="utf-8"))
        report["samples"][0]["collectedAt"] = stale
        artifact.write_text(json.dumps(report), encoding="utf-8")
        manifest["samples"][0]["collectedAt"] = stale
        manifest["samples"][0]["artifactSha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()

        code, summary = self.run_verifier(manifest, strict=True)

        self.assertEqual(1, code)
        self.assertIn(23, summary["runtime"]["missingApis"])

    def test_raw_box_id_is_rejected(self) -> None:
        manifest = self.complete_manifest()
        manifest["samples"][0]["note"] = TEST_BOX_ID
        code, summary = self.run_verifier(manifest, strict=True)
        self.assertEqual(1, code)
        self.assertEqual("fail", next(c for c in summary["checks"] if c["id"] == "runtime.redaction")["status"])

    def test_compile_sdk_drift_fails(self) -> None:
        (self.root / "sdk" / "build.gradle.kts").write_text(
            "android {\n  compileSdk = 34\n  defaultConfig { minSdk = 21 }\n}\n",
            encoding="utf-8",
        )
        code, summary = self.run_verifier()
        self.assertEqual(1, code)
        self.assertFalse(summary["buildContractPassed"])

    def test_gradle_distribution_checksum_drift_fails(self) -> None:
        wrapper = self.root / "gradle" / "wrapper" / "gradle-wrapper.properties"
        wrapper.write_text(
            wrapper.read_text(encoding="utf-8").replace(
                "bbaeb2fef8710818cf0e261201dab964c572f92b942812df0c3620d62a529a01",
                "0" * 64,
            ),
            encoding="utf-8",
        )

        code, summary = self.run_verifier()

        self.assertEqual(1, code)
        self.assertEqual(
            "fail",
            next(c for c in summary["checks"] if c["id"] == "build.gradle-distribution-sha256")["status"],
        )


if __name__ == "__main__":
    unittest.main()
