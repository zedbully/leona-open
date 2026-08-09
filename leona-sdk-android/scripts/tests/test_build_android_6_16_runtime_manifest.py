#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "build-android-6-16-runtime-manifest.py"
SPEC = importlib.util.spec_from_file_location("runtime_manifest_builder", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RuntimeManifestBuilderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="leona-runtime-builder-test-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_import(self, api: int, trigger: str = "direct") -> Path:
        path = self.root / f"api{api}.json"
        version = MODULE.VERSIONS[api]
        path.write_text(
            json.dumps(
                {
                    "status": "pass",
                    "generatedAt": "2026-08-09T12:00:00+00:00",
                    "sampleCount": 1,
                    "rawIdentifiersPrinted": False,
                    "secretValuesPrinted": False,
                    "samples": [
                        {
                            "androidApi": f"{version} / {api}",
                            "collectedAt": "2026-08-09T11:59:00+00:00",
                            "result": "pass",
                            "triggerType": trigger,
                            "senseTriggered": trigger == "direct",
                            "reportVerified": True,
                            "boxIdHintOrHash": "01AR...5FAV",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    def run_builder(self, samples: list[tuple[int, Path]], require_complete: bool = False) -> tuple[int, dict]:
        out = self.root / ("complete" if require_complete else "partial")
        args = ["--output-dir", str(out)]
        for api, path in samples:
            args.extend(["--sample", f"{api}={path}"])
        if require_complete:
            args.append("--require-complete")
        with mock.patch("builtins.print"):
            code = MODULE.main(args)
        return code, json.loads((out / "summary.json").read_text(encoding="utf-8"))

    def test_partial_direct_import_builds_redacted_manifest(self) -> None:
        path = self.write_import(36)
        code, summary = self.run_builder([(36, path)])
        self.assertEqual(0, code)
        self.assertEqual("partial", summary["status"])
        self.assertEqual([36], summary["passingApis"])
        manifest = json.loads(Path(summary["runtimeEvidencePath"]).read_text(encoding="utf-8"))
        self.assertEqual("current-direct-runtime", manifest["samples"][0]["evidenceClass"])
        self.assertEqual("redacted-matrix-import-summary-v1", manifest["samples"][0]["artifactType"])
        self.assertEqual("2026-08-09T11:59:00+00:00", manifest["samples"][0]["collectedAt"])

    def test_non_direct_import_is_rejected(self) -> None:
        path = self.write_import(23, trigger="ui")
        code, summary = self.run_builder([(23, path)])
        self.assertEqual(1, code)
        self.assertEqual("fail", summary["status"])
        self.assertIn("api23:sample-trigger-not-direct", summary["failures"])

    def test_missing_collection_timestamp_is_rejected(self) -> None:
        path = self.write_import(23)
        report = json.loads(path.read_text(encoding="utf-8"))
        report["samples"][0].pop("collectedAt")
        path.write_text(json.dumps(report), encoding="utf-8")

        code, summary = self.run_builder([(23, path)])

        self.assertEqual(1, code)
        self.assertIn("api23:sample-collected-at-invalid", summary["failures"])

    def test_complete_manifest_passes_strict_builder(self) -> None:
        samples = [(api, self.write_import(api)) for api in MODULE.VERSIONS]
        code, summary = self.run_builder(samples, require_complete=True)
        self.assertEqual(0, code)
        self.assertEqual("pass", summary["status"])
        self.assertEqual([], summary["missingApis"])


if __name__ == "__main__":
    unittest.main()
