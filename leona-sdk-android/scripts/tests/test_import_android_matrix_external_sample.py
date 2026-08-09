#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "import-android-matrix-external-sample.py"
SPEC = importlib.util.spec_from_file_location("matrix_importer", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
TEST_BOX_ID = "01ARZ3NDEK" + "TSV4RRFFQ69G5FAV"


class MatrixImporterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="leona-matrix-import-test-")
        self.row = Path(self.temp.name) / "matrix-row.md"
        self.row.write_text("# fixture\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def normalize(self, metadata: dict[str, str]) -> dict:
        sample = MODULE.normalize_sample(
            self.row,
            {
                "Brand": "google",
                "Model": "sdk_gphone64_arm64",
                "Android version / API": "16 / 36",
                "Serial hash": "a" * 64,
                **metadata,
            },
            {},
            {},
        )
        assert sample is not None
        return sample

    def test_direct_pass_records_trigger_and_report_without_raw_box_id(self) -> None:
        sample = self.normalize(
            {
                "Pass / blocked / failed": "pass",
                "BoxId": TEST_BOX_ID,
                "Reason": "BoxId generated through direct trigger.",
            }
        )
        self.assertEqual("direct", sample["triggerType"])
        self.assertTrue(sample["senseTriggered"])
        self.assertTrue(sample["reportVerified"])
        self.assertTrue(sample["collectedAt"].endswith("+00:00"))
        self.assertNotIn(TEST_BOX_ID, sample["boxIdHintOrHash"])

    def test_blocked_sample_cannot_claim_sense_or_report(self) -> None:
        sample = self.normalize(
            {
                "Pass / blocked / failed": "blocked",
                "BoxId": "not_generated",
                "Reason": "No BoxId found in LeonaCloudTest logs.",
            }
        )
        self.assertEqual("unknown", sample["triggerType"])
        self.assertFalse(sample["senseTriggered"])
        self.assertFalse(sample["reportVerified"])


if __name__ == "__main__":
    unittest.main()
