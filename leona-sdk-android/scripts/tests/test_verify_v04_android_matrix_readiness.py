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
    def run_gate(self, env_extra: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess[str], dict]:
        output = Path(self.temp.name) / "matrix-output"
        env = os.environ.copy()
        env["LEONA_V04_ANDROID_MATRIX_OUT"] = str(output)
        if env_extra:
            env.update(env_extra)
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

    def test_local_readiness_is_consumed_without_hosted_runtime_dependency(self) -> None:
        result, summary = self.run_gate()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("github_hosted_boundary_runtime", {item["id"] for item in summary["checks"]})
        self.assertEqual("local-pass-with-external-blockers", summary["status"])

    def test_legacy_hosted_input_is_ignored(self) -> None:
        result, summary = self.run_gate({"LEONA_GITHUB_HOSTED_RUNTIME_ROOT": "/does/not/exist"})
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("github_hosted_boundary_runtime", {item["id"] for item in summary["checks"]})


if __name__ == "__main__":
    unittest.main()
