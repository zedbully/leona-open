from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "android-cloud-runtime.yml"
RUNNER = REPO_ROOT / "leona-sdk-android" / "scripts" / "run-github-hosted-runtime-matrix.sh"


class GitHubHostedRuntimeWorkflowTest(unittest.TestCase):
    def test_boundary_workflow_is_public_safe_and_same_candidate(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", text)
        self.assertNotIn("${{ secrets.", text)
        self.assertEqual(1, text.count(":sample-app:assembleCloudTest"))
        self.assertIn("--no-build-cache", text)
        self.assertIn("--no-configuration-cache", text)
        self.assertIn("api-level: 23", text)
        self.assertIn("api-level: 36", text)
        self.assertIn("--required-api 23", text)
        self.assertIn("--required-api 36", text)
        self.assertIn("actions/checkout@v7", text)
        self.assertIn("actions/setup-java@v5", text)
        self.assertIn("gradle/actions/setup-gradle@v6", text)
        self.assertIn("actions/upload-artifact@v7", text)
        self.assertNotIn("sample-app/build/outputs", text)
        self.assertNotIn("leona-github-matrix-private.env/", text)
        self.assertIn("leona-github-cloud-runtime-verification/", text)
        self.assertIn("Remove credential-bearing build state", text)
        self.assertIn("*/executionHistory", text)

    def test_runner_rejects_non_github_host_before_credentials(self) -> None:
        result = subprocess.run(
            ["bash", str(RUNNER), "23"],
            check=False,
            capture_output=True,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        self.assertEqual(2, result.returncode)
        self.assertIn("restricted to GitHub Actions-managed hosts", result.stderr)


if __name__ == "__main__":
    unittest.main()
