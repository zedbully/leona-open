from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "android-cloud-runtime.yml"
MAIN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "android.yml"
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
        self.assertEqual(2, text.count("target: default"))
        self.assertNotIn("target: google_apis", text)
        self.assertIn("--required-api 23", text)
        self.assertIn("--required-api 36", text)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7", text)
        self.assertIn("actions/setup-java@b6effb05e454b25005698d916606bdc6ffcbf961 # v5", text)
        self.assertIn("gradle/actions/setup-gradle@9c971963bec38e04b3d30dcc455b5382be2fdbfb # v6", text)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7", text)
        self.assertNotRegex(text, r"uses:\s+[^\s]+@v\d+(?:\s|$)")
        self.assertNotIn("sample-app/build/outputs", text)
        self.assertNotIn("leona-github-matrix-private.env/", text)
        self.assertIn("leona-github-cloud-runtime-verification/", text)
        self.assertIn("Remove credential-bearing build state", text)
        self.assertIn("*/executionHistory", text)
        runner = RUNNER.read_text(encoding="utf-8")
        for package_name in ("com.google.android.gms", "com.android.vending", "com.google.android.gsf"):
            self.assertIn(package_name, runner)
        self.assertIn('"aospNoGms": True', runner)
        self.assertIn('"forbiddenGoogleRuntimePackageCount": 0', runner)

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

    def test_all_android_actions_are_commit_pinned(self) -> None:
        for workflow in (WORKFLOW, MAIN_WORKFLOW):
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text(encoding="utf-8")
                self.assertNotRegex(text, r"uses:\s+[^\s]+@v\d+(?:\s|$)")


if __name__ == "__main__":
    unittest.main()
