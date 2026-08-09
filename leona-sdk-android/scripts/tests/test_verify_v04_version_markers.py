from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


SDK_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = SDK_ROOT / "scripts" / "verify-v0.4-version-markers.sh"


class VersionMarkerPortabilityTest(unittest.TestCase):
    def test_gate_passes_without_ripgrep_in_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leona-version-markers-no-rg-") as temp:
            env = {
                "HOME": os.environ.get("HOME", ""),
                "PATH": "/usr/bin:/bin",
                "LEONA_ANDROID_VERSION_MARKERS_OUT": temp,
                "LEONA_TARGET_RELEASE_VERSION": "0.4.0",
                "LEONA_REQUIRE_ANDROID_VERSION_MARKERS": "1",
            }
            result = subprocess.run(
                ["/bin/bash", str(SCRIPT)],
                cwd=SDK_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr + result.stdout)
            summary = (Path(temp) / "summary.md").read_text(encoding="utf-8")
            self.assertIn("- status: pass", summary)
            self.assertIn("- local pass checks: 8", summary)


if __name__ == "__main__":
    unittest.main()
