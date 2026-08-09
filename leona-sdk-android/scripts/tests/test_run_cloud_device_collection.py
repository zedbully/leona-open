from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "run-cloud-device-collection.sh"


def extract_matrix_writer() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("write_matrix_row_template() {")
    end = text.index("\n\nwait_for_adb() {", start)
    return text[start:end]


class CloudDeviceCollectionTest(unittest.TestCase):
    def test_box_id_without_verdict_file_is_nounset_safe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="leona-collection-matrix-writer-") as temp:
            root = Path(temp)
            apk = root / "sample.apk"
            apk.write_bytes(b"fixture-apk")
            for name in ("install.log", "package.txt", "posture.env", "device-summary.env"):
                (root / name).write_text("", encoding="utf-8")
            (root / "logcat.leona.txt").write_text(
                '{"boxId":"123e4567-e89b-12d3-a456-426614174000"}\n',
                encoding="utf-8",
            )
            row = root / "matrix-row.md"
            program = f"""
set -euo pipefail
OUT_DIR={str(root)!r}
APK={str(apk)!r}
TRANSPORT=adb
TRIGGER_SENSE=direct
KEEP_FULL_LOGCAT=0
prop_value() {{ printf ''; }}
sha256_file() {{ printf '%064d\n' 0; }}
{extract_matrix_writer()}
write_matrix_row_template {str(row)!r}
"""
            result = subprocess.run(
                ["bash", "-c", program],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            output = row.read_text(encoding="utf-8")
            self.assertIn("Pass / blocked / failed: pass", output)
            self.assertIn("Query this BoxId through your backend verdict integration", output)


if __name__ == "__main__":
    unittest.main()
