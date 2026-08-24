from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SerialOutputRedactionTest(unittest.TestCase):
    def test_clock_skew_blocked_report_hashes_adb_target(self) -> None:
        source = (ROOT / "run-clock-skew-regression.sh").read_text(encoding="utf-8")
        self.assertIn("serial_hint()", source)
        self.assertIn("- adb target: $(serial_hint)", source)
        self.assertNotIn("- adb target: ${SERIAL:-not specified}", source)

    def test_installed_sample_smoke_never_prints_raw_serial(self) -> None:
        source = (ROOT / "run-installed-sample-logcat-smoke.sh").read_text(encoding="utf-8")
        self.assertIn("serial_hint()", source)
        self.assertIn('[Leona installed sample smoke] serial : $(serial_hint "$ADB_SERIAL")', source)
        self.assertNotIn('echo "[Leona installed sample smoke] serial : $ADB_SERIAL"', source)
        self.assertNotIn('printf \'  %s\\n\' "${devices[@]}"', source)
        self.assertNotIn("Current devices:", source)


if __name__ == "__main__":
    unittest.main()
