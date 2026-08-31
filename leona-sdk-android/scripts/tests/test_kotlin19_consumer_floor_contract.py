#!/usr/bin/env python3
"""Keep the published V1/API23 floor consistent across build and consumer gates."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SDK_GRADLE = ROOT / "sdk" / "build.gradle.kts"
SAMPLE_GRADLE = ROOT / "sample-app" / "build.gradle.kts"
CONSUMER_SCRIPT = ROOT / "scripts" / "verify-kotlin-1-9-consumer.sh"
README = ROOT / "README.md"
CONTRACT = ROOT / "compatibility" / "android-6-16-contract.json"


def _default_min_sdk(source: str) -> int:
    block = re.search(r"defaultConfig\s*\{(?P<body>.*?)\n\s*\}", source, re.DOTALL)
    if block is None:
        raise AssertionError("defaultConfig block missing")
    match = re.search(r"\bminSdk\s*=\s*(\d+)", block.group("body"))
    if match is None:
        raise AssertionError("minSdk missing from defaultConfig")
    return int(match.group(1))


class Kotlin19ConsumerFloorContractTest(unittest.TestCase):
    def test_sdk_sample_and_consumer_fixture_share_api23_floor(self) -> None:
        self.assertEqual(23, _default_min_sdk(SDK_GRADLE.read_text(encoding="utf-8")))
        self.assertEqual(23, _default_min_sdk(SAMPLE_GRADLE.read_text(encoding="utf-8")))
        consumer = CONSUMER_SCRIPT.read_text(encoding="utf-8")
        fixture = re.search(
            r"cat > \"\$\{CONSUMER_DIR\}/app/build\.gradle\.kts\" <<EOF(?P<body>.*?)^EOF$",
            consumer,
            re.DOTALL | re.MULTILINE,
        )
        self.assertIsNotNone(fixture)
        self.assertEqual(23, _default_min_sdk(fixture.group("body")))

    def test_readme_android_6_16_section_does_not_overclaim_api21(self) -> None:
        readme = README.read_text(encoding="utf-8")
        self.assertIn("minSdk-23-brightgreen", readme)
        start = readme.index("## Android 6 through Android 16 compatibility")
        end = readme.find("\n## ", start + 3)
        section = readme[start:] if end == -1 else readme[start:end]
        self.assertIn("minSdk = 23", section)
        self.assertNotIn("minSdk = 21", section)

    def test_api23_to_36_contract_is_unchanged(self) -> None:
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        self.assertEqual(23, contract["scope"]["minimumApi"])
        self.assertEqual(36, contract["scope"]["maximumApi"])
        self.assertEqual(list(range(23, 37)), [row["apiLevel"] for row in contract["scope"]["apiLevels"]])
        self.assertEqual(23, contract["buildContract"]["maximumMinSdk"])
        self.assertEqual(23, contract["identityContract"]["sdkCompatibility"]["minimumApi"])
        self.assertEqual(36, contract["identityContract"]["sdkCompatibility"]["maximumApi"])


if __name__ == "__main__":
    unittest.main()
