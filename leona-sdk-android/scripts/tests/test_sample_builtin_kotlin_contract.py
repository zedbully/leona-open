#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD_FILE = ROOT / "sample-app" / "build.gradle.kts"
DOC_FILE = ROOT / "docs" / "v1-android-built-in-kotlin.md"


def _block_after(source: str, marker: str) -> str:
    """Return one balanced Kotlin DSL block without depending on formatting."""
    start = source.index(marker)
    opening = source.index("{", start)
    depth = 0
    for index in range(opening, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise AssertionError(f"unterminated block: {marker}")


class SampleBuiltInKotlinContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.build = BUILD_FILE.read_text(encoding="utf-8")
        self.source_sets = _block_after(self.build, "sourceSets {")

    def test_agp_owns_conventional_kotlin_directories(self) -> None:
        # AGP 9.3.1 discovers these directories itself. Re-registering them via
        # AndroidSourceSet.kotlin can leave built-in Kotlin output present while
        # the clean unit-test classpath omits that output.
        for name in ("main", "debug", "release"):
            self.assertNotIn(f'getByName("{name}")', self.source_sets)

    def test_non_conventional_variant_overlays_remain_explicit(self) -> None:
        cloud_test = _block_after(self.source_sets, 'getByName("cloudTest") {')
        huawei_release = _block_after(self.source_sets, 'getByName("huaweiRelease") {')
        self.assertIn('"src/release/kotlin"', cloud_test)
        self.assertIn('"src/cloudTest/kotlin"', cloud_test)
        self.assertIn('"src/release/kotlin"', huawei_release)

    def test_unit_tests_reference_the_classes_that_exercise_the_clean_classpath(self) -> None:
        test_text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (ROOT / "sample-app" / "src").glob("test*/**/*.kt")
        )
        for symbol in (
            "ReflectivePlayIntegrityBridge",
            "SampleHuaweiSysIntegrity",
            "SampleMainlandDebugAttestation",
            "SamplePlayIntegrityDebugProvider",
        ):
            self.assertIn(symbol, test_text)

    def test_regression_documentation_keeps_clean_command(self) -> None:
        doc = DOC_FILE.read_text(encoding="utf-8")
        self.assertIn(":sdk:testDebugUnitTest", doc)
        self.assertIn(":sample-app:testDebugUnitTest", doc)
        self.assertIn("--no-build-cache", doc)


if __name__ == "__main__":
    unittest.main()
