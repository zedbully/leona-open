#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CPP = ROOT / "sdk" / "src" / "main" / "cpp"


class NativeBuildContractTest(unittest.TestCase):
    def test_project_native_target_is_warning_clean(self) -> None:
        cmake = (CPP / "CMakeLists.txt").read_text(encoding="utf-8")
        for flag in ("-Wall", "-Wextra", "-Werror"):
            self.assertIn(flag, cmake)

    def test_jni_logging_does_not_use_gnu_variadic_extension(self) -> None:
        source = (CPP / "jni_bridge.cpp").read_text(encoding="utf-8")
        self.assertNotIn("##__VA_ARGS__", source)
        self.assertIn("#define LOG_I(...)", source)

    def test_non_arm64_timing_helpers_are_not_compiled(self) -> None:
        source = (CPP / "detection" / "timing_probe.cpp").read_text(encoding="utf-8")
        guard = source.index("#if defined(__aarch64__)")
        helper = source.index("static inline uint64_t read_cntvct")
        self.assertLess(guard, helper)
        self.assertIn("#endif\n\nbool sample_known_workload", source)

    def test_inventory_contract_is_public_safe(self) -> None:
        doc = (ROOT / "docs" / "v1-android-native-artifact-inventory.md").read_text(encoding="utf-8")
        self.assertIn("PROVIDER_ARTIFACT_NOT_INCLUDED", doc)
        self.assertIn("llvm-readelf", doc)
        self.assertIn("API23--36 device runtime", doc)
        self.assertNotIn("BEGIN PRIVATE KEY", doc)


if __name__ == "__main__":
    unittest.main()
