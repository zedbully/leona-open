#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify-android-aar-native.py"
SPEC = importlib.util.spec_from_file_location("android_aar_native_verifier", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


SOURCE = r'''
#define JNI(name) __attribute__((visibility("default"))) void name(void) {}
JNI(Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_collect)
JNI(Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_decoyCheck)
JNI(Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_honeypotFakeKey)
JNI(Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_honeypotFakeToken)
JNI(Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_init)
JNI(Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_updateTamperContext)
'''
EXTRA_EXPORT = "JNI(Java_io_leonasec_leona_internal_runtime_OssNativeRuntime_unexpected)\n"


def _ndk_bin() -> Path | None:
    configured = os.environ.get("ANDROID_NDK_ROOT") or os.environ.get("ANDROID_NDK_HOME")
    if configured:
        candidates = sorted(Path(configured).glob("toolchains/llvm/prebuilt/*/bin"))
        if candidates:
            return candidates[-1]
    android_home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if android_home:
        candidates = sorted(Path(android_home).glob("ndk/*/toolchains/llvm/prebuilt/*/bin"))
        if candidates:
            return candidates[-1]
    return None


@unittest.skipUnless(_ndk_bin() is not None, "NDK is unavailable for generated ELF fixtures")
class AndroidAarNativeVerifierTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="leona-aar-native-")
        cls.root = Path(cls.temp.name)
        cls.ndk_bin = _ndk_bin()
        assert cls.ndk_bin is not None
        cls.readelf = str(cls.ndk_bin / "llvm-readelf")
        cls.nm = str(cls.ndk_bin / "llvm-nm")
        cls.so: dict[str, Path] = {}
        cls.so["arm64-v8a"] = cls._build("arm64-v8a", SOURCE)
        cls.so["armeabi-v7a"] = cls._build("armeabi-v7a", SOURCE)
        cls.so["x86_64"] = cls._build("x86_64", SOURCE)
        cls.extra_so = cls._build("arm64-v8a", SOURCE + EXTRA_EXPORT, "extra")
        cls.execstack_so = cls._build("arm64-v8a", SOURCE, "execstack", ["-Wl,-z,execstack"])
        cls.runpath_so = cls._build("arm64-v8a", SOURCE, "runpath", ["-Wl,-rpath,/system/lib"])

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    @classmethod
    def _build(
        cls,
        abi: str,
        source: str,
        suffix: str = "valid",
        extra_flags: list[str] | None = None,
    ) -> Path:
        drivers = {
            "arm64-v8a": "aarch64-linux-android23-clang",
            "armeabi-v7a": "armv7a-linux-androideabi23-clang",
            "x86_64": "x86_64-linux-android23-clang",
        }
        src = cls.root / f"{abi}-{suffix}.c"
        out = cls.root / f"{abi}-{suffix}.so"
        src.write_text(source, encoding="utf-8")
        command = [
            str(cls.ndk_bin / drivers[abi]),
            "-shared",
            "-fPIC",
            "-fvisibility=hidden",
            "-Wl,-soname,libleona.so,-z,noexecstack,-z,relro,-z,now,--strip-all",
        ]
        command.extend(extra_flags or [])
        command.extend(["-o", str(out), str(src)])
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise unittest.SkipTest(f"NDK fixture compile unavailable: {result.stderr[-400:]}")
        return out

    @classmethod
    def _aar(cls, name: str, overrides: dict[str, bytes | None] | None = None, extra: dict[str, bytes] | None = None) -> Path:
        overrides = overrides or {}
        extra = extra or {}
        path = cls.root / f"{name}.aar"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("AndroidManifest.xml", b"manifest")
            archive.writestr("classes.jar", b"classes")
            for abi, so in cls.so.items():
                value = overrides.get(abi, so.read_bytes())
                if value is None:
                    continue
                archive.writestr(f"jni/{abi}/libleona.so", value)
            for entry, value in extra.items():
                archive.writestr(entry, value)
        return path

    def verify(self, path: Path) -> dict:
        return MODULE.verify_aar(path, llvm_readelf=self.readelf, llvm_nm=self.nm)

    def test_valid_inventory_is_bounded_and_provider_absent(self) -> None:
        inventory = self.verify(self._aar("valid"))
        self.assertEqual(inventory["providerStatus"], "PROVIDER_ARTIFACT_NOT_INCLUDED")
        self.assertEqual([row["abi"] for row in inventory["abis"]], sorted(MODULE.ALLOWED_ABIS))
        for row in inventory["abis"]:
            self.assertEqual(set(row), {"abi", "sha256", "size", "exports", "needed"})
            self.assertEqual(set(row["exports"]), MODULE.EXPECTED_JNI_EXPORTS)
            self.assertTrue(set(row["needed"]) <= MODULE.ALLOWED_NEEDED)

    def test_zip_slip_is_rejected(self) -> None:
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("zip-slip", extra={"../escape": b"x"}))

    def test_duplicate_entry_is_rejected(self) -> None:
        path = self.root / "duplicate.aar"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                archive.writestr("classes.jar", b"classes")
                for abi, so in self.so.items():
                    archive.writestr(f"jni/{abi}/libleona.so", so.read_bytes())
                archive.writestr("jni/arm64-v8a/libleona.so", self.so["arm64-v8a"].read_bytes())
        with self.assertRaises(MODULE.InventoryError):
            self.verify(path)

    def test_oversized_entry_is_rejected_before_native_inspection(self) -> None:
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("oversize", extra={"assets/oversize": b"x" * (MODULE.MAX_ENTRY_BYTES + 1)}))

    def test_missing_and_extra_abi_are_rejected(self) -> None:
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("missing", overrides={"x86_64": None}))
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("extra-abi", extra={"jni/mips/libleona.so": self.so["arm64-v8a"].read_bytes()}))

    def test_wrong_machine_is_rejected(self) -> None:
        value = bytearray(self.so["arm64-v8a"].read_bytes())
        value[18:20] = (40).to_bytes(2, "little")
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("wrong-machine", overrides={"arm64-v8a": bytes(value)}))

    def test_extra_jni_export_is_rejected(self) -> None:
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("extra-export", overrides={"arm64-v8a": self.extra_so.read_bytes()}))

    def test_runpath_and_executable_stack_are_rejected(self) -> None:
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("runpath", overrides={"arm64-v8a": self.runpath_so.read_bytes()}))
        with self.assertRaises(MODULE.InventoryError):
            self.verify(self._aar("execstack", overrides={"arm64-v8a": self.execstack_so.read_bytes()}))


if __name__ == "__main__":
    unittest.main()
