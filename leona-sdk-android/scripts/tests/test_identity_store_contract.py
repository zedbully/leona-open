#!/usr/bin/env python3
"""Source contract for API 23+ Leona identity persistence hardening."""

import re
import json
import unittest
from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parents[2]
    / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/LeonaIdentityStore.kt"
).read_text(encoding="utf-8")
MANAGER_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/DeviceIdentityManager.kt"
).read_text(encoding="utf-8")


class LeonaIdentityStoreContractTest(unittest.TestCase):
    def test_api23_encryption_has_no_plaintext_fallback(self) -> None:
        self.assertIn('IllegalStateException("Unable to encrypt Leona identity state"', SOURCE)
        self.assertIn('"Android Keystore-backed identity requires API 23+"', SOURCE)
        self.assertRegex(SOURCE, r"check\(Build\.VERSION\.SDK_INT\s*>=\s*Build\.VERSION_CODES\.M\)")
        self.assertNotRegex(SOURCE, r"encrypt\([^)]*\)[\s\S]{0,200}getOrDefault\s*\(\s*plaintext")
        fallback = re.search(r"\.getOrElse\s*\{\s*cause\s*->(?P<body>[\s\S]*?)\n\s*}", SOURCE)
        self.assertIsNotNone(fallback)
        self.assertNotRegex(fallback.group("body"), r"\breturn\s+plaintext\b|^\s*plaintext\s*$")

    def test_api23_decryption_rejects_non_keystore_or_malformed_envelopes(self) -> None:
        self.assertRegex(
            SOURCE,
            r"if\s*\(Build\.VERSION\.SDK_INT\s*<\s*Build\.VERSION_CODES\.M\)[\s\S]{0,220}"
            r"currentProtectionStatus\s*=\s*IdentityProtectionStatus\.API_BELOW_23[\s\S]{0,220}"
            r"return\s+null",
        )
        self.assertRegex(
            SOURCE,
            r"if\s*\(stored\.length\s*>\s*MAX_ENVELOPE_LENGTH\)[\s\S]{0,180}"
            r"currentProtectionStatus\s*=\s*IdentityProtectionStatus\.CORRUPT_OR_MISSING[\s\S]{0,180}"
            r"return\s+null",
        )
        self.assertRegex(SOURCE, r"runCatching\s*\{\s*JSONObject\(stored\)\s*\}\s*\.getOrNull\(\)")
        self.assertRegex(
            SOURCE,
            r"if\s*\(json\s*==\s*null\s*\|\|\s*json\.optString\(\"mode\"\)\s*!=\s*\"keystore\"\)"
            r"[\s\S]{0,180}return\s+null",
        )
        self.assertNotRegex(SOURCE, r"(?m)^\s*return\s+stored\s*$")

    def test_gcm_iv_and_tag_bounds_are_explicit(self) -> None:
        self.assertIn("require(iv.size == GCM_IV_LENGTH_BYTES)", SOURCE)
        self.assertIn("require(ct.size >= GCM_TAG_LENGTH_BYTES)", SOURCE)
        self.assertIn("GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)", SOURCE)
        self.assertRegex(SOURCE, r"GCM_IV_LENGTH_BYTES\s*=\s*12")
        self.assertRegex(SOURCE, r"GCM_TAG_LENGTH_BITS\s*=\s*128")
        self.assertRegex(SOURCE, r"GCM_TAG_LENGTH_BYTES\s*=\s*16")

    def test_identity_anchors_commit_synchronously_and_surface_failures(self) -> None:
        for key in ("KEY_INSTALL_ID", "KEY_CANONICAL_DEVICE_ID", "KEY_LAST_SNAPSHOT"):
            self.assertRegex(SOURCE, rf"persist\({key},\s*encrypt\(")
        self.assertIn("private fun persist(key: String, encryptedValue: String)", SOURCE)
        self.assertIn(".putString(key, encryptedValue).commit()", SOURCE)
        self.assertIn('"Unable to persist Leona identity state"', SOURCE)
        self.assertNotIn(".apply()", SOURCE)

    def test_corrupt_snapshot_is_quarantined_without_losing_current_status(self) -> None:
        self.assertIn("fun loadLastSnapshot(): DeviceFingerprintSnapshot?", SOURCE)
        self.assertIn("quarantineCorruptSnapshot()", SOURCE)
        self.assertIn("fun beginResolution()", SOURCE)
        self.assertIn("statusForNextResolution(", SOURCE)
        self.assertRegex(
            SOURCE,
            r"prefs\.edit\(\)\.remove\(KEY_LAST_SNAPSHOT\)\.commit\(\)",
        )
        self.assertIn("statusAfterSnapshotQuarantine(cleared)", SOURCE)
        policy = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/IdentityProtectionState.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("IdentityProtectionLevel.CORRUPT_OR_MISSING", policy)
        self.assertIn("recoverable = true", policy)

    def test_new_install_lifecycle_cannot_restore_identity_from_backup(self) -> None:
        self.assertIn("context.noBackupFilesDir", SOURCE)
        self.assertIn('"leona-install-lifecycle-v1"', SOURCE)
        self.assertIn("ensureCurrentInstallLifecycle()", SOURCE)
        self.assertRegex(
            SOURCE,
            r"remove\(KEY_INSTALL_ID\)[\s\S]{0,160}"
            r"remove\(KEY_CANONICAL_DEVICE_ID\)[\s\S]{0,160}"
            r"remove\(KEY_LAST_SNAPSHOT\)",
        )
        self.assertIn("lifecycleMarker.createNewFile()", SOURCE)

    def test_valid_encrypted_state_survives_a_missing_sentinel(self) -> None:
        self.assertRegex(
            SOURCE,
            r"val existingInstallId = decrypt\(prefs\.getString\(KEY_INSTALL_ID, null\)\)",
        )
        self.assertRegex(
            SOURCE,
            r"existingInstallId != null[\s\S]{0,500}lifecycleMarker\.createNewFile\(\)"
            r"[\s\S]{0,180}return",
        )
        self.assertRegex(
            SOURCE,
            r"existingInstallId != null[\s\S]{0,520}remove\(KEY_INSTALL_ID\)",
        )

    def test_install_id_is_random_and_lifecycle_hint_has_no_source_fallback(self) -> None:
        self.assertIn("IdentityIdGenerator.newInstallId()", MANAGER_SOURCE)
        self.assertIn("private fun resolveLocalInstallId()", MANAGER_SOURCE)
        self.assertRegex(
            MANAGER_SOURCE,
            r"store\.loadInstallId\(\)[\s\S]{0,180}takeIf\(::isUsableInstallId\)",
        )
        self.assertIn("InstallIdAdmission.isUsable(value)", MANAGER_SOURCE)
        self.assertIn("runCatching { store.persistInstallId(installId) }", MANAGER_SOURCE)
        self.assertNotIn("sourceDir", MANAGER_SOURCE)
        start = MANAGER_SOURCE.index("private fun resolveLocalInstallId()")
        end = MANAGER_SOURCE.index("private fun resolveInstallLifecycleSha256", start)
        local_install = MANAGER_SOURCE[start:end]
        self.assertNotIn("Build.", local_install)
        self.assertNotIn("Settings", local_install)

        start = MANAGER_SOURCE.index("private fun resolveInstallLifecycleSha256")
        end = MANAGER_SOURCE.index("private fun isUsableInstallId", start)
        lifecycle = MANAGER_SOURCE[start:end]
        self.assertIn("packageInfo?.firstInstallTime", lifecycle)
        self.assertIn("InstallLifecycleHint.sha256", lifecycle)
        self.assertNotIn("sourceDir", lifecycle)

        hint_source = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/IdentityProtectionState.kt"
        ).read_text(encoding="utf-8")
        self.assertIn('firstInstallTime?.takeIf { it > 0L }?.toString() ?: return null', hint_source)
        self.assertIn('"$packageName:install-epoch:$epoch"', hint_source)

    def test_environment_labels_are_validated_without_truncation(self) -> None:
        config_source = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/config/LeonaConfig.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("normalizeEnvironmentLabel(value)", config_source)
        self.assertIn("MAX_ENVIRONMENT_LENGTH", config_source)
        self.assertIn("Character::isISOControl", config_source)
        self.assertNotIn("environment = value?.trim()?.take(64)", config_source)

    def test_multi_process_is_explicitly_not_admitted(self) -> None:
        contract = json.loads(
            (
                Path(__file__).resolve().parents[2]
                / "compatibility/android-6-16-contract.json"
            ).read_text(encoding="utf-8")
        )
        compatibility = contract["identityContract"]["sdkCompatibility"]
        self.assertEqual(["single-process"], compatibility["processModes"])
        self.assertEqual(
            "BLOCKED_NOT_ADMITTED_SHARED_PREFS_NOT_CROSS_PROCESS_SAFE",
            compatibility["multiProcessStatus"],
        )


if __name__ == "__main__":
    unittest.main()
