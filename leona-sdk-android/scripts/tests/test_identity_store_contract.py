#!/usr/bin/env python3
"""Source contract for API 23+ Leona identity persistence hardening."""

import re
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
        self.assertRegex(SOURCE, r"if \(Build\.VERSION\.SDK_INT\s*<\s*Build\.VERSION_CODES\.M\) return null")
        self.assertIn("if (stored.length > MAX_ENVELOPE_LENGTH) return null", SOURCE)
        self.assertRegex(SOURCE, r"JSONObject\(stored\)[\s\S]{0,100}getOrNull\(\)\s*\?:\s*return null")
        self.assertRegex(SOURCE, r'optString\("mode"\)\s*!=\s*"keystore"\)\s*return null')
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

    def test_install_epoch_seed_is_only_a_storage_recovery_input(self) -> None:
        self.assertIn("packageInfo?.firstInstallTime", MANAGER_SOURCE)
        self.assertIn("appContext.applicationInfo?.sourceDir", MANAGER_SOURCE)
        self.assertIn("val packageInstallEpoch", MANAGER_SOURCE)
        self.assertIn("UUID.nameUUIDFromBytes", MANAGER_SOURCE)
        self.assertIn('"${appContext.packageName}:install-epoch:$epoch"', MANAGER_SOURCE)
        self.assertIn("toByteArray(StandardCharsets.UTF_8)", MANAGER_SOURCE)
        self.assertIn("The seed is hashed in the", MANAGER_SOURCE)


if __name__ == "__main__":
    unittest.main()
