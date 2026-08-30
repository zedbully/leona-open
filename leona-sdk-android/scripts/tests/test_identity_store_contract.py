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
SECURE_CHANNEL_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "sdk/src/main/kotlin/io/leonasec/leona/internal/SecureChannel.kt"
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
        self.assertIn("persist(\n            IdentityRecord.CANONICAL_DEVICE_ID", SOURCE)
        self.assertIn("persist(IdentityRecord.SNAPSHOT", SOURCE)
        self.assertIn("private fun persist(record: IdentityRecord, encryptedValue: String)", SOURCE)
        self.assertIn(".putString(record.preferenceKey, encryptedValue).commit()", SOURCE)
        self.assertIn('"Unable to persist Leona identity state"', SOURCE)
        self.assertNotIn(".apply()", SOURCE)

    def test_install_update_and_snapshot_invalidation_share_one_commit(self) -> None:
        self.assertIn("fun replaceInstallIdAndClearSnapshot(installId: String)", SOURCE)
        atomic = re.search(
            r"fun replaceInstallIdAndClearSnapshot[\s\S]*?prefs\.edit\(\)(?P<body>[\s\S]*?)\.commit\(\)",
            SOURCE,
        )
        self.assertIsNotNone(atomic)
        self.assertIn("putString(KEY_INSTALL_ID", atomic.group("body"))
        self.assertIn("remove(KEY_LAST_SNAPSHOT)", atomic.group("body"))
        self.assertIn("store.replaceInstallIdAndClearSnapshot(normalized)", MANAGER_SOURCE)
        policy = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/IdentityProtectionState.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("cached.installId == currentInstallId", policy)

    def test_corrupt_snapshot_is_quarantined_without_losing_current_status(self) -> None:
        self.assertIn("fun loadLastSnapshot(): DeviceFingerprintSnapshot?", SOURCE)
        self.assertIn("quarantine(IdentityRecord.SNAPSHOT)", SOURCE)
        self.assertIn("fun beginResolution()", SOURCE)
        self.assertIn("statusForNextRecordResolution(", SOURCE)
        self.assertRegex(
            SOURCE,
            r"prefs\.edit\(\)\.remove\(record\.preferenceKey\)\.commit\(\)",
        )
        self.assertIn("statusAfterRecordQuarantine(cleared)", SOURCE)
        policy = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/IdentityProtectionState.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("IdentityProtectionLevel.CORRUPT_OR_MISSING", policy)
        self.assertIn("recoverable = true", policy)
        self.assertIn("statusAfterSuccessfulRecovery", policy)

    def test_new_install_lifecycle_cannot_restore_identity_from_backup(self) -> None:
        self.assertIn("context.noBackupFilesDir", SOURCE)
        self.assertIn('"leona-install-lifecycle-v1"', SOURCE)
        self.assertIn("ensureCurrentInstallLifecycle()", SOURCE)
        self.assertIn("val dependenciesCleared", SOURCE)
        for key in ("KEY_INSTALL_ID", "KEY_CANONICAL_DEVICE_ID", "KEY_LAST_SNAPSHOT"):
            self.assertIn(f"remove({key})", SOURCE)
        clear_start = SOURCE.index("val dependenciesCleared")
        marker_start = SOURCE.index("if (!createLifecycleMarker())", clear_start)
        self.assertLess(clear_start, marker_start)
        retry_guard = SOURCE.index("IdentityProtectionLevel.KEYSTORE_UNAVAILABLE")
        self.assertLess(retry_guard, clear_start)
        self.assertIn("lifecycleMarker.createNewFile()", SOURCE)

    def test_valid_encrypted_state_survives_a_missing_sentinel(self) -> None:
        self.assertRegex(
            SOURCE,
            r"val existingInstallId = loadInstallId\(\)",
        )
        self.assertRegex(
            SOURCE,
            r"existingInstallId != null[\s\S]{0,500}createLifecycleMarker\(\)"
            r"[\s\S]{0,180}return",
        )

    def test_install_id_is_random_and_lifecycle_hint_has_no_source_fallback(self) -> None:
        self.assertIn("IdentityIdGenerator.newInstallId()", MANAGER_SOURCE)
        self.assertIn("private fun resolveLocalInstallId()", MANAGER_SOURCE)
        self.assertRegex(
            MANAGER_SOURCE,
            r"store\.loadInstallId\(\)[\s\S]{0,180}takeIf\(::isUsableInstallId\)",
        )
        self.assertIn("InstallIdAdmission.isUsable(value)", MANAGER_SOURCE)
        self.assertIn("store.replaceInstallIdAndClearSnapshot(installId)", MANAGER_SOURCE)
        self.assertIn("catch (_: IllegalStateException)", MANAGER_SOURCE)
        self.assertNotIn("runCatching { store.replaceInstallIdAndClearSnapshot(installId) }", MANAGER_SOURCE)
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

    def test_record_envelopes_are_versioned_and_domain_bound(self) -> None:
        policy = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/IdentityProtectionState.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("const val CURRENT_VERSION = 2", policy)
        self.assertIn("const val LEGACY_VERSION = 1", policy)
        self.assertIn("aadFor(record", policy)
        self.assertIn('"record", record.wireName', SOURCE)
        self.assertIn("cipher.updateAAD", SOURCE)
        self.assertIn("descriptor.legacy", SOURCE)
        self.assertIn("migrateLegacyIfNeeded", SOURCE)

    def test_legacy_migration_is_fail_closed_for_every_record(self) -> None:
        for method, record in (
            ("loadInstallId", "IdentityRecord.INSTALL_ID"),
            ("loadCanonicalDeviceId", "IdentityRecord.CANONICAL_DEVICE_ID"),
            ("loadLastSnapshot", "IdentityRecord.SNAPSHOT"),
        ):
            start = SOURCE.index(f"fun {method}")
            end = SOURCE.find("\n    fun ", start + 5)
            section = SOURCE[start:] if end < 0 else SOURCE[start:end]
            self.assertRegex(section, rf"migrateLegacyIfNeeded\(\s*{re.escape(record)}")
            self.assertIn("return null", section)

        self.assertNotIn("runCatching { persist(record, encrypt(record", SOURCE)
        migration_start = SOURCE.index("private fun migrateLegacyIfNeeded")
        migration_end = SOURCE.index("private fun quarantineAfterMigrationFailure", migration_start)
        migration = SOURCE[migration_start:migration_end]
        self.assertIn("catch (_: IllegalStateException)", migration)
        self.assertIn("currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED", migration)
        self.assertIn("quarantineAfterMigrationFailure(record)", migration)
        self.assertIn("return false", migration)

    def test_persisted_snapshot_semantics_are_strict(self) -> None:
        snapshot = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/DeviceFingerprintSnapshot.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("validateSemantics(obj, expectedPackageName)", snapshot)
        self.assertIn("InstallIdAdmission.isUsable(installId)", snapshot)
        self.assertIn("CanonicalIdAdmission.isUsable(canonicalDeviceId)", snapshot)
        self.assertIn("isSemanticallyCoherent()", snapshot)

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
        self.assertEqual("LEO_PROTECTED_LOGICAL_FIELDS", compatibility["transportFields"]["newIdentityFields"])
        self.assertFalse(compatibility["transportFields"]["clearHttpHeaders"])
        self.assertEqual("CROSS_MODULE_BLOCKED_NOT_ADMITTED", compatibility["transportFields"]["crossModuleStatus"])

    def test_identity_fields_are_protected_logical_fields_not_clear_headers(self) -> None:
        self.assertIn(
            "protectedHeaders = LeonaCryptoProtectedHeadersCodec.encode(headers)",
            SECURE_CHANNEL_SOURCE,
        )
        self.assertNotRegex(
            SECURE_CHANNEL_SOURCE,
            r"(?:addHeader|header)\(\s*\"X-Leona-(?:Environment|Session-Id-Sha256|Identity-Protection)\"",
        )

    def test_shared_preferences_wrong_types_are_quarantined_per_record(self) -> None:
        self.assertIn("private fun readStored(record: IdentityRecord): String?", SOURCE)
        self.assertIn("catch (_: ClassCastException)", SOURCE)
        self.assertIn("quarantine(record)", SOURCE)
        for record in ("INSTALL_ID", "CANONICAL_DEVICE_ID", "SNAPSHOT"):
            self.assertIn(f"readStored(IdentityRecord.{record})", SOURCE)
        self.assertNotIn("prefs.getString(KEY_LAST_SNAPSHOT", SOURCE)

    def test_current_snapshot_and_canonical_updates_share_manager_lock_and_admission(self) -> None:
        self.assertRegex(MANAGER_SOURCE, r"@Synchronized\s+fun currentSnapshot\(\)")
        self.assertRegex(MANAGER_SOURCE, r"@Synchronized\s+fun updateCanonicalDeviceId\(")
        self.assertIn("isCacheAdmissible(cached, currentInstallId, persistedCanonicalDeviceId", MANAGER_SOURCE)
        self.assertIn("IdentityCacheAdmission.isAdmissible", MANAGER_SOURCE)
        self.assertIn("shouldAttemptProtectedRecovery(snapshot.identityProtectionStatus)", MANAGER_SOURCE)
        self.assertIn("identityProtectionStatus = IdentityProtectionStatus.READY", MANAGER_SOURCE)
        self.assertIn("store.protectionStatus()", MANAGER_SOURCE)
        self.assertNotIn("runCatching { store.persistCanonicalDeviceId", MANAGER_SOURCE)

    def test_server_install_rotation_failure_is_visible_and_not_downgraded(self) -> None:
        update_start = MANAGER_SOURCE.index("fun updateServerInstallId")
        update_end = MANAGER_SOURCE.index("private fun normalizeServerInstallId", update_start)
        update = MANAGER_SOURCE[update_start:update_end]
        self.assertIn("store.replaceInstallIdAndClearSnapshot(normalized)", update)
        self.assertNotIn("runCatching", update)

    def test_quarantine_status_requires_protected_rewrite_before_consumption(self) -> None:
        policy = (
            Path(__file__).resolve().parents[2]
            / "sdk/src/main/kotlin/io/leonasec/leona/internal/identity/IdentityProtectionState.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("fun shouldAttemptProtectedRecovery", policy)
        self.assertIn("IdentityProtectionCode.ENVELOPE_INVALID", policy)
        self.assertIn("IdentityProtectionCode.STORAGE_WRITE_FAILED", policy)
        self.assertRegex(
            policy,
            r"fun statusForNextRecordResolution\([\s\S]*?\): IdentityProtectionStatus\s*\{[\s\S]*?return current",
        )
        self.assertIn("pendingRecordRecoveries", SOURCE)
        self.assertIn("protectedRecoveryReady", SOURCE)
        self.assertIn("protectedRecoveryReady.intersect(pendingRecordRecoveries)", SOURCE)


if __name__ == "__main__":
    unittest.main()
