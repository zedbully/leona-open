/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import android.annotation.TargetApi
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

internal data class IdentityStoreDecryptedRecord(
    val plaintext: String,
    val legacy: Boolean,
)

/** Internal-only fault seam used by JVM tests; production defaults stay Android Keystore-backed. */
internal data class IdentityStoreCryptoHooks(
    val decrypt: ((IdentityRecord, String?) -> IdentityStoreDecryptedRecord?)? = null,
    val encrypt: ((IdentityRecord, String) -> String)? = null,
    val probe: (() -> IdentityProtectionStatus)? = null,
    val createLifecycleMarker: (() -> Boolean)? = null,
)

internal class LeonaIdentityStore(
    context: Context,
    private val cryptoHooks: IdentityStoreCryptoHooks? = null,
) {
    private val contextPackageName = context.applicationContext.packageName

    private var currentProtectionStatus: IdentityProtectionStatus = IdentityProtectionStatus.READY

    private val completedQuarantines = mutableSetOf<IdentityRecord>()
    private val pendingRecordRecoveries = mutableSetOf<IdentityRecord>()
    private val protectedRecoveryReady = mutableSetOf<IdentityRecord>()

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val lifecycleMarker = File(
        context.noBackupFilesDir,
        LIFECYCLE_MARKER_NAME,
    )

    init {
        probeKeyStore()
        ensureCurrentInstallLifecycle()
    }

    /** Typed diagnostic state; never use this as a business decision. */
    @Synchronized
    fun protectionStatus(): IdentityProtectionStatus = currentProtectionStatus

    /** Start a collection attempt; consume degradation only after protected recovery. */
    @Synchronized
    fun beginResolution() {
        val recoveredRecords = protectedRecoveryReady.intersect(pendingRecordRecoveries)
        if (recoveredRecords.isNotEmpty()) {
            pendingRecordRecoveries.removeAll(recoveredRecords)
            protectedRecoveryReady.removeAll(recoveredRecords)
            completedQuarantines.removeAll(recoveredRecords)
        }
        val hasQuarantinedRecord = completedQuarantines.isNotEmpty()
        val recordStillPresent = completedQuarantines.any { prefs.contains(it.preferenceKey) }
        val next = if (recoveredRecords.isNotEmpty() && pendingRecordRecoveries.isEmpty()) {
            IdentityPersistencePolicy.statusAfterSuccessfulRecovery(currentProtectionStatus)
        } else {
            IdentityPersistencePolicy.statusForNextRecordResolution(
                current = currentProtectionStatus,
                recordPresent = recordStillPresent,
                quarantineCompleted = hasQuarantinedRecord,
            )
        }
        if (next != currentProtectionStatus) {
            completedQuarantines.clear()
        }
        currentProtectionStatus = next
    }

    @Synchronized
    fun loadInstallId(): String? {
        val result = decryptRecord(IdentityRecord.INSTALL_ID, readStored(IdentityRecord.INSTALL_ID))
        if (result == null) {
            if (currentProtectionStatus.level == IdentityProtectionLevel.CORRUPT_OR_MISSING &&
                prefs.contains(IdentityRecord.INSTALL_ID.preferenceKey)
            ) {
                quarantine(IdentityRecord.INSTALL_ID)
            }
            return null
        }
        if (!InstallIdAdmission.isUsable(result.plaintext)) {
            currentProtectionStatus = IdentityProtectionStatus.CORRUPT_OR_MISSING
            quarantine(IdentityRecord.INSTALL_ID)
            return null
        }
        if (!migrateLegacyIfNeeded(IdentityRecord.INSTALL_ID, result)) return null
        return result.plaintext
    }

    /** Atomically replaces install_id and invalidates the cached snapshot. */
    @Synchronized
    fun replaceInstallIdAndClearSnapshot(installId: String) {
        require(InstallIdAdmission.isUsable(installId)) { "invalid install id" }
        val encryptedInstallId = encrypt(IdentityRecord.INSTALL_ID, installId)
        val committed = runCatching {
            prefs.edit()
                .putString(KEY_INSTALL_ID, encryptedInstallId)
                .remove(KEY_LAST_SNAPSHOT)
                .commit()
        }.getOrDefault(false)
        if (!committed) {
            pendingRecordRecoveries += IdentityRecord.INSTALL_ID
            pendingRecordRecoveries += IdentityRecord.SNAPSHOT
            protectedRecoveryReady.remove(IdentityRecord.INSTALL_ID)
            protectedRecoveryReady.remove(IdentityRecord.SNAPSHOT)
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            throw IllegalStateException("Unable to atomically update Leona install identity")
        }
        completedQuarantines.remove(IdentityRecord.INSTALL_ID)
        completedQuarantines.remove(IdentityRecord.SNAPSHOT)
        protectedRecoveryReady += IdentityRecord.INSTALL_ID
        protectedRecoveryReady += IdentityRecord.SNAPSHOT
    }

    @Synchronized
    fun clearLastSnapshot() {
        val cleared = runCatching {
            prefs.edit().remove(KEY_LAST_SNAPSHOT).commit()
        }.getOrDefault(false)
        if (!cleared) {
            pendingRecordRecoveries += IdentityRecord.SNAPSHOT
            protectedRecoveryReady.remove(IdentityRecord.SNAPSHOT)
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            throw IllegalStateException("Unable to clear Leona identity snapshot")
        }
        completedQuarantines.remove(IdentityRecord.SNAPSHOT)
        protectedRecoveryReady += IdentityRecord.SNAPSHOT
    }

    @Synchronized
    fun loadCanonicalDeviceId(): String? {
        val result = decryptRecord(
            IdentityRecord.CANONICAL_DEVICE_ID,
            readStored(IdentityRecord.CANONICAL_DEVICE_ID),
        )
        if (result == null) {
            if (currentProtectionStatus.level == IdentityProtectionLevel.CORRUPT_OR_MISSING &&
                prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey)
            ) {
                quarantine(IdentityRecord.CANONICAL_DEVICE_ID)
            }
            return null
        }
        val canonical = result.plaintext.trim().ifEmpty { null }
        if (canonical == null || !CanonicalIdAdmission.isUsable(canonical)) {
            currentProtectionStatus = IdentityProtectionStatus.CORRUPT_OR_MISSING
            quarantine(IdentityRecord.CANONICAL_DEVICE_ID)
            return null
        }
        val migrated = migrateLegacyIfNeeded(
            IdentityRecord.CANONICAL_DEVICE_ID,
            result.copy(plaintext = canonical),
        )
        if (!migrated) return null
        return canonical
    }

    @Synchronized
    fun persistCanonicalDeviceId(deviceId: String) {
        require(CanonicalIdAdmission.isUsable(deviceId)) { "invalid canonical device id" }
        persist(
            IdentityRecord.CANONICAL_DEVICE_ID,
            encrypt(IdentityRecord.CANONICAL_DEVICE_ID, deviceId),
        )
    }

    @Synchronized
    fun loadLastSnapshot(): DeviceFingerprintSnapshot? {
        val stored = readStored(IdentityRecord.SNAPSHOT) ?: return null
        val decrypted = decryptRecord(IdentityRecord.SNAPSHOT, stored)
        if (decrypted == null) {
            if (currentProtectionStatus.level == IdentityProtectionLevel.CORRUPT_OR_MISSING &&
                prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey)
            ) {
                quarantine(IdentityRecord.SNAPSHOT)
            }
            return null
        }
        val snapshot = DeviceFingerprintSnapshot.fromJson(
            decrypted.plaintext,
            expectedPackageName = contextPackageName,
        )
        if (snapshot != null) {
            if (!migrateLegacyIfNeeded(IdentityRecord.SNAPSHOT, decrypted)) return null
            return snapshot
        }

        // Authenticated plaintext that is not a valid snapshot is still a
        // corrupt record. Remove only this record; install/canonical state is
        // retained and the corruption status remains on the current report.
        currentProtectionStatus = IdentityProtectionStatus.CORRUPT_OR_MISSING
        quarantine(IdentityRecord.SNAPSHOT)
        return null
    }

    @Synchronized
    fun persistLastSnapshot(snapshot: DeviceFingerprintSnapshot) {
        require(
            DeviceFingerprintSnapshot.fromJson(snapshot.toJson(), expectedPackageName = contextPackageName) != null,
        ) { "invalid identity snapshot" }
        persist(IdentityRecord.SNAPSHOT, encrypt(IdentityRecord.SNAPSHOT, snapshot.toJson()))
    }

    private fun quarantine(record: IdentityRecord) {
        val cleared = runCatching {
            prefs.edit().remove(record.preferenceKey).commit()
        }.getOrDefault(false)
        // Keep the affected record pending even when the clear itself fails;
        // a later protected rewrite of this same record is the only recovery
        // that may consume the degradation.
        pendingRecordRecoveries.add(record)
        if (cleared) completedQuarantines.add(record)
        // A quarantine is evidence for the current report, not a successful
        // protected rewrite. Never let an earlier recovery marker consume it.
        protectedRecoveryReady.remove(record)
        currentProtectionStatus = IdentityPersistencePolicy.statusAfterRecordQuarantine(cleared)
    }

    /** SharedPreferences throws when a caller or older version stored a wrong type. */
    private fun readStored(record: IdentityRecord): String? = try {
        prefs.getString(record.preferenceKey, null)
    } catch (_: ClassCastException) {
        currentProtectionStatus = IdentityProtectionStatus.CORRUPT_OR_MISSING
        quarantine(record)
        null
    }

    /**
     * Identity state must survive a successful call before it can be used as an
     * anchor. `apply()` is asynchronous and hides a failed disk write, so use
     * synchronous `commit()` and make failure visible to the caller.
     */
    private fun persist(record: IdentityRecord, encryptedValue: String) {
        val committed = runCatching {
            prefs.edit().putString(record.preferenceKey, encryptedValue).commit()
        }.getOrDefault(false)
        if (!committed) {
            pendingRecordRecoveries += record
            protectedRecoveryReady.remove(record)
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            throw IllegalStateException("Unable to persist Leona identity state")
        }
        completedQuarantines.remove(record)
        if (pendingRecordRecoveries.contains(record)) protectedRecoveryReady.add(record)
    }

    /**
     * noBackupFilesDir is deliberately used only as an install-lifecycle
     * sentinel. Android Auto Backup excludes this directory, so a restored
     * SharedPreferences file cannot silently resurrect an old install id.
     * The sentinel contains no identity value and is not a trust anchor.
     */
    private fun ensureCurrentInstallLifecycle() {
        if (lifecycleMarker.exists()) return
        val parent = lifecycleMarker.parentFile
        if (parent != null && !parent.isDirectory && !runCatching { parent.mkdirs() }.getOrDefault(false)) {
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            return
        }

        // A valid Keystore envelope is stronger evidence of the current app
        // installation than the no-backup sentinel. Some managed/emulated
        // environments can omit no-backup files from a reboot snapshot while
        // retaining ordinary app data. Preserve the encrypted install state in
        // that case; otherwise a reboot would look like an uninstall. On a
        // genuine reinstall, the app-scoped Keystore key is gone, so decrypt
        // fails and the restored preference is discarded below.
        val existingInstallId = loadInstallId()
        if (existingInstallId != null) {
            if (!createLifecycleMarker()) {
                currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            }
            return
        }
        if (currentProtectionStatus.level == IdentityProtectionLevel.KEYSTORE_UNAVAILABLE ||
            currentProtectionStatus.level == IdentityProtectionLevel.UNSUPPORTED_API ||
            currentProtectionStatus.code == IdentityProtectionCode.STORAGE_WRITE_FAILED
        ) {
            // Preserve recoverable ciphertext when migration or storage failed;
            // a later initialization can retry after the provider is available.
            return
        }

        val dependenciesCleared = runCatching {
            prefs.edit()
                .remove(KEY_INSTALL_ID)
                .remove(KEY_CANONICAL_DEVICE_ID)
                .remove(KEY_LAST_SNAPSHOT)
                .commit()
        }.getOrDefault(false)
        if (!dependenciesCleared) {
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            return
        }
        if (!createLifecycleMarker()) {
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
        }
    }

    private fun createLifecycleMarker(): Boolean =
        cryptoHooks?.createLifecycleMarker?.let { hook -> runCatching { hook() }.getOrDefault(false) }
            ?: runCatching { lifecycleMarker.createNewFile() || lifecycleMarker.exists() }.getOrDefault(false)

    /**
     * Legacy v1 values are never returned until their v2 domain-bound rewrite
     * has committed. Encryption/provider failures keep the old ciphertext for
     * recovery; a failed rewrite commit quarantines only this record.
     */
    private fun migrateLegacyIfNeeded(record: IdentityRecord, decrypted: IdentityStoreDecryptedRecord): Boolean {
        if (!decrypted.legacy) return true
        val encrypted = try {
            encrypt(record, decrypted.plaintext)
        } catch (_: IllegalStateException) {
            // encrypt() has already recorded a bounded Keystore/API status.
            // The caller must not use the legacy plaintext after this failure.
            pendingRecordRecoveries.add(record)
            protectedRecoveryReady.remove(record)
            return false
        }
        val committed = try {
            prefs.edit().putString(record.preferenceKey, encrypted).commit()
        } catch (_: RuntimeException) {
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            false
        }
        if (!committed) {
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
            quarantineAfterMigrationFailure(record)
            return false
        }
        completedQuarantines.remove(record)
        if (pendingRecordRecoveries.contains(record)) protectedRecoveryReady.add(record)
        return true
    }

    private fun quarantineAfterMigrationFailure(record: IdentityRecord) {
        val migrationFailureStatus = currentProtectionStatus
        val cleared = try {
            prefs.edit().remove(record.preferenceKey).commit()
        } catch (_: RuntimeException) {
            false
        }
        pendingRecordRecoveries.add(record)
        if (cleared) {
            completedQuarantines.add(record)
            currentProtectionStatus = if (migrationFailureStatus.code == IdentityProtectionCode.STORAGE_WRITE_FAILED) {
                IdentityProtectionStatus.STORAGE_WRITE_FAILED
            } else {
                IdentityProtectionStatus.CORRUPT_OR_MISSING
            }
        } else {
            currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED
        }
        protectedRecoveryReady.remove(record)
    }

    private fun encrypt(record: IdentityRecord, plaintext: String): String {
        cryptoHooks?.encrypt?.let { hook ->
            return try {
                hook(record, plaintext)
            } catch (failure: IllegalStateException) {
                currentProtectionStatus = IdentityProtectionStatus.KEYSTORE_UNAVAILABLE
                throw failure
            }
        }
        // The public compatibility matrix starts at Android 6 / API 23. Do not
        // silently downgrade the identity envelope to plaintext on older hosts:
        // an installed APK must fail closed rather than make tamperable state
        // look like a trusted device anchor.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            currentProtectionStatus = IdentityProtectionStatus.API_BELOW_23
        }
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            "Android Keystore-backed identity requires API 23+"
        }
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
            cipher.updateAAD(
                IdentityEnvelopePolicy.aadFor(record).toByteArray(StandardCharsets.UTF_8),
            )
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
            JSONObject()
                .put("version", IdentityEnvelopePolicy.CURRENT_VERSION)
                .put("mode", "keystore")
                .put("record", record.wireName)
                .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                .put("ct", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .toString()
        }.getOrElse { cause ->
            // Android 6+ is the commercial support floor. Never silently downgrade
            // device-identity state to plaintext when Android Keystore is unavailable.
            currentProtectionStatus = IdentityProtectionStatus.KEYSTORE_UNAVAILABLE
            throw IllegalStateException("Unable to encrypt Leona identity state", cause)
        }
    }

    private fun decryptRecord(
        record: IdentityRecord,
        stored: String?,
    ): IdentityStoreDecryptedRecord? {
        if (stored == null) return null
        cryptoHooks?.decrypt?.let { hook -> return hook(record, stored) }
        // Legacy plaintext preferences are never accepted as identity state.
        // This also makes an API < 23 host fail closed on the next write instead
        // of treating a pre-matrix value as a trusted anchor.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            currentProtectionStatus = IdentityProtectionStatus.API_BELOW_23
            return null
        }
        if (stored.length > MAX_ENVELOPE_LENGTH) {
            currentProtectionStatus = IdentityProtectionStatus.CORRUPT_OR_MISSING
            return null
        }
        // API 23+ accepts only authenticated AES-GCM envelopes. Legacy/plaintext or
        // malformed values are discarded so local preference tampering cannot become
        // trusted install/canonical/fingerprint state.
        val descriptor = IdentityEnvelopePolicy.inspect(stored, expectedRecord = record)
        if (descriptor == null) {
            currentProtectionStatus = IdentityProtectionStatus.CORRUPT_OR_MISSING
            return null
        }
        val json = runCatching { JSONObject(stored) }.getOrNull()
        if (json == null || json.optString("mode") != "keystore") {
            currentProtectionStatus = IdentityProtectionStatus.CORRUPT_OR_MISSING
            return null
        }
        return runCatching {
            val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
            val ct = Base64.decode(json.getString("ct"), Base64.NO_WRAP)
            require(iv.size == GCM_IV_LENGTH_BYTES) { "invalid identity envelope IV" }
            require(ct.size >= GCM_TAG_LENGTH_BYTES) { "invalid identity envelope ciphertext" }
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                keystoreKey(),
                GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv),
            )
            if (!descriptor.legacy) {
                cipher.updateAAD(
                    IdentityEnvelopePolicy.aadFor(record, descriptor.version)
                        .toByteArray(StandardCharsets.UTF_8),
                )
            }
            String(cipher.doFinal(ct), StandardCharsets.UTF_8)
        }.onSuccess {
            currentProtectionStatus = IdentityPersistencePolicy.preserveProbeStatus(
                current = currentProtectionStatus,
                probeSucceeded = true,
            )
        }.onFailure { cause ->
            // A missing/invalid Keystore key and an authentication-tag failure
            // are both non-admissible local state. Keep the reason typed and
            // bounded; never expose provider exception text to callers.
            currentProtectionStatus = if (cause is javax.crypto.AEADBadTagException) {
                IdentityProtectionStatus.CORRUPT_OR_MISSING
            } else {
                IdentityProtectionStatus.KEYSTORE_UNAVAILABLE
            }
        }.map { plaintext ->
            IdentityStoreDecryptedRecord(plaintext = plaintext, legacy = descriptor.legacy)
        }.getOrNull()
    }

    private fun probeKeyStore() {
        cryptoHooks?.probe?.let { probe ->
            currentProtectionStatus = runCatching { probe() }
                .getOrElse { IdentityProtectionStatus.KEYSTORE_UNAVAILABLE }
            return
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            currentProtectionStatus = IdentityProtectionStatus.API_BELOW_23
            return
        }
        runCatching { keystoreKey() }
            .onSuccess {
                currentProtectionStatus = IdentityPersistencePolicy.preserveProbeStatus(
                    current = currentProtectionStatus,
                    probeSucceeded = true,
                )
            }
            .onFailure {
                currentProtectionStatus = if (currentProtectionStatus == IdentityProtectionStatus.READY) {
                    IdentityProtectionStatus.KEYSTORE_UNAVAILABLE
                } else {
                    currentProtectionStatus
                }
            }
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun keystoreKey(): java.security.Key {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        keyStore.getKey(KEY_ALIAS, null)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    companion object {
        private const val PREFS_NAME = "io.leonasec.leona.identity"
        private const val LIFECYCLE_MARKER_NAME = "leona-install-lifecycle-v1"
        private const val KEY_INSTALL_ID = "install.id"
        private const val KEY_CANONICAL_DEVICE_ID = "device.id.canonical"
        private const val KEY_LAST_SNAPSHOT = "fingerprint.snapshot"
        private const val KEY_ALIAS = "io.leonasec.leona.identity.v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH_BYTES = 12
        private const val GCM_TAG_LENGTH_BYTES = 16
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val MAX_ENVELOPE_LENGTH = 65_536
    }
}
