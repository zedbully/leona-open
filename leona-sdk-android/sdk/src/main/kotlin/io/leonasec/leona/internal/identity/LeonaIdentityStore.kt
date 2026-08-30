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

internal class LeonaIdentityStore(
    context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val lifecycleMarker = File(
        context.noBackupFilesDir,
        LIFECYCLE_MARKER_NAME,
    )

    init {
        ensureCurrentInstallLifecycle()
    }

    fun loadInstallId(): String? = decrypt(prefs.getString(KEY_INSTALL_ID, null))

    fun persistInstallId(installId: String) {
        persist(KEY_INSTALL_ID, encrypt(installId))
    }

    fun clearLastSnapshot() {
        check(prefs.edit().remove(KEY_LAST_SNAPSHOT).commit()) {
            "Unable to clear Leona identity snapshot"
        }
    }

    fun loadCanonicalDeviceId(): String? = decrypt(prefs.getString(KEY_CANONICAL_DEVICE_ID, null))
        ?.trim()
        ?.ifEmpty { null }

    fun persistCanonicalDeviceId(deviceId: String) {
        persist(KEY_CANONICAL_DEVICE_ID, encrypt(deviceId))
    }

    fun loadLastSnapshot(): DeviceFingerprintSnapshot? =
        DeviceFingerprintSnapshot.fromJson(decrypt(prefs.getString(KEY_LAST_SNAPSHOT, null)))

    fun persistLastSnapshot(snapshot: DeviceFingerprintSnapshot) {
        persist(KEY_LAST_SNAPSHOT, encrypt(snapshot.toJson()))
    }

    /**
     * Identity state must survive a successful call before it can be used as an
     * anchor. `apply()` is asynchronous and hides a failed disk write, so use
     * synchronous `commit()` and make failure visible to the caller.
     */
    private fun persist(key: String, encryptedValue: String) {
        check(prefs.edit().putString(key, encryptedValue).commit()) {
            "Unable to persist Leona identity state"
        }
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
        check(parent == null || parent.isDirectory || parent.mkdirs()) {
            "Unable to prepare Leona install lifecycle state"
        }

        // A valid Keystore envelope is stronger evidence of the current app
        // installation than the no-backup sentinel. Some managed/emulated
        // environments can omit no-backup files from a reboot snapshot while
        // retaining ordinary app data. Preserve the encrypted install state in
        // that case; otherwise a reboot would look like an uninstall. On a
        // genuine reinstall, the app-scoped Keystore key is gone, so decrypt
        // fails and the restored preference is discarded below.
        val existingInstallId = decrypt(prefs.getString(KEY_INSTALL_ID, null))
        if (existingInstallId != null) {
            check(lifecycleMarker.createNewFile() || lifecycleMarker.exists()) {
                "Unable to restore Leona install lifecycle state"
            }
            return
        }

        check(
            prefs.edit()
                .remove(KEY_INSTALL_ID)
                .remove(KEY_CANONICAL_DEVICE_ID)
                .remove(KEY_LAST_SNAPSHOT)
                .commit(),
        ) {
            "Unable to reset Leona identity state for a new install"
        }
        check(lifecycleMarker.createNewFile() || lifecycleMarker.exists()) {
            "Unable to persist Leona install lifecycle state"
        }
    }

    private fun encrypt(plaintext: String): String {
        // The public compatibility matrix starts at Android 6 / API 23. Do not
        // silently downgrade the identity envelope to plaintext on older hosts:
        // an installed APK must fail closed rather than make tamperable state
        // look like a trusted device anchor.
        check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            "Android Keystore-backed identity requires API 23+"
        }
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext.toByteArray(StandardCharsets.UTF_8))
            JSONObject()
                .put("mode", "keystore")
                .put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                .put("ct", Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .toString()
        }.getOrElse { cause ->
            // Android 6+ is the commercial support floor. Never silently downgrade
            // device-identity state to plaintext when Android Keystore is unavailable.
            throw IllegalStateException("Unable to encrypt Leona identity state", cause)
        }
    }

    private fun decrypt(stored: String?): String? {
        if (stored == null) return null
        // Legacy plaintext preferences are never accepted as identity state.
        // This also makes an API < 23 host fail closed on the next write instead
        // of treating a pre-matrix value as a trusted anchor.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        if (stored.length > MAX_ENVELOPE_LENGTH) return null
        // API 23+ accepts only authenticated AES-GCM envelopes. Legacy/plaintext or
        // malformed values are discarded so local preference tampering cannot become
        // trusted install/canonical/fingerprint state.
        val json = runCatching { JSONObject(stored) }.getOrNull() ?: return null
        if (json.optString("mode") != "keystore") return null
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
            String(cipher.doFinal(ct), StandardCharsets.UTF_8)
        }.getOrNull()
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
