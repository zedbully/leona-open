/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
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

    fun loadInstallId(): String? = decrypt(prefs.getString(KEY_INSTALL_ID, null))

    fun persistInstallId(installId: String) {
        prefs.edit().putString(KEY_INSTALL_ID, encrypt(installId)).apply()
    }

    fun loadCanonicalDeviceId(): String? = decrypt(prefs.getString(KEY_CANONICAL_DEVICE_ID, null))
        ?.trim()
        ?.ifEmpty { null }

    fun persistCanonicalDeviceId(deviceId: String) {
        prefs.edit().putString(KEY_CANONICAL_DEVICE_ID, encrypt(deviceId)).apply()
    }

    fun loadLastSnapshot(): DeviceFingerprintSnapshot? =
        DeviceFingerprintSnapshot.fromJson(decrypt(prefs.getString(KEY_LAST_SNAPSHOT, null)))

    fun persistLastSnapshot(snapshot: DeviceFingerprintSnapshot) {
        prefs.edit().putString(KEY_LAST_SNAPSHOT, encrypt(snapshot.toJson())).apply()
    }

    private fun encrypt(plaintext: String): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return plaintext
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
        }.getOrDefault(plaintext)
    }

    private fun decrypt(stored: String?): String? {
        if (stored == null) return null
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return stored
        return runCatching {
            val json = JSONObject(stored)
            if (json.optString("mode") != "keystore") return@runCatching stored
            val iv = Base64.decode(json.getString("iv"), Base64.NO_WRAP)
            val ct = Base64.decode(json.getString("ct"), Base64.NO_WRAP)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey(), GCMParameterSpec(128, iv))
            String(cipher.doFinal(ct), StandardCharsets.UTF_8)
        }.getOrNull() ?: stored
    }

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
        private const val KEY_INSTALL_ID = "install.id"
        private const val KEY_CANONICAL_DEVICE_ID = "device.id.canonical"
        private const val KEY_LAST_SNAPSHOT = "fingerprint.snapshot"
        private const val KEY_ALIAS = "io.leonasec.leona.identity.v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
