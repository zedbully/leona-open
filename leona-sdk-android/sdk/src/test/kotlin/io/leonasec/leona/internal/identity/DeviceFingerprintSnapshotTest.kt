/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import io.leonasec.leona.LeonaDeviceEnvironmentEvidence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class DeviceFingerprintSnapshotTest {

    @Test
    fun `snapshot survives json round trip`() {
        val snapshot = DeviceFingerprintSnapshot(
            generatedAtMillis = 123L,
            installId = "00000000-0000-4000-8000-000000000001",
            canonicalDeviceId = "L00000000000000000000000000000001",
            resolvedDeviceId = "L00000000000000000000000000000001",
            fingerprintHash = "a".repeat(64),
            fingerprintSource = "base_device_v2",
            identityAnchorSource = "android_id",
            canonicalDeviceIdSource = "server_persisted",
            packageName = "io.leonasec.demo",
            appVersionName = "1.2.3",
            appVersionCode = 42L,
            installerPackage = "com.android.vending",
            androidId = "android-123",
            signingCertSha256 = listOf("b".repeat(64), "c".repeat(64)),
            brand = "google",
            model = "pixel",
            manufacturer = "google",
            sdkInt = 34,
            abis = listOf("arm64-v8a"),
            localeTag = "en-US",
            timeZoneId = "UTC",
            screenSummary = "1080x2400@440",
            riskSignals = setOf("root.basic", "debugger.attached"),
            deviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence(
                evidenceIds = setOf("build.tags.test_keys", "verified_boot.orange"),
                build = mapOf("tags" to "test-keys", "type" to "userdebug"),
                verifiedBoot = mapOf("state" to "orange"),
            ),
            installLifecycleSha256 = "e".repeat(64),
        )

        val parsed = DeviceFingerprintSnapshot.fromJson(snapshot.toJson())
        assertNotNull(parsed)
        assertEquals(snapshot, parsed)
        assertEquals(
            setOf("root.su_or_busybox_path_present", "debugger.attached"),
            parsed?.evidenceSignals,
        )
    }

    @Test
    fun `snapshot semantic validation rejects wrong types ids package and status coherence`() {
        val valid = org.json.JSONObject(validSnapshotJson())

        assertNull(
            DeviceFingerprintSnapshot.fromJson(
                org.json.JSONObject(valid.toString()).put("installId", "plaintext").toString(),
            ),
        )
        assertNull(
            DeviceFingerprintSnapshot.fromJson(
                org.json.JSONObject(valid.toString()).put("fingerprintHash", 7).toString(),
            ),
        )
        assertNull(
            DeviceFingerprintSnapshot.fromJson(
                org.json.JSONObject(valid.toString()).put("packageName", "other.pkg").toString(),
                expectedPackageName = "io.leonasec.demo",
            ),
        )
        assertNull(
            DeviceFingerprintSnapshot.fromJson(
                org.json.JSONObject(valid.toString())
                    .put("identityProtectionLevel", "KEYSTORE_AES_GCM")
                    .put("identityProtectionCode", "STORAGE_WRITE_FAILED")
                    .put("identityProtectionDurable", true)
                    .put("identityProtectionRecoverable", true)
                    .toString(),
            ),
        )
    }

    private fun validSnapshotJson(): String = DeviceFingerprintSnapshot(
        generatedAtMillis = 123L,
        installId = "00000000-0000-4000-8000-000000000001",
        canonicalDeviceId = "L00000000000000000000000000000001",
        resolvedDeviceId = "L00000000000000000000000000000001",
        fingerprintHash = "a".repeat(64),
        fingerprintSource = "base_device_v2",
        identityAnchorSource = "android_id",
        canonicalDeviceIdSource = "server_persisted",
        packageName = "io.leonasec.demo",
        appVersionName = "1.2.3",
        appVersionCode = 42L,
        installerPackage = "com.android.vending",
        androidId = "android-123",
        signingCertSha256 = listOf("b".repeat(64), "c".repeat(64)),
        brand = "google",
        model = "pixel",
        manufacturer = "google",
        sdkInt = 34,
        abis = listOf("arm64-v8a"),
        localeTag = "en-US",
        timeZoneId = "UTC",
        screenSummary = "1080x2400@440",
        riskSignals = setOf("root.basic"),
        deviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.EMPTY,
    ).toJson()
}
