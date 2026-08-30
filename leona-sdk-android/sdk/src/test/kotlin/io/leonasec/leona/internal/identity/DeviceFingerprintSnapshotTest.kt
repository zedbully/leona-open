/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import io.leonasec.leona.LeonaDeviceEnvironmentEvidence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class DeviceFingerprintSnapshotTest {

    @Test
    fun `snapshot survives json round trip`() {
        val snapshot = DeviceFingerprintSnapshot(
            generatedAtMillis = 123L,
            installId = "install-1",
            canonicalDeviceId = "canon-1",
            resolvedDeviceId = "Lcanon-1",
            fingerprintHash = "abc123",
            fingerprintSource = "base_device_v2",
            identityAnchorSource = "android_id",
            canonicalDeviceIdSource = "server_persisted",
            packageName = "io.leonasec.demo",
            appVersionName = "1.2.3",
            appVersionCode = 42L,
            installerPackage = "com.android.vending",
            androidId = "android-123",
            signingCertSha256 = listOf("aa", "bb"),
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
}
