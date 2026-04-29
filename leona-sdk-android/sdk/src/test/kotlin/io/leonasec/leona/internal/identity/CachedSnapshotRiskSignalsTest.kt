/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.junit.Assert.assertEquals
import org.junit.Test

class CachedSnapshotRiskSignalsTest {

    @Test
    fun `cache hit refreshes risk signals and upload metadata while reusing identity fields`() {
        val cached = snapshot(
            installerPackage = "com.android.vending",
            signingCertSha256 = listOf("stable-cert"),
            riskSignals = setOf(
                "developer.adb_enabled",
                "network.proxy_configured",
                "package.name_mismatch",
                "signature.untrusted",
            ),
        )

        val refreshed = CachedSnapshotRiskSignals.refresh(
            cached = cached,
            installerPackage = null,
            signingCertSha256 = listOf("fresh-cert"),
            riskSignals = setOf("debugger.attached", "root.basic"),
        )

        assertEquals(cached.installId, refreshed.installId)
        assertEquals(cached.canonicalDeviceId, refreshed.canonicalDeviceId)
        assertEquals(cached.resolvedDeviceId, refreshed.resolvedDeviceId)
        assertEquals(cached.fingerprintHash, refreshed.fingerprintHash)
        assertEquals(null, refreshed.installerPackage)
        assertEquals(listOf("fresh-cert"), refreshed.signingCertSha256)
        assertEquals(
            setOf("debugger.attached", "root.basic"),
            refreshed.riskSignals,
        )
    }

    @Test
    fun `cache hit can clear stale risk signals after a fresh collection`() {
        val cached = snapshot(
            installerPackage = "com.untrusted.store",
            signingCertSha256 = listOf("untrusted-cert"),
            riskSignals = setOf(
                "root.basic",
                "root.packages",
                "environment.emulator",
                "environment.virtual_container",
                "installer.untrusted",
                "signature.untrusted",
                "developer.options_enabled",
            ),
        )

        val refreshed = CachedSnapshotRiskSignals.refresh(
            cached = cached,
            installerPackage = "com.android.vending",
            signingCertSha256 = listOf("trusted-cert"),
            riskSignals = emptySet(),
        )

        assertEquals(cached.copy(
            installerPackage = "com.android.vending",
            signingCertSha256 = listOf("trusted-cert"),
            riskSignals = emptySet(),
        ), refreshed)
    }

    private fun snapshot(
        installerPackage: String?,
        signingCertSha256: List<String>,
        riskSignals: Set<String>,
    ): DeviceFingerprintSnapshot = DeviceFingerprintSnapshot(
        generatedAtMillis = 123L,
        installId = "install-1",
        canonicalDeviceId = "Ldevice-1",
        resolvedDeviceId = "Ldevice-1",
        fingerprintHash = "fingerprint-1",
        packageName = "io.leonasec.actual",
        appVersionName = "1.2.3",
        appVersionCode = 42L,
        installerPackage = installerPackage,
        androidId = "android-1",
        signingCertSha256 = signingCertSha256,
        brand = "google",
        model = "pixel",
        manufacturer = "google",
        sdkInt = 34,
        abis = listOf("arm64-v8a"),
        localeTag = "en-US",
        timeZoneId = "UTC",
        screenSummary = "1080x2400@440",
        riskSignals = riskSignals,
    )
}
