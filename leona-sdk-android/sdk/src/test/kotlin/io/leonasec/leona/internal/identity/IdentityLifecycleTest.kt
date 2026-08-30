/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityLifecycleTest {

    @Test
    fun `install id is random and independent from session id`() {
        val firstInstall = IdentityIdGenerator.newInstallId()
        val secondInstall = IdentityIdGenerator.newInstallId()
        val firstSession = IdentityIdGenerator.newSessionId()
        val secondSession = IdentityIdGenerator.newSessionId()

        assertNotEquals(firstInstall, secondInstall)
        assertNotEquals(firstSession, secondSession)
        assertNotEquals(firstInstall, firstSession)
        assertTrue(firstInstall.matches(LOCAL_UUID))
        assertTrue(secondInstall.matches(LOCAL_UUID))
        assertTrue(firstSession.matches(SESSION_ID))
        assertTrue(secondSession.matches(SESSION_ID))
    }

    @Test
    fun `corrupt or arbitrary stored install ids are not admitted`() {
        assertFalse(InstallIdAdmission.isUsable("plaintext-install-id"))
        assertFalse(InstallIdAdmission.isUsable("I" + "0".repeat(31)))
        assertTrue(InstallIdAdmission.isUsable("I" + "0".repeat(32)))
        assertTrue(InstallIdAdmission.isUsable(IdentityIdGenerator.newInstallId()))
    }

    @Test
    fun `protection degradation is typed and never durable`() {
        val degraded = IdentityProtectionStatus.KEYSTORE_UNAVAILABLE

        assertTrue(degraded.isDegraded)
        assertFalse(degraded.durable)
        assertEquals(IdentityProtectionCode.KEYSTORE_INIT_FAILED, degraded.code)
        assertEquals(IdentityProtectionLevel.KEYSTORE_UNAVAILABLE, degraded.level)
    }

    @Test
    fun `snapshot keeps install and session separate without persisting session`() {
        val snapshot = DeviceFingerprintSnapshot(
            generatedAtMillis = 1L,
            installId = IdentityIdGenerator.newInstallId(),
            canonicalDeviceId = null,
            resolvedDeviceId = "T" + "a".repeat(43),
            fingerprintHash = "a".repeat(64),
            packageName = "io.leonasec.test",
            appVersionName = "1",
            appVersionCode = 1L,
            installerPackage = null,
            androidId = null,
            signingCertSha256 = emptyList(),
            brand = "brand",
            model = "model",
            manufacturer = "manufacturer",
            sdkInt = 23,
            abis = listOf("arm64-v8a"),
            localeTag = "en-US",
            timeZoneId = "UTC",
            screenSummary = null,
            riskSignals = emptySet(),
            sessionId = IdentityIdGenerator.newSessionId(),
            identityProtectionStatus = IdentityProtectionStatus.READY,
        )

        val restored = DeviceFingerprintSnapshot.fromJson(snapshot.toJson())

        assertEquals(snapshot.installId, restored?.installId)
        assertEquals("", restored?.sessionId)
        assertNotEquals(snapshot.installId, snapshot.sessionId)
        assertEquals(IdentityProtectionLevel.KEYSTORE_AES_GCM, restored?.identityProtectionStatus?.level)
        assertFalse(snapshot.toJson().contains("sessionId"))

        val legacy = org.json.JSONObject(snapshot.toJson()).put("sessionId", "Slegacy")
        assertEquals("", DeviceFingerprintSnapshot.fromJson(legacy.toString())?.sessionId)
    }

    @Test
    fun `lifecycle hint is absent without a positive install epoch and rotates by epoch`() {
        assertEquals(null, InstallLifecycleHint.sha256("io.leonasec.test", null))
        assertEquals(null, InstallLifecycleHint.sha256("io.leonasec.test", 0L))
        assertEquals(null, InstallLifecycleHint.sha256("io.leonasec.test", -1L))
        val first = InstallLifecycleHint.sha256("io.leonasec.test", 100L)
        val same = InstallLifecycleHint.sha256("io.leonasec.test", 100L)
        val reinstalled = InstallLifecycleHint.sha256("io.leonasec.test", 200L)
        assertEquals(first, same)
        assertNotEquals(first, reinstalled)
    }

    @Test
    fun `degraded persistence returns memory-only policy and preserves failure`() {
        assertTrue(IdentityPersistencePolicy.shouldPersistSnapshot(IdentityProtectionStatus.READY))
        assertFalse(IdentityPersistencePolicy.shouldPersistSnapshot(IdentityProtectionStatus.KEYSTORE_UNAVAILABLE))
        assertFalse(IdentityPersistencePolicy.shouldPersistSnapshot(IdentityProtectionStatus.STORAGE_WRITE_FAILED))
        assertEquals(
            IdentityProtectionStatus.CORRUPT_OR_MISSING,
            IdentityPersistencePolicy.preserveProbeStatus(
                IdentityProtectionStatus.CORRUPT_OR_MISSING,
                probeSucceeded = true,
            ),
        )
        assertTrue(
            IdentityPersistencePolicy.shouldAttemptProtectedRecovery(
                IdentityProtectionStatus.CORRUPT_OR_MISSING,
            ),
        )
        assertFalse(
            IdentityPersistencePolicy.shouldAttemptProtectedRecovery(
                IdentityProtectionStatus.STORAGE_WRITE_FAILED,
            ),
        )
    }

    @Test
    fun `corrupt snapshot quarantine preserves report status and retries after clear failure`() {
        val failedClear = IdentityPersistencePolicy.statusAfterRecordQuarantine(clearSucceeded = false)
        assertEquals(IdentityProtectionLevel.CORRUPT_OR_MISSING, failedClear.level)
        assertEquals(IdentityProtectionCode.STORAGE_WRITE_FAILED, failedClear.code)
        assertFalse(failedClear.durable)
        assertTrue(failedClear.recoverable)

        val nextAttempt = IdentityPersistencePolicy.statusAfterRecordQuarantine(clearSucceeded = true)
        assertEquals(IdentityProtectionStatus.CORRUPT_OR_MISSING, nextAttempt)
        assertFalse(IdentityPersistencePolicy.shouldPersistSnapshot(nextAttempt))
        assertEquals(
            nextAttempt,
            IdentityPersistencePolicy.statusForNextRecordResolution(
                current = nextAttempt,
                recordPresent = false,
                quarantineCompleted = true,
            ),
        )
        assertEquals(
            nextAttempt,
            IdentityPersistencePolicy.statusForNextRecordResolution(
                current = nextAttempt,
                recordPresent = true,
                quarantineCompleted = true,
            ),
        )
    }

    @Test
    fun `each damaged record recovers independently after its own quarantine`() {
        IdentityRecord.values().forEach {
            val observed = IdentityPersistencePolicy.statusAfterRecordQuarantine(clearSucceeded = true)
            assertEquals(IdentityProtectionLevel.CORRUPT_OR_MISSING, observed.level)
            assertEquals(
                IdentityProtectionStatus.READY,
                IdentityPersistencePolicy.statusAfterSuccessfulRecovery(observed),
            )
            assertEquals(
                observed,
                IdentityPersistencePolicy.statusForNextRecordResolution(
                    current = observed,
                    recordPresent = true,
                    quarantineCompleted = true,
                ),
            )
        }
    }

    @Test
    fun `successful protected rewrite clears a recoverable degradation on next resolution`() {
        assertEquals(
            IdentityProtectionStatus.READY,
            IdentityPersistencePolicy.statusAfterSuccessfulRecovery(
                IdentityProtectionStatus.CORRUPT_OR_MISSING,
            ),
        )
        assertEquals(
            IdentityProtectionStatus.READY,
            IdentityPersistencePolicy.statusAfterSuccessfulRecovery(
                IdentityProtectionStatus.KEYSTORE_UNAVAILABLE,
            ),
        )
        assertEquals(
            IdentityProtectionStatus.API_BELOW_23,
            IdentityPersistencePolicy.statusAfterSuccessfulRecovery(
                IdentityProtectionStatus.API_BELOW_23,
            ),
        )
    }

    @Test
    fun `field registry has required privacy columns and no hardware identity`() {
        val fields = IdentityFieldRegistryV1.fields

        assertTrue(fields.size >= 10)
        fields.forEach { field ->
            assertEquals(IdentityFieldRegistryV1.API_RANGE, field.apiRange)
            assertTrue(field.source.isNotBlank())
            assertTrue(field.permission.isNotBlank())
            assertTrue(field.purpose.isNotBlank())
            assertTrue(field.stability.isNotBlank())
            assertTrue(field.distinctiveness.isNotBlank())
            assertTrue(field.spoofability.isNotBlank())
            assertTrue(field.privacyLevel.isNotBlank())
            assertTrue(field.protection.isNotBlank())
            assertTrue(field.retention.isNotBlank())
            assertTrue(field.missingStrategy.isNotBlank())
        }
        val names = fields.map { it.name }.toSet()
        assertTrue("install_id" in names)
        assertTrue("session_id" in names)
        assertFalse(names.any { it.contains("imei") || it.contains("serial") || it.contains("mac") })
    }

    companion object {
        private val LOCAL_UUID = Regex(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        )
        private val SESSION_ID = Regex("^S[0-9a-f]{32}$")
    }
}
