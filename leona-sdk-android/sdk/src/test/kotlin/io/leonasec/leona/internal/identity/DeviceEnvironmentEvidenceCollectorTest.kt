/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceEnvironmentEvidenceCollectorTest {

    @Test
    fun `test and dev keys become neutral build evidence`() {
        val evidence = DeviceEnvironmentEvidenceCollector.summarize(
            DeviceEnvironmentEvidenceCollector.BuildProfile(
                tags = "release-keys,test-keys dev-keys",
                type = "userdebug",
                fingerprint = "lineage/device/userdebug/15/AP3A/test-keys",
                verifiedBootState = "orange",
                vbmetaDeviceState = "unlocked",
                flashLocked = "0",
            ),
        )

        assertTrue("expected test-keys evidence", "build.tags.test_keys" in evidence.evidenceIds)
        assertTrue("expected dev-keys evidence", "build.tags.dev_keys" in evidence.evidenceIds)
        assertTrue("expected userdebug evidence", "build.type.userdebug_or_eng" in evidence.evidenceIds)
        assertTrue("expected verified boot evidence", "verified_boot.orange" in evidence.evidenceIds)
        assertTrue("expected bootloader evidence", "bootloader.unlocked" in evidence.evidenceIds)
        assertTrue("expected ROM evidence", "rom.custom_aosp_like" in evidence.evidenceIds)
        assertEquals("test-keys/dev-keys must not be root evidence", false, evidence.evidenceIds.any { it == "root.basic" })
    }

    @Test
    fun `gsi and custom rom identifiers are grouped separately`() {
        val evidence = DeviceEnvironmentEvidenceCollector.summarize(
            DeviceEnvironmentEvidenceCollector.BuildProfile(
                tags = "release-keys",
                type = "user",
                fingerprint = "google/panther/panther:15/AP3A/release-keys",
                display = "crDroid-11.0",
                gsiImageRunning = "true",
                systemProductName = "aosp_arm64",
            ),
        )

        assertTrue("expected gsi evidence", "gsi.running" in evidence.evidenceIds)
        assertTrue("expected crDroid evidence", "rom.crdroid_like" in evidence.evidenceIds)
        assertTrue("expected ROM rollup evidence", "rom.custom_aosp_like" in evidence.evidenceIds)
        assertEquals("true", evidence.gsi["imageRunning"])
    }
}
