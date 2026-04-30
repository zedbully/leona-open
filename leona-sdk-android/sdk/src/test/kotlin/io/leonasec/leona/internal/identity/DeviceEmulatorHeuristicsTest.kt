/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceEmulatorHeuristicsTest {

    @Test
    fun `generic gsi-like build is not enough for emulator evidence`() {
        assertFalse(
            DeviceEmulatorHeuristics.isEmulatorLikely(
                fingerprint = "generic/aosp_arm64/gsi_arm64:15/AP3A/userdebug/test-keys",
                model = "AOSP on ARM64",
                manufacturer = "Google",
                hardware = "qcom",
                product = "aosp_arm64",
                device = "generic_arm64",
                board = "kalama",
                hasKnownRuntimeEvidence = false,
            ),
        )
    }

    @Test
    fun `known emulator runtime evidence still marks emulator`() {
        assertTrue(
            DeviceEmulatorHeuristics.isEmulatorLikely(
                fingerprint = "generic/aosp_arm64/gsi_arm64:15/AP3A/userdebug/test-keys",
                model = "AOSP on ARM64",
                manufacturer = "Google",
                hardware = "qcom",
                product = "aosp_arm64",
                device = "generic_arm64",
                board = "kalama",
                hasKnownRuntimeEvidence = true,
            ),
        )
    }

    @Test
    fun `custom product containing sdk substring is not enough for emulator evidence`() {
        assertFalse(
            DeviceEmulatorHeuristics.isEmulatorLikely(
                fingerprint = "vendor/customsdkdevice/customsdkdevice:15/AP3A/user/release-keys",
                model = "Custom SDK Device",
                manufacturer = "Example",
                hardware = "qcom",
                product = "customsdkdevice",
                device = "customsdkdevice",
                board = "kalama",
                hasKnownRuntimeEvidence = false,
            ),
        )
    }

    @Test
    fun `android studio emulator remains emulator`() {
        assertTrue(
            DeviceEmulatorHeuristics.isEmulatorLikely(
                fingerprint = "google/sdk_gphone64_arm64/emu64a:14/UE1A/dev-keys",
                model = "sdk_gphone64_arm64",
                manufacturer = "Google",
                hardware = "ranchu",
                product = "sdk_gphone64_arm64",
                device = "emu64a",
                board = "goldfish_arm64",
                hasKnownRuntimeEvidence = false,
            ),
        )
    }
}
