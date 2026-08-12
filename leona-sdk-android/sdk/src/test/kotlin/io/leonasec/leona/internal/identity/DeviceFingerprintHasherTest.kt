/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DeviceFingerprintHasherTest {

    @Test
    fun `real device v2 fixture stays stable when volatile app data is unchanged`() {
        val first = pixelFixtureFingerprint(appScopedAndroidId = "android-real-1")
        val second = pixelFixtureFingerprint(appScopedAndroidId = "android-real-1")

        assertEquals(first, second)
        assertTrue(first.matches(Regex("[0-9a-f]{64}")))
        assertEquals(2, DeviceFingerprintHasher.BASE_SEED_VERSION)
        assertEquals("base_device_v2", DeviceFingerprintHasher.FINGERPRINT_SOURCE_BASE_V2)
    }

    @Test
    fun `virtual instance anchors are hashed and affect fingerprint`() {
        val firstAnchor = DeviceFingerprintHasher.hashVirtualInstanceAnchors(
            mapOf("prop.nemud.player_uuid" to "vm-instance-a"),
        )!!
        val secondAnchor = DeviceFingerprintHasher.hashVirtualInstanceAnchors(
            mapOf("prop.nemud.player_uuid" to "vm-instance-b"),
        )!!
        val firstClone = mumuFixtureFingerprint(
            appScopedAndroidId = "android-cloned",
            virtualInstanceAnchorHash = firstAnchor,
        )
        val secondClone = mumuFixtureFingerprint(
            appScopedAndroidId = "android-cloned",
            virtualInstanceAnchorHash = secondAnchor,
        )

        assertTrue(firstAnchor.matches(Regex("[0-9a-f]{64}")))
        assertTrue(secondAnchor.matches(Regex("[0-9a-f]{64}")))
        assertNotEquals(firstAnchor, secondAnchor)
        assertNotEquals(firstClone, secondClone)
        assertEquals(4, DeviceFingerprintHasher.VIRTUAL_ANCHOR_SEED_VERSION)
        assertEquals("virtual_instance_anchor_v4", DeviceFingerprintHasher.FINGERPRINT_SOURCE_VIRTUAL_ANCHOR_V4)
    }

    @Test
    fun `virtual instance anchor keeps fingerprint stable when app scoped id changes`() {
        val virtualAnchor = DeviceFingerprintHasher.hashVirtualInstanceAnchors(
            mapOf("prop.nemud.player_uuid" to "vm-instance-a"),
        )!!

        assertEquals(
            mumuFixtureFingerprint(
                appScopedAndroidId = "first-install-android-id",
                virtualInstanceAnchorHash = virtualAnchor,
            ),
            mumuFixtureFingerprint(
                appScopedAndroidId = "second-install-android-id",
                virtualInstanceAnchorHash = virtualAnchor,
            ),
        )
        assertNotEquals(
            mumuFixtureFingerprint(appScopedAndroidId = "first-install-android-id"),
            mumuFixtureFingerprint(appScopedAndroidId = "second-install-android-id"),
        )
    }

    @Test
    fun `stable virtual property anchor ignores reboot network rotation`() {
        val beforeReboot = DeviceFingerprintHasher.selectVirtualInstanceAnchors(
            properties = mapOf("prop.ro.boot.qemu.avd_name" to "leona-aosp-api25"),
        )
        val afterReboot = DeviceFingerprintHasher.selectVirtualInstanceAnchors(
            properties = mapOf("prop.ro.boot.qemu.avd_name" to "leona-aosp-api25"),
        )

        assertEquals(beforeReboot, afterReboot)
        assertEquals(mapOf("prop.ro.boot.qemu.avd_name" to "leona-aosp-api25"), beforeReboot)
    }

    @Test
    fun `network anchor is never promoted when stable properties are unavailable`() {
        assertEquals(
            emptyMap<String, String>(),
            DeviceFingerprintHasher.selectVirtualInstanceAnchors(
                properties = emptyMap(),
            ),
        )
    }

    @Test
    fun `stable virtual profile anchor remains distinct from rotating network metadata`() {
        val profile = mapOf(
            "profile.device" to "leona_api25",
            "profile.product" to "leona_api25",
            "profile.hardware" to "ranchu",
        )

        assertEquals(
            profile,
            DeviceFingerprintHasher.selectVirtualInstanceAnchors(
                properties = profile,
            ),
        )
    }

    @Test
    fun `app scoped android id distinguishes virtual instances from the same image`() {
        val first = DeviceFingerprintHasher.selectVirtualInstanceAnchors(
            properties = mapOf(
                "identity.android_id" to "virtual-instance-a",
                "profile.device" to "generic_arm64",
                "profile.product" to "sdk_phone_arm64",
                "profile.hardware" to "ranchu",
            ),
        )
        val second = DeviceFingerprintHasher.selectVirtualInstanceAnchors(
            properties = mapOf(
                "identity.android_id" to "virtual-instance-b",
                "profile.device" to "generic_arm64",
                "profile.product" to "sdk_phone_arm64",
                "profile.hardware" to "ranchu",
            ),
        )

        assertNotEquals(
            DeviceFingerprintHasher.hashVirtualInstanceAnchors(first),
            DeviceFingerprintHasher.hashVirtualInstanceAnchors(second),
        )
    }

    @Test
    fun `virtual instance anchor hashing ignores placeholders`() {
        assertNull(
            DeviceFingerprintHasher.hashVirtualInstanceAnchors(
                mapOf(
                    "prop.ro.serialno" to "unknown",
                    "net.eth0" to "02:00:00:00:00:00",
                    "prop.nemud.player_uuid" to "<redacted>",
                    "identity.android_id" to "9774d56d682e549c",
                ),
            ),
        )
    }

    @Test
    fun `fingerprint versions keep real devices stable while virtual anchors opt in`() {
        assertEquals(2, DeviceFingerprintHasher.BASE_SEED_VERSION)
        assertEquals(4, DeviceFingerprintHasher.VIRTUAL_ANCHOR_SEED_VERSION)
        assertEquals(4, DeviceFingerprintHasher.CACHE_SCHEMA_VERSION)
    }

    private fun pixelFixtureFingerprint(appScopedAndroidId: String): String =
        DeviceFingerprintHasher.fixtureFingerprintHash(
            appScopedAndroidId = appScopedAndroidId,
            buildFingerprint = "google/panther/panther:14/AP1A.240505.005/1234567:user/release-keys",
            device = "panther",
            product = "panther",
            hardware = "panther",
            brand = "google",
            model = "Pixel 7",
            manufacturer = "Google",
            sdkInt = 34,
            abis = listOf("arm64-v8a"),
        )

    private fun mumuFixtureFingerprint(
        appScopedAndroidId: String,
        virtualInstanceAnchorHash: String? = null,
    ): String =
        DeviceFingerprintHasher.fixtureFingerprintHash(
            appScopedAndroidId = appScopedAndroidId,
            buildFingerprint = "Netease/mumu/mumu:12/SQ3A.220705.004/20260507:user/release-keys",
            device = "mumu",
            product = "mumu",
            hardware = "nemu",
            brand = "Netease",
            model = "MuMu",
            manufacturer = "Netease",
            sdkInt = 32,
            abis = listOf("arm64-v8a", "armeabi-v7a"),
            virtualInstanceAnchorHash = virtualInstanceAnchorHash,
        )
}
