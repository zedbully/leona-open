/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudConfigManagerTest {

    @Test
    fun `cloud config trust only accepts https endpoints`() {
        assertTrue(CloudConfigManager.isTrustedCloudConfigEndpoint("https://cfg.example.test/v1/mobile-config"))
        assertTrue(CloudConfigManager.isTrustedCloudConfigEndpoint(" HTTPS://cfg.example.test/v1/mobile-config "))
        assertFalse(CloudConfigManager.isTrustedCloudConfigEndpoint("http://cfg.example.test/v1/mobile-config"))
        assertFalse(CloudConfigManager.isTrustedCloudConfigEndpoint("http://10.0.2.2:8090/v1/mobile-config"))
        assertFalse(CloudConfigManager.isTrustedCloudConfigEndpoint(null))
        assertFalse(CloudConfigManager.isTrustedCloudConfigEndpoint(""))
    }

    @Test
    fun `cached cloud config must be bound to the trusted endpoint that fetched it`() {
        val endpoint = "https://cfg.example.test/v1/mobile-config"

        assertTrue(CloudConfigManager.isTrustedCachedCloudConfig(endpoint, endpoint))
        assertFalse(CloudConfigManager.isTrustedCachedCloudConfig(endpoint, null))
        assertFalse(CloudConfigManager.isTrustedCachedCloudConfig(endpoint, "http://cfg.example.test/v1/mobile-config"))
        assertFalse(CloudConfigManager.isTrustedCachedCloudConfig(endpoint, "https://other.example.test/v1/mobile-config"))
        assertFalse(CloudConfigManager.isTrustedCachedCloudConfig("http://cfg.example.test/v1/mobile-config", endpoint))
    }

    @Test
    fun `body parser accepts nested policy overrides and ignores identity fields`() {
        val remote = CloudConfigManager.parseRemoteConfigBody(
            """
            {
              "canonicalDeviceId": "Lignored-root",
              "config": {
                "disabledSignals": ["androidId"],
                "disableCollectionWindowMs": 1500
              },
              "policy": {
                "disabledCollectors": ["risk.emulator"]
              },
              "device": {
                "canonicalDeviceId": "Ldevice-body"
              },
              "deviceIdentity": {
                "resolvedDeviceId": "Ldevice-identity"
              }
            }
            """.trimIndent(),
        )

        assertEquals(1500L, remote.disableCollectionWindowMs)
        assertEquals(setOf("androidId", "risk.emulator"), remote.disabledSignals)
    }

    @Test
    fun `untrusted remote config cannot alter policy`() {
        val remote = CloudConfigManager.parseRemoteConfigBody(
            """
            {
              "disabledSignals": ["androidId", "risk.emulator"],
              "disableCollectionWindowMs": 5000,
              "canonicalDeviceId": "Luntrusted"
            }
            """.trimIndent(),
        )

        val trusted = remote.onlyIfTrusted(true)
        val untrusted = remote.onlyIfTrusted(false)

        assertEquals(5000L, trusted.disableCollectionWindowMs)
        assertEquals(setOf("androidId", "risk.emulator"), trusted.disabledSignals)
        assertEquals(-1L, untrusted.disableCollectionWindowMs)
        assertTrue(untrusted.disabledSignals.isEmpty())
    }

    @Test
    fun `headers override scalar fields and merge disabled signals`() {
        val body = CloudConfigManager.parseRemoteConfigBody(
            """
            {
              "disabledSignals": ["androidId"],
              "disableCollectionWindowMs": 1000
            }
            """.trimIndent(),
        )
        val headers = CloudConfigManager.parseRemoteConfigHeaders(
            mapOf(
                "X-Leona-Disabled-Signals" to "risk.emulator, root.basic",
                "X-Leona-Disable-Collection-Window-Ms" to "5000",
                "X-Leona-Canonical-Device-Id" to "Lignored-header",
            ),
        )

        val merged = body.merge(headers)

        assertEquals(5000L, merged.disableCollectionWindowMs)
        assertTrue(merged.disabledSignals.containsAll(setOf("androidId", "risk.emulator", "root.basic")))
    }
}
