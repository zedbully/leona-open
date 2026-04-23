/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CloudConfigManagerTest {

    @Test
    fun `body parser accepts nested canonical id and policy overrides`() {
        val remote = CloudConfigManager.parseRemoteConfigBody(
            """
            {
              "config": {
                "disabledSignals": ["androidId"],
                "disableCollectionWindowMs": 1500
              },
              "policy": {
                "disabledCollectors": ["risk.emulator"]
              },
              "device": {
                "canonicalDeviceId": "Ldevice-body"
              }
            }
            """.trimIndent(),
        )

        assertEquals("Ldevice-body", remote.canonicalDeviceId)
        assertEquals(1500L, remote.disableCollectionWindowMs)
        assertEquals(setOf("androidId", "risk.emulator"), remote.disabledSignals)
    }

    @Test
    fun `body parser falls back to deviceIdentity resolved device id`() {
        val remote = CloudConfigManager.parseRemoteConfigBody(
            """
            {
              "deviceIdentity": {
                "resolvedDeviceId": "Ldevice-identity"
              }
            }
            """.trimIndent(),
        )

        assertEquals("Ldevice-identity", remote.canonicalDeviceId)
    }

    @Test
    fun `headers override scalar fields and merge disabled signals`() {
        val body = CloudConfigManager.parseRemoteConfigBody(
            """
            {
              "disabledSignals": ["androidId"],
              "disableCollectionWindowMs": 1000,
              "canonicalDeviceId": "Ldevice-body"
            }
            """.trimIndent(),
        )
        val headers = CloudConfigManager.parseRemoteConfigHeaders(
            mapOf(
                "X-Leona-Disabled-Signals" to "risk.emulator, root.basic",
                "X-Leona-Disable-Collection-Window-Ms" to "5000",
                "X-Leona-Canonical-Device-Id" to "Ldevice-header",
            ),
        )

        val merged = body.merge(headers)

        assertEquals("Ldevice-header", merged.canonicalDeviceId)
        assertEquals(5000L, merged.disableCollectionWindowMs)
        assertTrue(merged.disabledSignals.containsAll(setOf("androidId", "risk.emulator", "root.basic")))
    }
}
