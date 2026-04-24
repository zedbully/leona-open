/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.Context
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.mockito.Mockito.mock

class ReflectivePlayIntegrityBridgeTest {

    @Test
    fun `createIfAvailable matches sdk availability`() {
        val context = mock(Context::class.java)

        val bridge = ReflectivePlayIntegrityBridge.createIfAvailable(
            context = context,
            cloudProjectNumber = 123456789L,
        )

        if (isPlayIntegritySdkPresent()) {
            assertNotNull(bridge)
        } else {
            assertNull(bridge)
        }
    }

    private fun isPlayIntegritySdkPresent(): Boolean = runCatching {
        Class.forName("com.google.android.play.core.integrity.IntegrityManagerFactory")
    }.isSuccess
}
