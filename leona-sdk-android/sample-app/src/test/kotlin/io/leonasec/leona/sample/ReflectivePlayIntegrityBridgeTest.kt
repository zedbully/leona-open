/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.Context
import org.junit.Assert.assertNull
import org.junit.Test
import org.mockito.Mockito.mock

class ReflectivePlayIntegrityBridgeTest {

    @Test
    fun `createIfAvailable returns null when play integrity sdk is absent`() {
        val context = mock(Context::class.java)

        val bridge = ReflectivePlayIntegrityBridge.createIfAvailable(
            context = context,
            cloudProjectNumber = 123456789L,
        )

        assertNull(bridge)
    }
}
