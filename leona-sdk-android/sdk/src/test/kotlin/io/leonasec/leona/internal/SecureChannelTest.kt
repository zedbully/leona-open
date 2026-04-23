/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import android.content.SharedPreferences
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.spi.SecureDeviceContext
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

class SecureChannelTest {

    @Test
    fun `upload returns a non-empty BoxId for alpha stub`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(ctx, LeonaConfig.Builder().build())

        val id = channel.upload(byteArrayOf(1, 2, 3, 4), deviceContext())
        assertNotNull(id)
        assertTrue(id.boxId.toString().isNotEmpty())
    }

    @Test
    fun `each upload returns a unique BoxId`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(ctx, LeonaConfig.Builder().build())

        val id1 = channel.upload(byteArrayOf(), deviceContext())
        val id2 = channel.upload(byteArrayOf(), deviceContext())
        assertNotEquals(id1, id2)
    }

    private fun deviceContext(): SecureDeviceContext = SecureDeviceContext(
        installId = "install-1",
        resolvedDeviceId = "Tdevice-1",
        fingerprintHash = "fingerprint-1",
    )

    private fun mockContext(): Context {
        val ctx = mock(Context::class.java)
        val prefs = mock(SharedPreferences::class.java)
        val editor = mock(SharedPreferences.Editor::class.java)
        `when`(ctx.getSharedPreferences("io.leonasec.leona.session", Context.MODE_PRIVATE))
            .thenReturn(prefs)
        `when`(prefs.edit()).thenReturn(editor)
        `when`(editor.putString(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
            .thenReturn(editor)
        `when`(editor.remove(org.mockito.ArgumentMatchers.anyString())).thenReturn(editor)
        return ctx
    }
}
