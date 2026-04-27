/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Test

class AppIntegrityDexSectionTest {

    @Test
    fun `dex section hashes include variable sized code items`() {
        val dex = ByteArray(0x140) { index -> (index and 0xFF).toByte() }
        dex[0] = 'd'.code.toByte()
        dex[1] = 'e'.code.toByte()
        dex[2] = 'x'.code.toByte()

        val buffer = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(0x20, dex.size)
        buffer.putInt(0x34, 0x100)
        buffer.putInt(0x100, 4)
        putMapItem(buffer, 0x104, 0x0000, 1, 0x000)
        putMapItem(buffer, 0x110, 0x0006, 1, 0x070)
        putMapItem(buffer, 0x11C, 0x2001, 1, 0x090)
        putMapItem(buffer, 0x128, 0x2002, 1, 0x0B0)

        val hashes = parseDexSectionHashes(dex, setOf("class_defs", "code_item"))

        assertEquals(sha256(dex.copyOfRange(0x070, 0x090)), hashes["class_defs"])
        assertEquals(sha256(dex.copyOfRange(0x090, 0x0B0)), hashes["code_item"])
    }

    private fun putMapItem(buffer: ByteBuffer, offset: Int, type: Int, size: Int, sectionOffset: Int) {
        buffer.putShort(offset, type.toShort())
        buffer.putShort(offset + 2, 0)
        buffer.putInt(offset + 4, size)
        buffer.putInt(offset + 8, sectionOffset)
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseDexSectionHashes(dexBytes: ByteArray, requestedSections: Set<String>): Map<String, String> {
        val method = AppIntegrity::class.java.getDeclaredMethod(
            "parseDexSectionHashes",
            ByteArray::class.java,
            Set::class.java,
        )
        method.isAccessible = true
        return method.invoke(AppIntegrity, dexBytes, requestedSections) as Map<String, String>
    }

    private fun sha256(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}
