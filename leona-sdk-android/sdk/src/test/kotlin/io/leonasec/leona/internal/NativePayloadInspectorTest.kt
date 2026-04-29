/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class NativePayloadInspectorTest {

    @Test
    fun `inspect decodes native findings and maps stable risk tags`() {
        val payload = buildPayload(
            Event(
                id = "injection.frida.known_library",
                severity = 3,
                category = 1,
                message = "frida gadget",
                evidence = "path=/data/local/tmp/frida",
            ),
            Event(
                id = "tamper.signature.untrusted",
                severity = 4,
                category = 4,
                message = "signature mismatch",
                evidence = "actual=abc",
            ),
            Event(
                id = "unidbg.parent.non_zygote",
                severity = 3,
                category = 3,
                message = "java parent",
                evidence = "parent=java",
            ),
            Event(
                id = "env.emulator.fs.virtio_9p_shared_mount",
                severity = 3,
                category = 2,
                message = "virtio 9p shared mount",
                evidence = "path=/proc/mounts",
            ),
        )

        val summary = NativePayloadInspector.inspect(payload)

        assertEquals(4, summary.eventCount)
        assertEquals(4, summary.highestSeverity)
        assertEquals(
            listOf(
                "injection.frida.known_library",
                "tamper.signature.untrusted",
                "unidbg.parent.non_zygote",
                "env.emulator.fs.virtio_9p_shared_mount",
            ),
            summary.findingIds,
        )
        assertTrue("expected frida tag", "hook.frida.native" in summary.riskTags)
        assertTrue("expected tamper tag", "tamper.native" in summary.riskTags)
        assertTrue("expected signature tag", "signature.untrusted.native" in summary.riskTags)
        assertTrue("expected unidbg tag", "environment.unidbg.native" in summary.riskTags)
        assertTrue("expected emulator tag", "environment.emulator.native" in summary.riskTags)
    }

    @Test
    fun `inspect returns empty summary for malformed payload`() {
        val summary = NativePayloadInspector.inspect("not-a-leona-payload".toByteArray())
        assertEquals(0, summary.eventCount)
        assertTrue(summary.riskTags.isEmpty())
    }

    private data class Event(
        val id: String,
        val severity: Int,
        val category: Int,
        val message: String,
        val evidence: String,
    )

    private fun buildPayload(vararg events: Event): ByteArray {
        val raw = ArrayList<Byte>()
        raw += listOf('L'.code.toByte(), 'N'.code.toByte(), 'A'.code.toByte(), '1'.code.toByte())
        raw += 0x01.toByte()
        raw += 0x00.toByte()
        raw.writeU16(events.size)
        events.forEach { event ->
            raw.writeString(event.id)
            raw += event.severity.toByte()
            raw += event.category.toByte()
            raw.writeString(event.message)
            raw.writeString(event.evidence)
        }
        return scramble(raw.toByteArray())
    }

    private fun ArrayList<Byte>.writeU16(value: Int) {
        add((value and 0xFF).toByte())
        add(((value shr 8) and 0xFF).toByte())
    }

    private fun ArrayList<Byte>.writeString(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeU16(bytes.size)
        bytes.forEach(::add)
    }

    private fun scramble(bytes: ByteArray): ByteArray {
        var k = 0x5C
        for (i in bytes.indices) {
            bytes[i] = (bytes[i].toInt() xor k).toByte()
            k = (k * 31 + 17) and 0xFF
        }
        return bytes
    }
}
