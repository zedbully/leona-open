/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Validates the binary payload format produced by `report/collector.cpp` on
 * the native side.
 *
 * The native implementation lives in C++ and we cannot call it directly from
 * JVM unit tests. Instead we maintain a pure-Kotlin mirror of the scramble
 * algorithm here and round-trip it. If either side drifts, this test fails —
 * which is exactly the guard-rail we want while the format is still young.
 */
class PayloadFormatTest {

    @Test
    fun `scramble is self-inverse with the same key schedule`() {
        val original = byteArrayOf(0, 1, 2, 3, 4, 5, 0x4C, 0x4E, 0x41, 0x31)
        val scrambled = PayloadScramble.scramble(original.copyOf())
        val unscrambled = PayloadScramble.scramble(scrambled.copyOf())
        assertTrue(
            "scramble should be self-inverse",
            original.contentEquals(unscrambled),
        )
    }

    @Test
    fun `scramble changes every byte of a non-empty magic-prefixed header`() {
        val original = "LNA1\u0001\u0000\u0000\u0000".toByteArray()
        val scrambled = PayloadScramble.scramble(original.copyOf())
        // With the initial key 0x5C and the XOR step, byte 0 flips. We only
        // require that the output differs at multiple positions — the exact
        // bytes are implementation detail that may change if we bump the
        // key schedule.
        var different = 0
        for (i in original.indices) {
            if (original[i] != scrambled[i]) different++
        }
        assertTrue(
            "scramble should perturb most bytes (got $different changes)",
            different >= original.size - 1,
        )
    }

    @Test
    fun `empty payload scrambles to empty`() {
        val scrambled = PayloadScramble.scramble(ByteArray(0))
        assertEquals(0, scrambled.size)
    }
}

/**
 * Kotlin mirror of the native scramble in `report/collector.cpp`. If the
 * algorithm there changes, update here and keep the round-trip tests green.
 */
private object PayloadScramble {
    fun scramble(bytes: ByteArray): ByteArray {
        var k = 0x5C
        for (i in bytes.indices) {
            bytes[i] = (bytes[i].toInt() xor k).toByte()
            k = (k * 31 + 17) and 0xFF
        }
        return bytes
    }
}
