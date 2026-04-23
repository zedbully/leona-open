/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BoxIdTest {

    @Test
    fun `toString returns the opaque value`() {
        val id = BoxId.of("abc123")
        assertEquals("abc123", id.toString())
    }

    @Test
    fun `equality is value-based`() {
        val a = BoxId.of("token-42")
        val b = BoxId.of("token-42")
        val c = BoxId.of("token-other")

        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
        assertNotEquals(a, c)
    }

    @Test
    fun `equals handles non-BoxId comparand`() {
        val id = BoxId.of("x")
        assertFalse(id.equals("x"))
        assertFalse(id.equals(null))
    }

    @Test
    fun `empty value is allowed — server decides validity`() {
        val id = BoxId.of("")
        assertEquals("", id.toString())
        assertTrue(id == BoxId.of(""))
    }
}
