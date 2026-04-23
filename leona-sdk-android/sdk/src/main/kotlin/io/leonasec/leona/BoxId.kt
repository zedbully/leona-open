/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

/**
 * An opaque token returned by [Leona.sense].
 *
 * The client holds a BoxId but cannot inspect its contents. Only Leona's
 * backend can map a BoxId to the real device identifier and detection
 * verdict. Your app forwards BoxId strings to your own backend; your backend
 * exchanges them with Leona server-side.
 *
 * **Do not parse, split, or interpret BoxId values client-side** — the format
 * is not part of the public contract and will change.
 */
class BoxId internal constructor(private val value: String) {

    /** The opaque string to forward to your backend. Treat as a bearer token. */
    override fun toString(): String = value

    override fun equals(other: Any?): Boolean = other is BoxId && other.value == value

    override fun hashCode(): Int = value.hashCode()

    internal companion object {
        fun of(value: String): BoxId = BoxId(value)
    }
}
