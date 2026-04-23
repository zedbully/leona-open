/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

/**
 * Internal event type. Produced by native detectors, consumed by
 * [EventCollector] before encryption. **Not exposed to app code.**
 *
 * If this type ever leaks to the public API we've broken architectural
 * principle #A ("client-side zero decisions").
 */
internal data class Event(
    val id: String,
    val category: Category,
    val severity: Severity,
    val message: String,
    val evidence: Map<String, String> = emptyMap(),
)

internal enum class Category {
    INJECTION,
    ENVIRONMENT,
    EMULATOR_UNIDBG,
    TAMPERING,
    HONEYPOT_TRIPPED,
    NETWORK,
    OTHER,
}

internal enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }
