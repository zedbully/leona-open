/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.config

/**
 * Canonical attestation format identifiers understood by Leona server.
 */
object AttestationFormats {
    const val PLAY_INTEGRITY = "play_integrity"
}

/**
 * Small helpers for creating standardized attestation statements.
 */
object AttestationStatements {
    @JvmStatic
    fun playIntegrity(token: String): AttestationStatement =
        AttestationStatement(AttestationFormats.PLAY_INTEGRITY, token)
}
