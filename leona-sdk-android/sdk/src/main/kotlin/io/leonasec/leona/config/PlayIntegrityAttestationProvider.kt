/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.config

/**
 * Canonical request handed to an app-provided Play Integrity bridge.
 *
 * The Leona SDK intentionally avoids a hard compile-time dependency on the
 * Google Play Integrity client library. Embedding apps can adapt this request
 * to StandardIntegrityManager / IntegrityManager themselves, then return the
 * raw JWS token string back to Leona.
 */
data class PlayIntegrityTokenRequest(
    val requestHash: String,
    val challenge: String,
    val installId: String,
    val cloudProjectNumber: Long? = null,
)

/**
 * Small bridge interface implemented by the embedding app.
 *
 * Typical integration:
 * 1. Build or reuse a StandardIntegrityManager.
 * 2. Request a token using [PlayIntegrityTokenRequest.requestHash].
 * 3. Return the raw token string.
 */
fun interface PlayIntegrityTokenProvider {
    suspend fun requestToken(request: PlayIntegrityTokenRequest): String?
}

/**
 * Play Integrity based [AttestationProvider] scaffold.
 *
 * This class standardizes Leona's attestation format and requestHash handling
 * while delegating the actual Google Play SDK call to [tokenProvider].
 */
class PlayIntegrityAttestationProvider(
    private val tokenProvider: PlayIntegrityTokenProvider,
    private val cloudProjectNumber: Long? = null,
) : AttestationProvider {

    override suspend fun attest(
        challenge: String,
        installId: String,
    ): AttestationStatement? {
        val token = tokenProvider.requestToken(
            PlayIntegrityTokenRequest(
                requestHash = challenge,
                challenge = challenge,
                installId = installId,
                cloudProjectNumber = cloudProjectNumber,
            ),
        )?.trim()?.takeIf { it.isNotEmpty() } ?: return null

        return AttestationStatements.playIntegrity(token)
    }
}
