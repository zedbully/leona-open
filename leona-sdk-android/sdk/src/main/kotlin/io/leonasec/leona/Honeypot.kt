/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import android.util.Base64
import io.leonasec.leona.internal.NativeBridge
import java.nio.charset.StandardCharsets

/**
 * Primitives for returning deceptive data instead of real data.
 *
 * ## Golden rule
 *
 * **Your code must NEVER decide client-side whether to serve a honeypot.**
 * That's a patch target. Honeypot primitives are only ever invoked in
 * response to a backend instruction:
 *
 * ```
 * val response = yourBackend.getUserProfile(…, leonaBoxId = boxId.toString())
 * if (response.leonaBackendFlags.honeypotRequested) {
 *     // Backend has classified this session as hostile; return fake data.
 *     showProfile(Honeypot.fakeUser())
 * } else {
 *     showProfile(response.user)
 * }
 * ```
 *
 * The backend decides. The SDK only provides believable garbage.
 *
 * ## What makes a good honeypot?
 *
 *  - Looks like real data at every level: format, length, charset, prefixes.
 *  - Self-consistent: an attacker re-running the same request must see
 *    stable values (so they think "this is a valid record"), not a new
 *    randomized payload each time.
 *  - Marked server-side: the server remembers it emitted honeypot data and
 *    escalates if the "user" submits any transaction using that data.
 */
object Honeypot {

    /**
     * A believable-looking AES-256 key. 32 bytes of deterministic-random
     * data derived from an internal seed — not cryptographically secure,
     * and that's the point. Intended to be returned to a hostile client
     * in place of a real key so any attempt to use it for traffic
     * decryption fails obviously on the server.
     */
    @JvmStatic
    fun fakeAesKey256(): ByteArray = NativeBridge.honeypotFakeKey(32)

    /**
     * A believable-looking AES-128 key. 16 bytes.
     */
    @JvmStatic
    fun fakeAesKey128(): ByteArray = NativeBridge.honeypotFakeKey(16)

    /**
     * A plausible-looking token string (48-char URL-safe base64).
     *
     * @param salt optional per-session value to vary the token; pass the
     *             BoxId string if you want the same hostile session to see
     *             the same fake token across retries.
     */
    @JvmStatic
    @JvmOverloads
    fun fakeSessionToken(salt: String = ""): String {
        val bytes = NativeBridge.honeypotFakeToken(
            salt.toByteArray(StandardCharsets.UTF_8),
            tokenLengthBytes = 36,
        )
        return bytes.toBase64UrlNoPadding()
    }

    /**
     * A plausible-looking email address for placeholder account data.
     * Domain is always `leonasec-canary.example` — any email server that
     * sees this domain knows it was emitted by a Leona honeypot.
     */
    @JvmStatic
    fun fakeEmail(): String {
        val localBytes = NativeBridge.honeypotFakeToken(ByteArray(0), tokenLengthBytes = 8)
        val local = localBytes.toBase64UrlNoPadding().lowercase()
        return "$local@leonasec-canary.example"
    }

    /**
     * A fake user record as a lightweight data class. Suitable for
     * replacing a real account lookup when the backend asks for a decoy.
     */
    @JvmStatic
    fun fakeUser(): FakeUser {
        return FakeUser(
            id = fakeSessionToken(salt = "user-id").take(16),
            email = fakeEmail(),
            displayName = "Guest ${NativeBridge.honeypotFakeToken(ByteArray(0), 2).toHexShort()}",
        )
    }

    /**
     * Small value type for fake user records. Deliberately not opinionated
     * about domain-specific fields — integrators know their own schema.
     */
    data class FakeUser(
        val id: String,
        val email: String,
        val displayName: String,
    )
}

private fun ByteArray.toHexShort(): String =
    joinToString("") { "%02x".format(it.toInt() and 0xFF) }.uppercase().take(4)

private fun ByteArray.toBase64UrlNoPadding(): String =
    Base64.encodeToString(this, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
