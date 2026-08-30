package io.leonasec.leona.crypto.leofacade

import io.leonasec.leona.crypto.LeonaCryptoErrorCode
import io.leonasec.leona.crypto.LeonaCryptoAssertionProvider
import io.leonasec.leona.crypto.LeonaCryptoScopeProvider
import io.leonasec.leona.crypto.LeonaCryptoPreparedAssertion
import io.leonasec.leona.crypto.LeonaCryptoRequestContext
import io.leonasec.leona.crypto.LeonaCryptoScopeCommitments
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LeoFacadeCryptoCompatibilityTest {
    @Test
    fun `only the pinned external facade major is accepted`() {
        assertTrue(LeoFacadeCryptoCompatibility.isSupportedProviderVersion("13.0.0"))
        assertTrue(LeoFacadeCryptoCompatibility.isSupportedProviderVersion("13.9.0+customer"))
        assertEquals(false, LeoFacadeCryptoCompatibility.isSupportedProviderVersion("12.9.0"))
        assertEquals(false, LeoFacadeCryptoCompatibility.isSupportedProviderVersion("14.0.0"))
        assertEquals(false, LeoFacadeCryptoCompatibility.isSupportedProviderVersion("unknown"))
    }

    @Test
    fun `missing configuration fails before loading native provider`() {
        val result = LeoFacadeCryptoTransportFactory.create(
            nativeConfiguration = ByteArray(0),
            bootstrap = byteArrayOf(1),
            providerVersion = "13.0.0",
            assertions = neverAssertion,
            scopes = neverScopes,
        )
        assertEquals(LeonaCryptoErrorCode.INVALID_INPUT, (result as io.leonasec.leona.crypto.LeonaCryptoResult.Failure).code)
    }
}

private fun <T> error(message: String): T = kotlin.error(message)

private val neverAssertion = object : LeonaCryptoAssertionProvider {
    override fun prepare(request: LeonaCryptoRequestContext): LeonaCryptoPreparedAssertion =
        error("assertion provider must not be called")

    override fun issue(
        request: LeonaCryptoRequestContext,
        prepared: LeonaCryptoPreparedAssertion,
        contextDigest: ByteArray,
    ): ByteArray = error("assertion provider must not be called")
}

private val neverScopes = LeonaCryptoScopeProvider {
    error("scope provider must not be called")
}
