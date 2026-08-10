package io.leonasec.leona.sample

import android.content.Context
import io.leonasec.leona.config.AttestationException
import io.leonasec.leona.config.AttestationProvider
import io.leonasec.leona.config.AttestationStatement
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import org.mockito.Mockito.mock

class SampleHuaweiSysIntegrityTest {
    private val context = mock(Context::class.java)

    @Test
    fun `non-Huawei mode leaves provider selection unchanged`() {
        assertNull(
            SampleHuaweiSysIntegrity.createProvider(
                context = context,
                mode = "off",
                appId = "123456",
            ),
        )
    }

    @Test
    fun `explicit Huawei mode fails closed when app id is missing`() = runTest {
        val provider = SampleHuaweiSysIntegrity.createProvider(
            context = context,
            mode = SampleHuaweiSysIntegrity.MODE,
            appId = "",
        )
        assertProviderFailure(provider)
    }

    @Test
    fun `explicit Huawei mode fails closed when private provider is absent`() = runTest {
        val provider = SampleHuaweiSysIntegrity.createProvider(
            context = context,
            mode = SampleHuaweiSysIntegrity.MODE,
            appId = "123456",
            providerClassName = "io.leonasec.missing.HuaweiProvider",
        )
        assertProviderFailure(provider)
    }

    @Test
    fun `reflection seam returns an opaque evidence provider`() = runTest {
        val provider = SampleHuaweiSysIntegrity.createProvider(
            context = context,
            mode = " HUAWEI_SYSINTEGRITY ",
            appId = "123456",
            providerClassName = FakeHuaweiProvider::class.java.name,
        )
        assertNotNull(provider)
        assertEquals(
            AttestationStatement("oem_attestation", "header.payload.signature"),
            provider!!.attest("challenge", "install"),
        )
    }

    private suspend fun assertProviderFailure(provider: AttestationProvider?) {
        assertNotNull(provider)
        try {
            provider!!.attest("challenge", "install")
            fail("explicit Huawei mode must fail closed")
        } catch (error: AttestationException) {
            assertEquals("oem_attestation", error.provider)
            assertEquals(false, error.retryable)
        }
    }
}

class FakeHuaweiProvider(
    @Suppress("UNUSED_PARAMETER") context: Context,
    @Suppress("UNUSED_PARAMETER") appId: String,
) : AttestationProvider {
    override suspend fun attest(challenge: String, installId: String): AttestationStatement =
        AttestationStatement("oem_attestation", "header.payload.signature")
}
