/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.spi

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class SecureReportingErrorClassifierTest {
    @Test
    fun `HTTP detail exposes only bounded metadata`() {
        val secret = "server-token=do-not-log"
        val detail = SecureReportingErrorClassifier.httpFailureDetail(secret)

        assertNotNull(detail)
        assertTrue(detail!!.contains("responseBodyBytes="))
        assertTrue(detail.contains("responseBodySha256="))
        assertFalse(detail.contains(secret))
        assertFalse(detail.contains("do-not-log"))
    }

    @Test
    fun `unknown network cause does not expose message`() {
        val secret = "https://example.invalid/?token=do-not-log"
        val exception = SecureReportingErrorClassifier.exception(
            operation = "sense()",
            classification = SecureReportingErrorClassification(SecureReportingErrorCode.UNKNOWN),
            cause = IOException(secret),
        )

        assertEquals(SecureReportingErrorCode.UNKNOWN, exception.code)
        assertFalse(exception.message.orEmpty().contains(secret))
        assertFalse(exception.message.orEmpty().contains("do-not-log"))
        assertTrue(exception.message.orEmpty().contains("messageSha256="))
    }
}
