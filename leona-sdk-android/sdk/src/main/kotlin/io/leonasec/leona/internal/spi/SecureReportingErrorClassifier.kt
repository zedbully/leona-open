/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.spi

import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.security.MessageDigest

enum class SecureReportingErrorCode(val wireValue: String, val retryableByDefault: Boolean) {
    TIMESTAMP_SKEW("timestamp_skew", true),
    NETWORK_TIMEOUT("network_timeout", true),
    TLS_TRUST_ANCHOR("tls_trust_anchor", false),
    TLS_HANDSHAKE("tls_handshake", false),
    AUTH_FAILED("auth_failed", false),
    SERVER_5XX("server_5xx", true),
    TRANSPORT_DISABLED("transport_disabled", false),
    REPORTING_ENDPOINT_REQUIRED("reporting_endpoint_required", false),
    API_KEY_REQUIRED("api_key_required", false),
    SECURE_ENGINE_REQUIRED("secure_engine_required", false),
    PROTECTED_PAYLOAD_CARRIER_UNAVAILABLE("protected_payload_carrier_unavailable", false),
    UNKNOWN("unknown", false),
}

data class SecureReportingErrorClassification(
    val code: SecureReportingErrorCode,
    val httpStatus: Int? = null,
    val retryable: Boolean = code.retryableByDefault,
)

class SecureReportingException(
    val classification: SecureReportingErrorClassification,
    message: String,
    cause: Throwable? = null,
) : IOException(message, cause) {
    val code: SecureReportingErrorCode = classification.code
}

object SecureReportingErrorClassifier {
    fun httpFailureDetail(errorBody: String?): String? {
        val text = errorBody?.takeIf { it.isNotBlank() } ?: return null
        return "responseBodyBytes=${text.toByteArray(Charsets.UTF_8).size}, " +
            "responseBodySha256=${sha256Hex(text).take(16)}"
    }

    fun classifyHttpFailure(
        statusCode: Int,
        errorBody: String?,
        headers: Map<String, String> = emptyMap(),
    ): SecureReportingErrorClassification {
        val diagnosticText = buildString {
            append(errorBody.orEmpty())
            headers.forEach { (name, value) ->
                append('\n')
                append(name)
                append(':')
                append(value)
            }
        }
        val code = when {
            hasTimestampSkewMarker(diagnosticText) -> SecureReportingErrorCode.TIMESTAMP_SKEW
            statusCode == 401 || statusCode == 403 -> SecureReportingErrorCode.AUTH_FAILED
            statusCode in 500..599 -> SecureReportingErrorCode.SERVER_5XX
            else -> SecureReportingErrorCode.UNKNOWN
        }
        return SecureReportingErrorClassification(
            code = code,
            httpStatus = statusCode,
        )
    }

    fun classifyNetworkFailure(error: IOException): SecureReportingErrorClassification {
        val code = when (error) {
            is SocketTimeoutException -> SecureReportingErrorCode.NETWORK_TIMEOUT
            is InterruptedIOException -> SecureReportingErrorCode.NETWORK_TIMEOUT
            else -> classifyTlsFailure(error)
                ?: SecureReportingErrorCode.UNKNOWN
        }
        return SecureReportingErrorClassification(code = code)
    }

    private fun classifyTlsFailure(error: Throwable): SecureReportingErrorCode? {
        var current: Throwable? = error
        var handshakeSeen = false
        while (current != null) {
            val type = current.javaClass.name
            val message = current.message.orEmpty()
            if (
                "Trust anchor for certification path not found" in message ||
                "CertPathValidatorException" in type ||
                "SunCertPathBuilderException" in type
            ) {
                return SecureReportingErrorCode.TLS_TRUST_ANCHOR
            }
            if (type == "javax.net.ssl.SSLHandshakeException") {
                handshakeSeen = true
            }
            current = current.cause
        }
        return if (handshakeSeen) SecureReportingErrorCode.TLS_HANDSHAKE else null
    }

    fun exception(
        operation: String,
        classification: SecureReportingErrorClassification,
        detail: String? = null,
        cause: Throwable? = null,
    ): SecureReportingException {
        val message = buildString {
            append(operation)
            append(" failed: diagnostic=")
            append(classification.code.wireValue)
            classification.httpStatus?.let {
                append(", httpStatus=")
                append(it)
            }
            append(", retryable=")
            append(classification.retryable)
            detail
                ?.takeIf { it.isNotBlank() }
                ?.let {
                    append(", ")
                    append(it.take(512))
                }
                ?: cause
                    ?.takeIf { classification.code == SecureReportingErrorCode.UNKNOWN }
                    ?.let {
                        append(", cause=")
                        append(safeCauseSummary(it).take(256))
                    }
        }
        return SecureReportingException(classification, message, cause)
    }

    private fun safeCauseSummary(cause: Throwable): String {
        val type = cause.javaClass.name
        val message = cause.message?.takeIf { it.isNotBlank() }.orEmpty()
        return if (message.isBlank()) {
            type
        } else {
            "$type(messageBytes=${message.toByteArray(Charsets.UTF_8).size}, " +
                "messageSha256=${sha256Hex(message).take(16)})"
        }
    }

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun hasTimestampSkewMarker(text: String): Boolean {
        val normalized = text.lowercase()
        return "leona_timestamp_skew" in normalized ||
            "timestamp_skew" in normalized ||
            "request timestamp outside acceptable window" in normalized ||
            "outside acceptable window" in normalized ||
            "clock skew" in normalized
    }
}
