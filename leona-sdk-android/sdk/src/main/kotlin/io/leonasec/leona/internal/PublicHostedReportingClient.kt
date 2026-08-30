/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
@file:Suppress("DEPRECATION")

package io.leonasec.leona.internal

import io.leonasec.leona.BoxId
import io.leonasec.leona.LeonaServerVerdict
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.spi.SecureReportingErrorClassifier
import io.leonasec.leona.internal.spi.SecureDeviceContext
import io.leonasec.leona.internal.spi.SecureUploadResult
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.URI
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/**
 * Public-safe hosted upload path used when the closed-source secure reporting
 * engine is not on the runtime classpath. It sends only an opaque native
 * payload plus low-trust evidence metadata; hosted policy and final business
 * decisions remain server-side.
 */
internal class PublicHostedReportingClient(
    private val config: LeonaConfig,
    private val http: OkHttpClient = buildHttpClient(config),
) {
    fun upload(
        endpoint: String,
        apiKey: String,
        sdkVersion: String,
        payload: ByteArray,
        deviceContext: SecureDeviceContext,
    ): SecureUploadResult {
        val body = buildRequestBody(sdkVersion, payload, deviceContext)
        val request = Request.Builder()
            .url(publicSenseUrl(endpoint))
            .post(body.toString().toRequestBody(JSON_MEDIA_TYPE))
            .header("X-Leona-App-Key", apiKey)
            .header("X-Leona-SDK-Version", sdkVersion)
            .header("X-Leona-Reporting-Mode", REPORTING_MODE)
            .build()

        val response = try {
            http.newCall(request).execute()
        } catch (error: IOException) {
            val classification = SecureReportingErrorClassifier.classifyNetworkFailure(error)
            throw SecureReportingErrorClassifier.exception(
                operation = "public hosted reporting",
                classification = classification,
                cause = error,
            )
        }

        response.use {
            if (!response.isSuccessful) {
                val errorBody = response.body?.string()
                    ?.let { sanitizeErrorBody(it, apiKey) }
                    .orEmpty()
                val classification = SecureReportingErrorClassifier.classifyHttpFailure(
                    statusCode = response.code,
                    errorBody = errorBody,
                    headers = response.headers.toMultimap()
                        .mapValues { (_, values) -> values.joinToString(",") },
                )
                throw SecureReportingErrorClassifier.exception(
                    operation = "public hosted reporting",
                    classification = classification,
                    detail = SecureReportingErrorClassifier.httpFailureDetail(errorBody),
                )
            }
            val json = JSONObject(response.body?.string().orEmpty())
            val verdict = parseServerVerdict(json, response)
            val boxId = verdict.boxId
                ?: json.optString("boxId").ifBlank { null }
                ?: throw IOException("public hosted reporting response missing boxId")
            return SecureUploadResult(
                boxId = newBoxId(boxId),
                canonicalDeviceId = verdict.canonicalDeviceId,
                serverVerdict = verdict,
                serverInstallId = resolveServerInstallId(json, response),
            )
        }
    }

    private fun buildRequestBody(
        sdkVersion: String,
        payload: ByteArray,
        deviceContext: SecureDeviceContext,
    ): JSONObject = JSONObject()
        .put("mode", REPORTING_MODE)
        .put("requestId", UUID.randomUUID().toString())
        .put("sdkVersion", sdkVersion)
        .put("payloadEncoding", "base64")
        .put("payload", payload.toByteString().base64())
        .put("deviceContext", deviceContext.toPublicHostedJson())

    private fun SecureDeviceContext.toPublicHostedJson(): JSONObject = JSONObject()
        .put("installIdSha256", sha256Hex(installId))
        .put("resolvedDeviceIdSha256", sha256Hex(resolvedDeviceId))
        .put("fingerprintHash", fingerprintHash)
        .put("evidenceSignals", JSONArray((evidenceSignals + deviceEnvironmentEvidence.evidenceIds).sorted()))
        .put("deviceEnvironmentEvidence", deviceEnvironmentEvidence.toJsonObject())
        .put("nativeFactTags", JSONArray(nativeFactTags.sorted()))
        .put("nativeFindingIds", JSONArray(nativeFindingIds))
        .put("nativeHighestSeverity", nativeHighestSeverity)
        .put("installerPackage", installerPackage)
        .put("signingCertSha256", JSONArray(signingCertSha256))
        .put("sdkInt", sdkInt)
        .apply {
            installLifecycleSha256
                ?.takeIf { it.matches(SHA256_HEX_PATTERN) }
                ?.let { put("installLifecycleSha256", it) }
            canonicalDeviceId
                ?.takeIf { it.isNotBlank() }
                ?.let { put("canonicalDeviceIdSha256", sha256Hex(it)) }
        }

    companion object {
        private const val REPORTING_MODE = "public_hosted"
        private const val PUBLIC_SENSE_PATH = "/v1/sense/public"
        private val JSON_MEDIA_TYPE = "application/json".toMediaType()
        private val SHA256_HEX_PATTERN = Regex("[0-9a-f]{64}")

        private fun buildHttpClient(config: LeonaConfig): OkHttpClient {
            val builder = OkHttpClient.Builder()
                .callTimeout(10, TimeUnit.SECONDS)
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(8, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
            if (shouldUseHostedTrustFallback(config.reportingEndpoint)) {
                val trustManager = leonaHostedTrustManager()
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf<TrustManager>(trustManager), SecureRandom())
                builder.sslSocketFactory(sslContext.socketFactory, trustManager)
            }
            if (config.certificatePins.isNotEmpty()) {
                val pinner = CertificatePinner.Builder()
                config.certificatePins.forEach { (host, pins) ->
                    pins.forEach { pin -> pinner.add(host, pin) }
                }
                builder.certificatePinner(pinner.build())
            }
            return builder.build()
        }

        internal fun shouldUseHostedTrustFallback(endpoint: String?): Boolean {
            val normalized = endpoint?.trim()?.takeIf { it.isNotEmpty() } ?: return false
            val host = runCatching { URI(publicSenseUrl(normalized)).host?.lowercase() }
                .getOrNull()
            return host in LEONA_HOSTED_TRUST_FALLBACK_HOSTS
        }

        private fun leonaHostedTrustManager(): X509TrustManager =
            DelegatingTrustManager(
                primary = defaultTrustManager(),
                fallback = trustManagerForPemCertificate(ISRG_ROOT_X1_PEM),
            )

        private fun defaultTrustManager(): X509TrustManager {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(null as KeyStore?)
            return factory.trustManagers.singleX509TrustManager()
        }

        private fun trustManagerForPemCertificate(pem: String): X509TrustManager {
            val derBytes = pem.lineSequence()
                .filterNot { it.startsWith("-----") }
                .joinToString(separator = "")
                .decodeBase64()
                ?.toByteArray()
                ?: throw CertificateException("Unable to decode bundled ISRG Root X1 certificate")
            val certificate = CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(derBytes))
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("isrg-root-x1", certificate)
            }
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            factory.init(keyStore)
            return factory.trustManagers.singleX509TrustManager()
        }

        private fun Array<TrustManager>.singleX509TrustManager(): X509TrustManager =
            filterIsInstance<X509TrustManager>().singleOrNull()
                ?: error("Expected exactly one X509TrustManager")

        private fun publicSenseUrl(endpoint: String): String {
            val normalized = endpoint.trim().trimEnd('/')
            require(
                normalized.startsWith("https://", ignoreCase = true) ||
                    isLoopbackHttpEndpoint(normalized)
            ) {
                "public hosted reporting endpoint must use HTTPS"
            }
            return when {
                normalized.endsWith(PUBLIC_SENSE_PATH) -> normalized
                normalized.endsWith("/v1/sense") -> "$normalized/public"
                normalized.endsWith("/v1") -> "$normalized/sense/public"
                else -> "$normalized$PUBLIC_SENSE_PATH"
            }
        }

        internal fun validatedPublicSenseUrl(endpoint: String): String = publicSenseUrl(endpoint)

        private fun isLoopbackHttpEndpoint(endpoint: String): Boolean =
            runCatching {
                val uri = URI(endpoint)
                uri.scheme.equals("http", ignoreCase = true) &&
                    (uri.host == "127.0.0.1" || uri.host == "localhost" || uri.host == "::1")
            }.getOrDefault(false)

        private fun parseServerVerdict(json: JSONObject, response: Response): LeonaServerVerdict {
            val boxId = sequenceOf(
                json.optString("boxId"),
                json.optJSONObject("verdict")?.optString("boxId"),
                response.header("X-Leona-Box-Id"),
            ).mapNotNull(::meaningfulString).firstOrNull()
            val riskTags = buildSet {
                addAll(json.optStringArray("riskTags"))
                addAll(json.optJSONObject("verdict").optStringArray("riskTags"))
                addAll(json.optJSONObject("risk").optStringArray("tags"))
                response.header("X-Leona-Risk-Tags")
                    ?.split(',')
                    ?.mapNotNull(::meaningfulString)
                    ?.let(::addAll)
            }
            return LeonaServerVerdict(
                boxId = boxId,
                canonicalDeviceId = resolveCanonicalDeviceId(json)
                    ?: validCanonicalDeviceId(response.header("X-Leona-Canonical-Device-Id")),
                decision = sequenceOf(
                    json.optString("decision"),
                    json.optJSONObject("verdict")?.optString("decision"),
                    response.header("X-Leona-Decision"),
                ).mapNotNull(::meaningfulString).firstOrNull(),
                action = sequenceOf(
                    json.optString("action"),
                    json.optJSONObject("verdict")?.optString("action"),
                    json.optJSONObject("risk")?.optString("action"),
                    response.header("X-Leona-Action"),
                ).mapNotNull(::meaningfulString).firstOrNull(),
                riskLevel = sequenceOf(
                    json.optString("riskLevel"),
                    json.optJSONObject("verdict")?.optString("riskLevel"),
                    json.optJSONObject("risk")?.optString("level"),
                    response.header("X-Leona-Risk-Level"),
                ).mapNotNull(::meaningfulString).firstOrNull(),
                riskScore = sequenceOf(
                    json.optInt("riskScore", Int.MIN_VALUE).takeUnless { it == Int.MIN_VALUE },
                    json.optJSONObject("verdict")?.optInt("riskScore", Int.MIN_VALUE)
                        ?.takeUnless { it == Int.MIN_VALUE },
                    json.optJSONObject("risk")?.optInt("score", Int.MIN_VALUE)
                        ?.takeUnless { it == Int.MIN_VALUE },
                    response.header("X-Leona-Risk-Score")?.toIntOrNull(),
                ).firstOrNull(),
                riskTags = riskTags,
            )
        }

        private fun resolveCanonicalDeviceId(json: JSONObject): String? =
            sequenceOf(
                json.optString("canonicalDeviceId"),
                json.optJSONObject("verdict")?.optString("canonicalDeviceId"),
                json.optString("serverCanonicalDeviceId"),
                json.optJSONObject("verdict")?.optString("serverCanonicalDeviceId"),
            ).mapNotNull(::validCanonicalDeviceId).firstOrNull()

        private fun resolveServerInstallId(json: JSONObject, response: Response): String? =
            sequenceOf(
                json.optString("installId"),
                json.optString("serverInstallId"),
                json.optString("install_id"),
                json.optJSONObject("identity")?.optString("installId"),
                json.optJSONObject("identity")?.optString("serverInstallId"),
                response.header("X-Leona-Install-Id"),
            ).mapNotNull(::validServerInstallId).firstOrNull()

        private fun JSONObject?.optStringArray(key: String): Set<String> =
            this?.optJSONArray(key)?.let { array ->
                buildSet {
                    for (index in 0 until array.length()) {
                        meaningfulString(array.optString(index))?.let(::add)
                    }
                }
            }.orEmpty()

        private fun meaningfulString(value: String?): String? {
            val trimmed = value?.trim()?.ifEmpty { null } ?: return null
            return trimmed.takeUnless { it.equals("null", ignoreCase = true) }
        }

        private fun validCanonicalDeviceId(value: String?): String? =
            meaningfulString(value)?.takeIf { CANONICAL_DEVICE_ID_PATTERN.matches(it) }

        private fun validServerInstallId(value: String?): String? =
            meaningfulString(value)?.takeIf { SERVER_INSTALL_ID_PATTERN.matches(it) }

        private fun sanitizeErrorBody(body: String, apiKey: String): String =
            body.replace(apiKey, "<redacted-api-key>")

        private fun sha256Hex(value: String): String =
            MessageDigest.getInstance("SHA-256")
                .digest(value.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

        private fun newBoxId(value: String): BoxId {
            val ctor = BoxId::class.java.getDeclaredConstructor(String::class.java)
            ctor.isAccessible = true
            return ctor.newInstance(value)
        }

        private val LEONA_HOSTED_TRUST_FALLBACK_HOSTS = setOf("leona.xiyanshan.com")
        private val CANONICAL_DEVICE_ID_PATTERN = Regex("^L[0-9a-fA-F]{32,64}$")
        private val SERVER_INSTALL_ID_PATTERN = Regex("^I[0-9a-f]{32}$")

        private const val ISRG_ROOT_X1_PEM = """
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""
    }

    private class DelegatingTrustManager(
        private val primary: X509TrustManager,
        private val fallback: X509TrustManager,
    ) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {
            primary.checkClientTrusted(chain, authType)
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
            try {
                primary.checkServerTrusted(chain, authType)
            } catch (primaryError: CertificateException) {
                try {
                    fallback.checkServerTrusted(chain, authType)
                } catch (fallbackError: CertificateException) {
                    primaryError.addSuppressed(fallbackError)
                    throw primaryError
                }
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> =
            primary.acceptedIssuers + fallback.acceptedIssuers
    }
}
