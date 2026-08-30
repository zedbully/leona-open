/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import android.content.SharedPreferences
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.crypto.LeonaCryptoEnvelopeCodec
import io.leonasec.leona.crypto.LeonaCryptoHttpRequest
import io.leonasec.leona.crypto.LeonaCryptoProtectedHeadersCodec
import io.leonasec.leona.internal.identity.CollectionPolicy
import io.leonasec.leona.internal.identity.DeviceFingerprintSnapshot
import io.leonasec.leona.internal.identity.DeviceIdentityManager
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONObject
import java.security.MessageDigest
import java.nio.charset.StandardCharsets

internal class CloudConfigManager(
    context: Context,
    private val config: LeonaConfig,
    private val identityManager: DeviceIdentityManager,
) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    suspend fun refreshIfNeeded(force: Boolean = false): CollectionPolicy {
        val cached = currentPolicy()
        if (!config.cloudConfigEnabled) return cached
        val channel = config.cryptoChannel ?: return cached
        val endpoint = resolvedEndpoint() ?: return cached
        val trustedConfigSource = isTrustedCloudConfigEndpoint(endpoint)
        if (!trustedConfigSource) return cached
        val now = System.currentTimeMillis()
        val cacheFresh = now - prefs.getLong(KEY_FETCHED_AT, 0L) < REFRESH_TTL_MS
        val cacheBoundToEndpoint = isTrustedCachedCloudConfig(endpoint, prefs.getString(KEY_REMOTE_ENDPOINT, null))
        if (!force && cacheFresh && cacheBoundToEndpoint) {
            return cached
        }

        return runCatching {
            val snapshot = identityManager.resolve(cached, refreshRiskSignals = true)
            val url = endpoint.toHttpUrlOrNull() ?: return@runCatching cached
            val protectedHeaders = linkedMapOf<String, String>()
            config.apiKey?.let { protectedHeaders["X-Leona-App-Key"] = it }
            config.tenantId?.let { protectedHeaders["X-Leona-Tenant"] = it }
            protectedHeaders["X-Leona-App-Id"] = config.appId
            config.channel?.let { protectedHeaders["X-Leona-Channel"] = it }
            protectedHeaders["X-Leona-Protocol"] = LeonaCryptoEnvelopeCodec.PROTOCOL_MAJOR.toString()
            protectedHeaders["X-Leona-Request-Id"] = java.util.UUID.randomUUID().toString()
            protectedHeaders.putAll(redactedIdentityHeaders(snapshot))
            val request = LeonaCryptoHttpRequest(
                method = "GET",
                authority = url.host + if (url.port != if (url.isHttps) 443 else 80) ":${url.port}" else "",
                path = "/v1/mobile-config",
                contentType = "application/json",
                protectedHeaders = LeonaCryptoProtectedHeadersCodec.encode(protectedHeaders),
            )
            val response = LeonaCryptoHttpClient(
                channel = channel,
                endpointUrl = endpoint,
                certificatePins = config.certificatePins,
                callTimeoutSeconds = 5,
                connectTimeoutSeconds = 2,
                readTimeoutSeconds = 4,
            ).execute(request)
            val opened = when (response) {
                is io.leonasec.leona.crypto.LeonaCryptoResult.Success -> response.value
                is io.leonasec.leona.crypto.LeonaCryptoResult.Failure -> return@runCatching cached
            }
            if (opened.statusCode !in 200..299) return@runCatching cached
            val body = opened.body.toString(StandardCharsets.UTF_8)
            val responseHeaders = LeonaCryptoProtectedHeadersCodec.decode(opened.protectedHeaders)
            val remote = parseRemoteConfig(body, responseHeaders).onlyIfTrusted(trustedConfigSource)
            prefs.edit()
                .putString(KEY_REMOTE_JSON, body)
                .putString(KEY_REMOTE_ENDPOINT, endpoint)
                .putLong(KEY_FETCHED_AT, now)
                .apply()
            remote.toPolicy(config)
        }.getOrDefault(cached)
    }

    fun currentPolicy(): CollectionPolicy {
        if (!config.cloudConfigEnabled) return RemoteConfig().toPolicy(config)
        val endpoint = resolvedEndpoint()
        if (!isTrustedCachedCloudConfig(endpoint, prefs.getString(KEY_REMOTE_ENDPOINT, null))) {
            return RemoteConfig().toPolicy(config)
        }
        val body = prefs.getString(KEY_REMOTE_JSON, null)
        val remote = parseRemoteConfig(body)
        return remote.toPolicy(config)
    }

    fun debugSnapshot(): DebugSnapshot = DebugSnapshot(
        rawJson = prefs.getString(KEY_REMOTE_JSON, null),
        fetchedAtMillis = prefs.getLong(KEY_FETCHED_AT, 0L).takeIf { it > 0L },
    )

    private fun resolvedEndpoint(): String? =
        config.cloudConfigEndpoint?.trim()?.ifEmpty { null }
            ?: config.reportingEndpoint?.trim()?.ifEmpty { null }

    private fun parseRemoteConfig(body: String?, protectedHeaders: Map<String, String> = emptyMap()): RemoteConfig {
        val remoteFromBody = parseRemoteConfigBody(body)
        val remoteFromHeaders = parseRemoteConfigHeaders(protectedHeaders)
        return remoteFromBody.merge(remoteFromHeaders)
    }

    internal data class RemoteConfig(
        val disabledSignals: Set<String> = emptySet(),
        val disableCollectionWindowMs: Long = -1L,
    ) {
        fun merge(other: RemoteConfig): RemoteConfig = RemoteConfig(
            disabledSignals = disabledSignals + other.disabledSignals,
            disableCollectionWindowMs = when {
                other.disableCollectionWindowMs >= 0 -> other.disableCollectionWindowMs
                else -> disableCollectionWindowMs
            },
        )

        fun onlyIfTrusted(trusted: Boolean): RemoteConfig =
            if (trusted) this else RemoteConfig()

        fun toPolicy(config: LeonaConfig): CollectionPolicy = CollectionPolicy(
            disabledSignals = config.disabledSignals + disabledSignals,
            disableCollectionWindowMs = when {
                disableCollectionWindowMs >= 0 -> disableCollectionWindowMs
                else -> config.disableCollectionWindowMs
            },
        )
    }

    internal data class DebugSnapshot(
        val rawJson: String?,
        val fetchedAtMillis: Long?,
    )

    internal companion object {
        const val PREFS_NAME = "io.leonasec.leona.cloud"
        const val KEY_REMOTE_JSON = "remote.json"
        const val KEY_REMOTE_ENDPOINT = "remote.endpoint"
        const val KEY_FETCHED_AT = "remote.fetchedAt"
        const val REFRESH_TTL_MS = 6L * 60L * 60L * 1000L

        internal fun redactedIdentityHeaders(snapshot: DeviceFingerprintSnapshot): Map<String, String> =
            buildMap {
                hashHeader(snapshot.resolvedDeviceId)?.let { put("X-Leona-Device-Id-Sha256", it) }
                hashHeader(snapshot.installId)?.let { put("X-Leona-Install-Id-Sha256", it) }
                snapshot.canonicalDeviceId
                    ?.let(::hashHeader)
                    ?.let { put("X-Leona-Canonical-Device-Id-Sha256", it) }
                snapshot.fingerprintHash.takeIf { it.isNotBlank() }?.let { put("X-Leona-Fingerprint", it) }
            }

        private fun hashHeader(value: String?): String? =
            value?.trim()?.takeIf { it.isNotEmpty() }?.let(::sha256Hex)

        private fun sha256Hex(value: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
            return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }

        internal fun isTrustedCloudConfigEndpoint(endpoint: String?): Boolean =
            endpoint?.trim()?.startsWith("https://", ignoreCase = true) == true

        internal fun isTrustedCachedCloudConfig(endpoint: String?, cachedEndpoint: String?): Boolean {
            val resolved = endpoint?.trim()?.ifEmpty { null } ?: return false
            return isTrustedCloudConfigEndpoint(resolved) && cachedEndpoint == resolved
        }

        internal fun parseRemoteConfigBody(body: String?): RemoteConfig {
            if (body.isNullOrBlank()) return RemoteConfig()
            return runCatching {
                val json = JSONObject(body)
                val policyJson = json.optJSONObject("policy")
                val configJson = json.optJSONObject("config")
                RemoteConfig(
                    disabledSignals = buildSet {
                        addAll(readStringArray(json, "disabledSignals"))
                        addAll(readStringArray(json, "disabledCollectors"))
                        addAll(readStringArray(policyJson, "disabledSignals"))
                        addAll(readStringArray(policyJson, "disabledCollectors"))
                        addAll(readStringArray(configJson, "disabledSignals"))
                        addAll(readStringArray(configJson, "disabledCollectors"))
                    },
                    disableCollectionWindowMs = firstNonNegativeLong(
                        json.optLong("disableCollectionWindowMs", -1L),
                        json.optLong("disableCollectionWindow", -1L),
                        policyJson?.optLong("disableCollectionWindowMs", -1L) ?: -1L,
                        policyJson?.optLong("disableCollectionWindow", -1L) ?: -1L,
                        configJson?.optLong("disableCollectionWindowMs", -1L) ?: -1L,
                        configJson?.optLong("disableCollectionWindow", -1L) ?: -1L,
                    ),
                )
            }.getOrDefault(RemoteConfig())
        }

        internal fun parseRemoteConfigHeaders(headers: Map<String, String?>): RemoteConfig {
            val disabledSignals = headers["X-Leona-Disabled-Signals"]
                ?.split(',')
                ?.mapNotNull { value -> value.trim().ifEmpty { null } }
                ?.toSet()
                .orEmpty()
            val disableCollectionWindowMs = headers["X-Leona-Disable-Collection-Window-Ms"]
                ?.trim()
                ?.toLongOrNull()
                ?: -1L
            return RemoteConfig(
                disabledSignals = disabledSignals,
                disableCollectionWindowMs = disableCollectionWindowMs,
            )
        }

        private fun readStringArray(json: JSONObject?, key: String): Set<String> {
            if (json == null) return emptySet()
            return buildSet {
                json.optJSONArray(key)?.let { array ->
                    for (index in 0 until array.length()) {
                        val value = array.optString(index).trim()
                        if (value.isNotEmpty()) add(value)
                    }
                }
            }
        }

        private fun firstNonNegativeLong(vararg values: Long): Long =
            values.firstOrNull { it >= 0L } ?: -1L
    }
}
