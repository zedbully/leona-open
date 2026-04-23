/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import android.content.SharedPreferences
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.identity.CollectionPolicy
import io.leonasec.leona.internal.identity.DeviceFingerprintSnapshot
import io.leonasec.leona.internal.identity.DeviceIdentityManager
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

internal class CloudConfigManager(
    context: Context,
    private val config: LeonaConfig,
    private val identityManager: DeviceIdentityManager,
) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val httpClient: OkHttpClient by lazy {
        val builder = OkHttpClient.Builder()
            .callTimeout(5, TimeUnit.SECONDS)
            .connectTimeout(2, TimeUnit.SECONDS)
            .readTimeout(4, TimeUnit.SECONDS)
            .retryOnConnectionFailure(true)
        if (config.certificatePins.isNotEmpty()) {
            val pinner = CertificatePinner.Builder()
            config.certificatePins.forEach { (host, pins) ->
                pins.forEach { pin -> pinner.add(host, pin) }
            }
            builder.certificatePinner(pinner.build())
        }
        builder.build()
    }

    suspend fun refreshIfNeeded(force: Boolean = false): CollectionPolicy {
        val cached = currentPolicy()
        if (!config.cloudConfigEnabled) return cached
        val endpoint = resolvedEndpoint() ?: return cached
        val now = System.currentTimeMillis()
        if (!force && now - prefs.getLong(KEY_FETCHED_AT, 0L) < REFRESH_TTL_MS) {
            return cached
        }

        return runCatching {
            val snapshot = identityManager.currentSnapshot()
                ?: identityManager.resolve(cached)
            val request = Request.Builder()
                .url(endpoint)
                .get()
                .apply {
                    config.apiKey?.let { header("X-Leona-App-Key", it) }
                    config.tenantId?.let { header("X-Leona-Tenant", it) }
                    header("X-Leona-App-Id", config.appId)
                    config.channel?.let { header("X-Leona-Channel", it) }
                    applyIdentityHeaders(snapshot)
                }
                .build()
            httpClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@use cached
                val body = response.body?.string().orEmpty()
                val remote = parseRemoteConfig(body, response)
                prefs.edit()
                    .putString(KEY_REMOTE_JSON, body)
                    .putLong(KEY_FETCHED_AT, now)
                    .apply()
                remote.canonicalDeviceId?.let(identityManager::updateCanonicalDeviceId)
                remote.toPolicy(config)
            }
        }.getOrDefault(cached)
    }

    fun currentPolicy(): CollectionPolicy {
        val body = prefs.getString(KEY_REMOTE_JSON, null)
        val remote = parseRemoteConfig(body)
        remote.canonicalDeviceId?.let(identityManager::updateCanonicalDeviceId)
        return remote.toPolicy(config)
    }

    fun debugSnapshot(): DebugSnapshot = DebugSnapshot(
        rawJson = prefs.getString(KEY_REMOTE_JSON, null),
        fetchedAtMillis = prefs.getLong(KEY_FETCHED_AT, 0L).takeIf { it > 0L },
    )

    private fun resolvedEndpoint(): String? =
        config.cloudConfigEndpoint?.trim()?.ifEmpty { null }
            ?: config.reportingEndpoint
                ?.trimEnd('/')
                ?.let { "$it${config.region.cloudConfigPath}" }

    private fun parseRemoteConfig(body: String?, response: Response? = null): RemoteConfig {
        val remoteFromBody = parseRemoteConfigBody(body)
        val remoteFromHeaders = response?.toRemoteConfigFromHeaders() ?: RemoteConfig()
        return remoteFromBody.merge(remoteFromHeaders)
    }

    internal data class RemoteConfig(
        val disabledSignals: Set<String> = emptySet(),
        val disableCollectionWindowMs: Long = -1L,
        val canonicalDeviceId: String? = null,
    ) {
        fun merge(other: RemoteConfig): RemoteConfig = RemoteConfig(
            disabledSignals = disabledSignals + other.disabledSignals,
            disableCollectionWindowMs = when {
                other.disableCollectionWindowMs >= 0 -> other.disableCollectionWindowMs
                else -> disableCollectionWindowMs
            },
            canonicalDeviceId = other.canonicalDeviceId ?: canonicalDeviceId,
        )

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

    private fun Request.Builder.applyIdentityHeaders(snapshot: DeviceFingerprintSnapshot) {
        header("X-Leona-Device-Id", snapshot.resolvedDeviceId)
        header("X-Leona-Install-Id", snapshot.installId)
        header("X-Leona-Fingerprint", snapshot.fingerprintHash)
        if (snapshot.riskSignals.isNotEmpty()) {
            header("X-Leona-Risk-Signals", snapshot.riskSignals.sorted().joinToString(",").take(512))
        }
        snapshot.canonicalDeviceId?.takeIf { it.isNotBlank() }?.let {
            header("X-Leona-Canonical-Device-Id", it)
        }
    }

    private fun Response.toRemoteConfigFromHeaders(): RemoteConfig {
        return parseRemoteConfigHeaders(
            mapOf(
                "X-Leona-Disabled-Signals" to header("X-Leona-Disabled-Signals"),
                "X-Leona-Disable-Collection-Window-Ms" to header("X-Leona-Disable-Collection-Window-Ms"),
                "X-Leona-Canonical-Device-Id" to header("X-Leona-Canonical-Device-Id"),
                "X-Leona-Device-Id" to header("X-Leona-Device-Id"),
            ),
        )
    }

    internal companion object {
        const val PREFS_NAME = "io.leonasec.leona.cloud"
        const val KEY_REMOTE_JSON = "remote.json"
        const val KEY_FETCHED_AT = "remote.fetchedAt"
        const val REFRESH_TTL_MS = 6L * 60L * 60L * 1000L

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
                    canonicalDeviceId = resolveCanonicalDeviceId(json),
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
            val canonicalDeviceId = sequenceOf(
                headers["X-Leona-Canonical-Device-Id"],
                headers["X-Leona-Device-Id"],
            ).mapNotNull { it?.trim()?.ifEmpty { null } }
                .firstOrNull()
            return RemoteConfig(
                disabledSignals = disabledSignals,
                disableCollectionWindowMs = disableCollectionWindowMs,
                canonicalDeviceId = canonicalDeviceId,
            )
        }

        private fun resolveCanonicalDeviceId(json: JSONObject): String? =
            sequenceOf(
                json.optString("canonicalDeviceId"),
                json.optString("deviceId"),
                json.optJSONObject("device")?.optString("canonicalDeviceId"),
                json.optJSONObject("device")?.optString("deviceId"),
                json.optJSONObject("device")?.optString("id"),
                json.optJSONObject("identity")?.optString("canonicalDeviceId"),
                json.optJSONObject("identity")?.optString("deviceId"),
                json.optJSONObject("deviceIdentity")?.optString("canonicalDeviceId"),
                json.optJSONObject("deviceIdentity")?.optString("deviceId"),
                json.optJSONObject("deviceIdentity")?.optString("resolvedDeviceId"),
            ).mapNotNull { it?.trim()?.ifEmpty { null } }
                .firstOrNull()

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
