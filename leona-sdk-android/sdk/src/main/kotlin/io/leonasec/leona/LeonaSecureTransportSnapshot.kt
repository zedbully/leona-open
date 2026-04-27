/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import org.json.JSONObject

data class LeonaSecureTransportSnapshot(
    val engineAvailable: Boolean,
    val engineClassName: String?,
    val endpointConfigured: Boolean,
    val apiKeyConfigured: Boolean,
    val attestationProviderConfigured: Boolean,
    val deviceBinding: LeonaDeviceBindingSnapshot?,
    val session: LeonaSecureSessionSnapshot?,
    val lastAttestation: LeonaAttestationSnapshot?,
    val lastHandshakeAtMillis: Long?,
    val lastHandshakeError: String?,
    val lastHandshakeErrorClass: String? = null,
    val lastHandshakeErrorCode: String? = null,
    val lastHandshakeErrorProvider: String? = null,
    val lastHandshakeRetryable: Boolean? = null,
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("engineAvailable", engineAvailable)
        .put("engineClassName", engineClassName)
        .put("endpointConfigured", endpointConfigured)
        .put("apiKeyConfigured", apiKeyConfigured)
        .put("attestationProviderConfigured", attestationProviderConfigured)
        .put("deviceBinding", deviceBinding?.toJsonObject())
        .put("session", session?.toJsonObject())
        .put("lastAttestation", lastAttestation?.toJsonObject())
        .put("lastHandshakeAtMillis", lastHandshakeAtMillis)
        .put("lastHandshakeError", lastHandshakeError)
        .put("lastHandshakeErrorClass", lastHandshakeErrorClass)
        .put("lastHandshakeErrorCode", lastHandshakeErrorCode)
        .put("lastHandshakeErrorProvider", lastHandshakeErrorProvider)
        .put("lastHandshakeRetryable", lastHandshakeRetryable)

    fun toJson(): String = toJsonObject().toString(2)
}

data class LeonaDeviceBindingSnapshot(
    val alias: String,
    val present: Boolean,
    val publicKeySha256: String?,
    val keyAlgorithm: String?,
    val signatureAlgorithm: String?,
    val hardwareBacked: Boolean?,
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("alias", alias)
        .put("present", present)
        .put("publicKeySha256", publicKeySha256)
        .put("keyAlgorithm", keyAlgorithm)
        .put("signatureAlgorithm", signatureAlgorithm)
        .put("hardwareBacked", hardwareBacked)
}

data class LeonaSecureSessionSnapshot(
    val sessionIdHint: String?,
    val expiresAtMillis: Long?,
    val hasServerTamperPolicy: Boolean,
    val canonicalDeviceId: String?,
    val deviceBindingStatus: String? = null,
    val serverAttestation: LeonaServerAttestationSnapshot? = null,
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("sessionIdHint", sessionIdHint)
        .put("expiresAtMillis", expiresAtMillis)
        .put("hasServerTamperPolicy", hasServerTamperPolicy)
        .put("canonicalDeviceId", canonicalDeviceId)
        .put("deviceBindingStatus", deviceBindingStatus)
        .put("serverAttestation", serverAttestation?.toJsonObject())
}

data class LeonaServerAttestationSnapshot(
    val provider: String? = null,
    val status: String? = null,
    val code: String? = null,
    val retryable: Boolean? = null,
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("provider", provider)
        .put("status", status)
        .put("code", code)
        .put("retryable", retryable)
}

data class LeonaAttestationSnapshot(
    val format: String,
    val tokenSha256: String,
    val tokenLength: Int,
    val collectedAtMillis: Long,
) {
    fun toJsonObject(): JSONObject = JSONObject()
        .put("format", format)
        .put("tokenSha256", tokenSha256)
        .put("tokenLength", tokenLength)
        .put("collectedAtMillis", collectedAtMillis)
}
