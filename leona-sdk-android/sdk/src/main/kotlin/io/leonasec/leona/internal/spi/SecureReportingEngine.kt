/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.spi

import io.leonasec.leona.BoxId
import io.leonasec.leona.LeonaDeviceEnvironmentEvidence
import io.leonasec.leona.LeonaSecureTransportSnapshot
import io.leonasec.leona.LeonaServerVerdict

data class SecureDeviceContext(
    val installId: String,
    val resolvedDeviceId: String,
    val canonicalDeviceId: String? = null,
    val fingerprintHash: String,
    val riskSignals: Set<String> = emptySet(),
    val nativeRiskTags: Set<String> = emptySet(),
    val nativeFindingIds: List<String> = emptyList(),
    val nativeHighestSeverity: Int? = null,
    val installerPackage: String? = null,
    val signingCertSha256: List<String> = emptyList(),
    val sdkInt: Int? = null,
    val deviceEnvironmentEvidence: LeonaDeviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.EMPTY,
) {
    constructor(
        installId: String,
        resolvedDeviceId: String,
        canonicalDeviceId: String? = null,
        fingerprintHash: String,
        riskSignals: Set<String> = emptySet(),
        nativeRiskTags: Set<String> = emptySet(),
        nativeFindingIds: List<String> = emptyList(),
        nativeHighestSeverity: Int? = null,
        installerPackage: String? = null,
        signingCertSha256: List<String> = emptyList(),
        sdkInt: Int? = null,
    ) : this(
        installId = installId,
        resolvedDeviceId = resolvedDeviceId,
        canonicalDeviceId = canonicalDeviceId,
        fingerprintHash = fingerprintHash,
        riskSignals = riskSignals,
        nativeRiskTags = nativeRiskTags,
        nativeFindingIds = nativeFindingIds,
        nativeHighestSeverity = nativeHighestSeverity,
        installerPackage = installerPackage,
        signingCertSha256 = signingCertSha256,
        sdkInt = sdkInt,
        deviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.EMPTY,
    )
}

data class SecureUploadResult(
    val boxId: BoxId,
    val canonicalDeviceId: String? = null,
    val serverVerdict: LeonaServerVerdict? = null,
)

interface SecureReportingEngine {
    suspend fun resolveServerTamperBaselineJson(): String?
    suspend fun upload(payload: ByteArray, deviceContext: SecureDeviceContext): SecureUploadResult
    fun debugSnapshot(): LeonaSecureTransportSnapshot?
}
