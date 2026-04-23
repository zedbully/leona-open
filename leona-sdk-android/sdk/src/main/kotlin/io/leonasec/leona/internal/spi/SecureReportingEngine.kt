/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.spi

import io.leonasec.leona.BoxId
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
)

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
