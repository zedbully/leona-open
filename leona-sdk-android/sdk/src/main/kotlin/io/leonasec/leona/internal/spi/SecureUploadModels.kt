/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.spi

import io.leonasec.leona.BoxId
import io.leonasec.leona.LeonaDeviceEnvironmentEvidence
import io.leonasec.leona.LeonaServerVerdict
import io.leonasec.leona.internal.ClientEvidenceSignalMapper

data class SecureDeviceContext(
    val installId: String,
    val resolvedDeviceId: String,
    val canonicalDeviceId: String? = null,
    val fingerprintHash: String,
    @Deprecated(
        message = "Use evidenceSignals. Client-side values are low-trust evidence, not final risk decisions.",
        replaceWith = ReplaceWith("evidenceSignals"),
    )
    val riskSignals: Set<String> = emptySet(),
    @Deprecated(
        message = "Use nativeFactTags/nativeFindingIds. Client-side values are low-trust evidence, not final risk decisions.",
        replaceWith = ReplaceWith("nativeFactTags"),
    )
    val nativeRiskTags: Set<String> = emptySet(),
    val nativeFindingIds: List<String> = emptyList(),
    val nativeHighestSeverity: Int? = null,
    val installerPackage: String? = null,
    val signingCertSha256: List<String> = emptyList(),
    val sdkInt: Int? = null,
    val deviceEnvironmentEvidence: LeonaDeviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.EMPTY,
    val evidenceSignals: Set<String> = ClientEvidenceSignalMapper.toEvidenceSignals(riskSignals),
    val nativeFactTags: Set<String> = nativeRiskTags,
    /** Hashed package-install lifecycle handle; telemetry/recovery only. */
    val installLifecycleSha256: String? = null,
    /** Process-scoped session correlation; not persisted as install identity. */
    val sessionId: String? = null,
    /** Typed local storage evidence; never a client-side verdict. */
    val identityProtectionLevel: String = "KEYSTORE_AES_GCM",
    val identityProtectionCode: String = "READY",
    val identityProtectionDurable: Boolean = true,
    val identityProtectionRecoverable: Boolean = true,
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
        evidenceSignals = ClientEvidenceSignalMapper.toEvidenceSignals(riskSignals),
        nativeFactTags = nativeRiskTags,
    )
}

data class SecureUploadResult(
    val boxId: BoxId,
    val canonicalDeviceId: String? = null,
    val serverVerdict: LeonaServerVerdict? = null,
    val serverInstallId: String? = null,
) {
    /** Retains the pre-install_id constructor for closed-source engines. */
    constructor(
        boxId: BoxId,
        canonicalDeviceId: String?,
        serverVerdict: LeonaServerVerdict?,
    ) : this(boxId, canonicalDeviceId, serverVerdict, null)
}
