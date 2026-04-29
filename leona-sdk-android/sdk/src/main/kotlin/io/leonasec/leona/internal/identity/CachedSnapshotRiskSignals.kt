/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

internal object CachedSnapshotRiskSignals {
    fun refresh(
        cached: DeviceFingerprintSnapshot,
        installerPackage: String?,
        signingCertSha256: List<String>,
        riskSignals: Set<String>,
    ): DeviceFingerprintSnapshot = cached.copy(
        installerPackage = installerPackage,
        signingCertSha256 = signingCertSha256,
        riskSignals = riskSignals,
    )
}
