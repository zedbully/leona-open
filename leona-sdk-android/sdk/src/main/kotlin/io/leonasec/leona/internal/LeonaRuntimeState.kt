/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.LeonaServerVerdict
import io.leonasec.leona.internal.identity.DeviceIdentityManager
import java.util.concurrent.atomic.AtomicReference

internal data class LeonaRuntimeState(
    val appContext: Context,
    val config: LeonaConfig,
    val channel: SecureChannel,
    val identityManager: DeviceIdentityManager,
    val cloudConfigManager: CloudConfigManager,
    val lastNativeRisk: AtomicReference<NativePayloadInspector.NativeRiskSummary> = AtomicReference(
        NativePayloadInspector.NativeRiskSummary.EMPTY,
    ),
    val lastIntegritySnapshot: AtomicReference<String?> = AtomicReference(null),
    val lastPolicySnapshot: AtomicReference<String?> = AtomicReference(null),
    val lastServerVerdict: AtomicReference<LeonaServerVerdict?> = AtomicReference(null),
)
