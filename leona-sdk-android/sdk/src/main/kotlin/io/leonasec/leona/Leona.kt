/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

import android.content.Context
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.AppIntegrity
import io.leonasec.leona.internal.CloudConfigManager
import io.leonasec.leona.internal.LeonaRuntimeState
import io.leonasec.leona.internal.NativeBridge
import io.leonasec.leona.internal.NativePayloadInspector
import io.leonasec.leona.internal.SecureChannel
import io.leonasec.leona.internal.TamperContext
import io.leonasec.leona.internal.identity.DeviceIdentityManager
import io.leonasec.leona.internal.spi.SecureDeviceContext
import io.leonasec.leona.internal.toTamperPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Public entry point for the Leona mobile security SDK.
 */
object Leona {

    private val initialized = AtomicBoolean(false)
    private val runtimeState = AtomicReference<LeonaRuntimeState?>()

    /**
     * Initialize the SDK. Safe to call multiple times — subsequent calls are
     * no-ops. Must be called before any [sense] invocation.
     */
    @JvmStatic
    fun init(context: Context, config: LeonaConfig = LeonaConfig.Builder().build()) {
        if (!initialized.compareAndSet(false, true)) return

        val appContext = context.applicationContext
        NativeBridge.load()
        NativeBridge.init(
            appContext,
            config.toNativeHandle(),
            AppIntegrity.capture(appContext, config.toTamperPolicy()),
            AppIntegrity.capturePolicy(config.toTamperPolicy()),
        )

        val identityManager = DeviceIdentityManager(appContext, config)
        val cloudConfigManager = CloudConfigManager(appContext, config, identityManager)
        val channel = SecureChannel(appContext, config)
        val state = LeonaRuntimeState(
            appContext = appContext,
            config = config,
            channel = channel,
            identityManager = identityManager,
            cloudConfigManager = cloudConfigManager,
        )
        runtimeState.set(state)

        if (config.cloudConfigEnabled && config.syncInit) {
            runBlocking(Dispatchers.IO) {
                identityManager.resolve(cloudConfigManager.currentPolicy())
                cloudConfigManager.refreshIfNeeded(force = true)
                identityManager.resolve(cloudConfigManager.currentPolicy())
                val tamperContext = refreshTamperDebugState(state)
                NativeBridge.updateTamperContext(
                    tamperContext.integritySnapshot,
                    tamperContext.policySnapshot,
                )
            }
        } else if (config.cloudConfigEnabled) {
            SecureChannel.launchFireAndForget {
                identityManager.resolve(cloudConfigManager.currentPolicy())
                cloudConfigManager.refreshIfNeeded(force = false)
                identityManager.resolve(cloudConfigManager.currentPolicy())
                val tamperContext = refreshTamperDebugState(state)
                NativeBridge.updateTamperContext(
                    tamperContext.integritySnapshot,
                    tamperContext.policySnapshot,
                )
            }
        } else {
            SecureChannel.launchFireAndForget {
                identityManager.resolve()
                val tamperContext = refreshTamperDebugState(state)
                NativeBridge.updateTamperContext(
                    tamperContext.integritySnapshot,
                    tamperContext.policySnapshot,
                )
            }
        }
    }

    /**
     * Collect the current device's security posture and report it to Leona's
     * backend. Returns an opaque [BoxId] that your app forwards to your
     * business API.
     */
    @JvmStatic
    suspend fun sense(): BoxId = withContext(Dispatchers.IO) {
        val state = runtimeState.get() ?: error("Leona.init() must be called before sense().")
        val policy = state.cloudConfigManager.refreshIfNeeded(force = false)
        val snapshot = state.identityManager.resolve(policy)
        val tamperContext = refreshTamperDebugState(state)
        NativeBridge.updateTamperContext(
            tamperContext.integritySnapshot,
            tamperContext.policySnapshot,
        )
        val payload = NativeBridge.collect()
        val nativeRisk = NativePayloadInspector.inspect(payload)
        state.lastNativeRisk.set(nativeRisk)
        val mergedRiskSignals = snapshot.riskSignals + nativeRisk.riskTags
        val uploadResult = state.channel.upload(
            payload = payload,
            deviceContext = SecureDeviceContext(
                installId = snapshot.installId,
                resolvedDeviceId = snapshot.resolvedDeviceId,
                canonicalDeviceId = snapshot.canonicalDeviceId,
                fingerprintHash = snapshot.fingerprintHash,
                riskSignals = mergedRiskSignals,
                nativeRiskTags = nativeRisk.riskTags,
                nativeFindingIds = nativeRisk.findingIds,
                nativeHighestSeverity = nativeRisk.highestSeverity,
                installerPackage = snapshot.installerPackage,
                signingCertSha256 = snapshot.signingCertSha256,
                sdkInt = snapshot.sdkInt,
            ),
        )
        uploadResult.canonicalDeviceId?.let(state.identityManager::updateCanonicalDeviceId)
        state.lastServerVerdict.set(uploadResult.serverVerdict)
        uploadResult.boxId
    }

    /** Java-friendly async variant of [sense]. */
    @JvmStatic
    fun senseAsync(callback: BoxIdCallback) {
        SecureChannel.launchSense(callback) { sense() }
    }

    /**
     * Returns the best currently-known device identifier.
     *
     * - `L...` = canonical ID persisted from server/cloud config
     * - `T...` = local temporary ID derived from stable per-app/device inputs
     */
    @JvmStatic
    fun getDeviceId(): String {
        val state = runtimeState.get() ?: error("Leona.init() must be called before getDeviceId().")
        val policy = state.cloudConfigManager.currentPolicy()
        return state.identityManager.resolve(policy).resolvedDeviceId
    }

    /** Java-friendly async variant of [getDeviceId]. */
    @JvmStatic
    fun getDeviceId(callback: DeviceIdCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getDeviceId())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /**
     * Returns a debug-oriented snapshot of the current local identity and
     * most recently-seen native risk summary.
     */
    @JvmStatic
    fun getDiagnosticSnapshot(): LeonaDiagnosticSnapshot {
        val state = runtimeState.get() ?: error("Leona.init() must be called before getDiagnosticSnapshot().")
        val policy = state.cloudConfigManager.currentPolicy()
        val identity = state.identityManager.resolve(policy)
        val nativeRisk = state.lastNativeRisk.get()
        val serverVerdict = state.lastServerVerdict.get()
        return LeonaDiagnosticSnapshot(
            deviceId = identity.resolvedDeviceId,
            installId = identity.installId,
            canonicalDeviceId = identity.canonicalDeviceId,
            fingerprintHash = identity.fingerprintHash,
            packageName = identity.packageName,
            appVersionName = identity.appVersionName,
            appVersionCode = identity.appVersionCode,
            installerPackage = identity.installerPackage,
            androidId = identity.androidId,
            signingCertSha256 = identity.signingCertSha256,
            localeTag = identity.localeTag,
            timeZoneId = identity.timeZoneId,
            screenSummary = identity.screenSummary,
            localRiskSignals = identity.riskSignals,
            nativeRiskTags = nativeRisk.riskTags,
            nativeFindingIds = nativeRisk.findingIds,
            nativeHighestSeverity = nativeRisk.highestSeverity,
            nativeEventCount = nativeRisk.eventCount,
            serverDecision = serverVerdict?.decision,
            serverAction = serverVerdict?.action,
            serverRiskLevel = serverVerdict?.riskLevel,
            serverRiskScore = serverVerdict?.riskScore,
            serverRiskTags = serverVerdict?.riskTags.orEmpty(),
            lastBoxId = serverVerdict?.boxId,
        )
    }

    /** Returns the last standardized server verdict seen from sense(), if any. */
    @JvmStatic
    fun getLastServerVerdict(): LeonaServerVerdict? {
        val state = runtimeState.get() ?: error("Leona.init() must be called before getLastServerVerdict().")
        return state.lastServerVerdict.get()
    }

    /** Returns the last standardized server verdict formatted as pretty JSON, if any. */
    @JvmStatic
    fun getLastServerVerdictJson(): String? = getLastServerVerdict()?.toJson()

    /** Java-friendly async variant of [getLastServerVerdictJson]. */
    @JvmStatic
    fun getLastServerVerdictJson(callback: ServerVerdictJsonCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getLastServerVerdictJson())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /** Returns secure reporting transport / device-binding / attestation diagnostics. */
    @JvmStatic
    fun getSecureTransportSnapshot(): LeonaSecureTransportSnapshot {
        val state = runtimeState.get() ?: error("Leona.init() must be called before getSecureTransportSnapshot().")
        return state.channel.debugSnapshot()
    }

    /** Java-friendly async variant of [getSecureTransportSnapshot]. */
    @JvmStatic
    fun getSecureTransportSnapshot(callback: SecureTransportSnapshotCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getSecureTransportSnapshot())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /** Returns secure reporting transport diagnostics formatted as pretty JSON. */
    @JvmStatic
    fun getSecureTransportSnapshotJson(): String = getSecureTransportSnapshot().toJson()

    /** Java-friendly async variant of [getSecureTransportSnapshotJson]. */
    @JvmStatic
    fun getSecureTransportSnapshotJson(callback: SecureTransportJsonCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getSecureTransportSnapshotJson())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /** Returns a support bundle with current identity, verdict, and effective policy. */
    @JvmStatic
    fun getSupportBundle(): LeonaSupportBundle {
        val state = runtimeState.get() ?: error("Leona.init() must be called before getSupportBundle().")
        val policy = state.cloudConfigManager.currentPolicy()
        val fallbackTamperPolicy = AppIntegrity.capturePolicy(state.config.toTamperPolicy())
        val fallbackIntegritySnapshot = AppIntegrity.capture(state.appContext, state.config.toTamperPolicy())
        val cloudDebug = state.cloudConfigManager.debugSnapshot()
        return LeonaSupportBundle(
            generatedAtMillis = System.currentTimeMillis(),
            sdkVersion = version,
            tenantId = state.config.tenantId,
            appId = state.config.appId,
            region = state.config.region.name,
            transportEnabled = state.config.transportEnabled,
            cloudConfigEnabled = state.config.cloudConfigEnabled,
            syncInit = state.config.syncInit,
            effectiveDisabledSignals = policy.disabledSignals,
            effectiveDisableCollectionWindowMs = policy.disableCollectionWindowMs,
            effectiveTamperPolicy = parseSnapshotMap(
                state.lastPolicySnapshot.get() ?: fallbackTamperPolicy,
            ),
            lastIntegritySnapshot = parseSnapshotMap(
                state.lastIntegritySnapshot.get() ?: fallbackIntegritySnapshot,
            ),
            cloudConfigFetchedAtMillis = cloudDebug.fetchedAtMillis,
            cloudConfigRawJson = cloudDebug.rawJson,
            secureTransport = getSecureTransportSnapshot(),
            diagnosticSnapshot = getDiagnosticSnapshot(),
            serverVerdict = state.lastServerVerdict.get(),
        )
    }

    /** Java-friendly async variant of [getSupportBundle]. */
    @JvmStatic
    fun getSupportBundle(callback: SupportBundleCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getSupportBundle())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /** Returns the current support bundle formatted as pretty JSON. */
    @JvmStatic
    fun getSupportBundleJson(): String = getSupportBundle().toJson()

    /** Java-friendly async variant of [getSupportBundleJson]. */
    @JvmStatic
    fun getSupportBundleJson(callback: SupportBundleJsonCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getSupportBundleJson())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /** Java-friendly async variant of [getDiagnosticSnapshot]. */
    @JvmStatic
    fun getDiagnosticSnapshot(callback: DiagnosticSnapshotCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getDiagnosticSnapshot())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /** Returns the current diagnostic snapshot formatted as pretty JSON. */
    @JvmStatic
    fun getDiagnosticSnapshotJson(): String = getDiagnosticSnapshot().toJson()

    /** Java-friendly async variant of [getDiagnosticSnapshotJson]. */
    @JvmStatic
    fun getDiagnosticSnapshotJson(callback: DiagnosticJsonCallback) {
        SecureChannel.launchFireAndForget {
            try {
                callback.onResult(getDiagnosticSnapshotJson())
            } catch (t: Throwable) {
                callback.onError(t)
            }
        }
    }

    /**
     * Resets JVM-side state so tests or host apps can reinitialize the SDK.
     * Native singletons remain loaded, but all cached Kotlin-side handles are dropped.
     */
    @JvmStatic
    fun destroy() {
        runtimeState.set(null)
        initialized.set(false)
    }

    /**
     * **Decoy API. Do not use for security decisions.**
     */
    @JvmStatic
    @Deprecated(
        message = "Client-side detection is unreliable. Use sense() + server verification.",
        level = DeprecationLevel.WARNING,
    )
    fun quickCheck(): Boolean {
        NativeBridge.load()
        return NativeBridge.decoyCheck()
    }

    /** Current SDK version, for logs and integration bug reports. */
    @JvmStatic
    val version: String = BuildConstants.VERSION_NAME

    private suspend fun refreshTamperDebugState(state: LeonaRuntimeState): TamperContext {
        val tamperContext = state.channel.prepareTamperContext()
        state.lastIntegritySnapshot.set(tamperContext.integritySnapshot)
        state.lastPolicySnapshot.set(tamperContext.policySnapshot)
        return tamperContext
    }

    private fun parseSnapshotMap(blob: String?): Map<String, String> {
        if (blob.isNullOrBlank()) return emptyMap()
        return buildMap {
            blob.lineSequence()
                .filter { it.isNotBlank() }
                .forEach { line ->
                    val separator = line.indexOf('=')
                    if (separator <= 0) return@forEach
                    val key = line.substring(0, separator).trim()
                    val value = line.substring(separator + 1)
                    if (key.isNotEmpty()) put(key, value)
                }
        }
    }
}

/** Callback for [Leona.senseAsync]. */
interface BoxIdCallback {
    fun onSuccess(boxId: BoxId)
    fun onError(cause: Throwable)
}
