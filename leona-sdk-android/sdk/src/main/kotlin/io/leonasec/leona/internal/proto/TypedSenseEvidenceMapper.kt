/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.proto

import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.NativePayloadInspector
import io.leonasec.leona.internal.identity.DeviceFingerprintSnapshot
import io.leonasec.leona.internal.identity.DeviceFingerprintHasher
import java.nio.charset.StandardCharsets
import java.util.UUID

/**
 * Converts the bounded local observations used by [Leona.sense] into the
 * closed, typed ingest model.  This mapper is deliberately allow-list based:
 * native bytes, identifiers, package names, finding messages, and arbitrary
 * caller metadata never become evidence entries.
 */
internal object TypedSenseEvidenceMapper {

    sealed interface Result {
        data class Success(val request: LeonaEvidenceIngestRequestModel) : Result
        data class Failure(val code: Code, val detail: String) : Result
    }

    enum class Code {
        INVALID_SCOPE,
        INVALID_IDENTITY,
        UNKNOWN_OBSERVATION,
        DUPLICATE_OBSERVATION,
        BOUNDS,
    }

    private const val MAX_OBSERVATIONS = 64

    /**
     * Source labels are intentionally mapped to fixed wire keys.  Keeping the
     * registry closed prevents a future detector from accidentally serializing
     * raw package/device data or an unbounded dynamic map key.
     */
    private val OBSERVATION_KEYS = mapOf(
        "debugger.attached" to "evidence.debugger_attached",
        "developer.options_enabled" to "evidence.developer_options_enabled",
        "developer.adb_enabled" to "evidence.developer_adb_enabled",
        "network.vpn_active" to "evidence.network_vpn_active",
        "network.proxy_configured" to "evidence.network_proxy_configured",
        "accessibility.third_party_enabled" to "evidence.accessibility_third_party_enabled",
        "root.su_or_busybox_path_present" to "evidence.root_su_or_busybox_path_present",
        "root.manager_package_present" to "evidence.root_manager_package_present",
        "environment.emulator.local_heuristic" to "evidence.environment_emulator_local_heuristic",
        "environment.virtual_container.package_present" to "evidence.environment_virtual_container_package_present",
        "installer.not_allowlisted" to "evidence.installer_not_allowlisted",
        "signature.not_allowlisted" to "evidence.signature_not_allowlisted",
        "package.name_mismatch" to "evidence.package_name_mismatch",
        "app.debuggable" to "evidence.app_debuggable",
        "runtime.frida.evidence" to "evidence.runtime_frida",
        "runtime.ptrace.evidence" to "evidence.runtime_ptrace",
        "runtime.injection.evidence" to "evidence.runtime_injection",
        "runtime.xposed.evidence" to "evidence.runtime_xposed",
        "device.root.evidence" to "evidence.device_root",
        "environment.emulator.evidence" to "evidence.environment_emulator",
        "environment.unidbg.evidence" to "evidence.environment_unidbg",
        "app.integrity.evidence" to "evidence.app_integrity",
        "rom.evidence" to "evidence.rom",
        "gsi.evidence" to "evidence.gsi",
        "bootloader.evidence" to "evidence.bootloader",
        "verified_boot.evidence" to "evidence.verified_boot",
        "vbmeta.evidence" to "evidence.vbmeta",
        "build.tags.evidence" to "evidence.build_tags",
        "build.type.evidence" to "evidence.build_type",
    )

    fun map(
        config: LeonaConfig,
        snapshot: DeviceFingerprintSnapshot,
        nativeRisk: NativePayloadInspector.NativeRiskSummary,
        nowEpochMs: Long = System.currentTimeMillis(),
        requestId: String = UUID.randomUUID().toString(),
        nonce: ByteArray = UUID.randomUUID().toString().toByteArray(StandardCharsets.US_ASCII),
    ): Result {
        val tenantId = config.tenantId?.takeIf { it.isNotBlank() }
            ?: return Result.Failure(Code.INVALID_SCOPE, "tenant scope is required")
        val environment = config.environment?.takeIf { it.isNotBlank() }
            ?: return Result.Failure(Code.INVALID_SCOPE, "environment scope is required")
        if (!InstallIdShape.isUsable(snapshot.installId) || !SessionIdShape.isUsable(snapshot.sessionId)) {
            return Result.Failure(Code.INVALID_IDENTITY, "opaque install/session reference is invalid")
        }
        if (!snapshot.identityProtectionStatus.isSemanticallyCoherent()) {
            return Result.Failure(Code.INVALID_IDENTITY, "identity protection status is incoherent")
        }
        if (nowEpochMs < 0L || snapshot.sdkInt !in 23..36) {
            return Result.Failure(Code.BOUNDS, "timestamp or Android API level is outside profile")
        }
        if (snapshot.fingerprintSchemaVersion !in 1..16) {
            return Result.Failure(Code.BOUNDS, "fingerprint schema version outside bound")
        }
        val fingerprintDigest = decodeDigest(snapshot.fingerprintHash)
            ?: return Result.Failure(Code.INVALID_IDENTITY, "fingerprint hash is not a lowercase SHA-256")
        if (snapshot.fingerprintSource !in FINGERPRINT_SOURCES || snapshot.identityAnchorSource !in ANCHOR_SOURCES) {
            return Result.Failure(Code.INVALID_IDENTITY, "fingerprint source is not in the frozen registry")
        }
        val lifecycleDigest = snapshot.installLifecycleSha256?.let(::decodeDigest)
        if (snapshot.installLifecycleSha256 != null && lifecycleDigest == null) {
            return Result.Failure(Code.INVALID_IDENTITY, "install lifecycle hash is not a lowercase SHA-256")
        }

        val sourceIds = snapshot.evidenceSignals.toList() + nativeRisk.factTags.toList()
        val duplicate = sourceIds.groupingBy { it }.eachCount().entries.firstOrNull { it.value > 1 }?.key
        if (duplicate != null) return Result.Failure(Code.DUPLICATE_OBSERVATION, "duplicate observation")

        val mapped = mutableListOf<LeonaEvidenceEntryModel>()
        mapped += entry("android.sdk_int", nowEpochMs, LeonaEvidenceValue.Int(snapshot.sdkInt.toLong()))
        mapped += entry("identity.fingerprint_schema_version", nowEpochMs, LeonaEvidenceValue.Int(snapshot.fingerprintSchemaVersion.toLong()))
        mapped += entry("identity.fingerprint_sha256", nowEpochMs, LeonaEvidenceValue.Bytes(fingerprintDigest), LeonaEvidenceQualityValue.REDACTED)
        mapped += entry("identity.fingerprint_source", nowEpochMs, LeonaEvidenceValue.StringValue(snapshot.fingerprintSource))
        mapped += entry("identity.anchor_source", nowEpochMs, LeonaEvidenceValue.StringValue(snapshot.identityAnchorSource))
        lifecycleDigest?.let { mapped += entry("identity.install_lifecycle_sha256", nowEpochMs, LeonaEvidenceValue.Bytes(it), LeonaEvidenceQualityValue.REDACTED) }
        mapped += entry("identity.protection.durable", nowEpochMs, LeonaEvidenceValue.Bool(snapshot.identityProtectionStatus.durable))
        mapped += entry("identity.protection.recoverable", nowEpochMs, LeonaEvidenceValue.Bool(snapshot.identityProtectionStatus.recoverable))
        mapped += entry("identity.protection.level", nowEpochMs, LeonaEvidenceValue.StringValue(snapshot.identityProtectionStatus.level.name))
        mapped += entry("identity.protection.code", nowEpochMs, LeonaEvidenceValue.StringValue(snapshot.identityProtectionStatus.code.name))
        if (nativeRisk.eventCount < 0) return Result.Failure(Code.BOUNDS, "native event count outside bound")
        mapped += entry("native.event_count", nowEpochMs, LeonaEvidenceValue.Int(nativeRisk.eventCount.toLong()))
        nativeRisk.highestSeverity?.let {
            if (it !in 0..255) return Result.Failure(Code.BOUNDS, "native severity outside bound")
            mapped += entry("native.highest_severity", nowEpochMs, LeonaEvidenceValue.Int(it.toLong()))
        }
        for (sourceId in sourceIds.sorted()) {
            val key = OBSERVATION_KEYS[sourceId]
                ?: return Result.Failure(Code.UNKNOWN_OBSERVATION, "observation is not in the frozen registry")
            mapped += entry(key, nowEpochMs, LeonaEvidenceValue.Bool(true))
        }
        if (mapped.map { it.key }.toSet().size != mapped.size) {
            return Result.Failure(Code.DUPLICATE_OBSERVATION, "duplicate wire observation key")
        }
        if (mapped.size > MAX_OBSERVATIONS) return Result.Failure(Code.BOUNDS, "observation count exceeds bound")
        val entries = mapped.sortedBy { it.key }
        return Result.Success(
            LeonaEvidenceIngestRequestModel(
                protocolMajor = 1,
                tenantId = tenantId,
                appId = config.appId,
                environmentId = environment,
                installId = snapshot.installId,
                sessionId = snapshot.sessionId,
                requestId = requestId,
                nonce = nonce.copyOf(),
                idempotencyKey = "sense-${requestId.replace("-", "")}",
                issuedAtEpochMs = nowEpochMs,
                clientScope = LeonaClientScopeModel(tenantId, config.appId, environment),
                entries = entries,
            ),
        )
    }

    private fun entry(
        key: String,
        observedAt: Long,
        value: LeonaEvidenceValue,
        quality: LeonaEvidenceQualityValue = LeonaEvidenceQualityValue.RAW,
    ) =
        LeonaEvidenceEntryModel(
            key = key,
            observedAtEpochMs = observedAt,
            source = LeonaEvidenceSourceValue.ANDROID,
            quality = quality,
            value = value,
        )

    private fun decodeDigest(value: String): ByteArray? {
        if (!value.matches(Regex("^[0-9a-f]{64}$"))) return null
        return ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private val FINGERPRINT_SOURCES = setOf(
        DeviceFingerprintHasher.FINGERPRINT_SOURCE_BASE_V2,
        DeviceFingerprintHasher.FINGERPRINT_SOURCE_VIRTUAL_ANCHOR_V4,
    )
    private val ANCHOR_SOURCES = setOf(
        DeviceFingerprintHasher.ANCHOR_SOURCE_ANDROID_ID,
        DeviceFingerprintHasher.ANCHOR_SOURCE_DEVICE_PROFILE,
        DeviceFingerprintHasher.ANCHOR_SOURCE_VIRTUAL_INSTANCE,
    )

    private object InstallIdShape {
        private val LOCAL = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
        private val SERVER = Regex("^I[0-9a-f]{32}$")
        fun isUsable(value: String): Boolean = LOCAL.matches(value) || SERVER.matches(value)
    }

    private object SessionIdShape {
        private val SESSION = Regex("^S[0-9a-f]{32}$")
        fun isUsable(value: String): Boolean = SESSION.matches(value)
    }
}
