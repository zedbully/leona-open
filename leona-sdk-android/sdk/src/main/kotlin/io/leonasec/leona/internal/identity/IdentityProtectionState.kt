/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import org.json.JSONObject
import java.util.UUID

/**
 * Protection state for local identity material.
 *
 * This is deliberately a typed, low-cardinality status rather than an
 * exception string. It is evidence about the local storage path and is never
 * a client-side allow/deny decision.
 */
internal enum class IdentityProtectionLevel {
    KEYSTORE_AES_GCM,
    EPHEMERAL_MEMORY_ONLY,
    UNSUPPORTED_API,
    KEYSTORE_UNAVAILABLE,
    CORRUPT_OR_MISSING,
}

internal enum class IdentityProtectionCode {
    READY,
    API_BELOW_23,
    KEYSTORE_INIT_FAILED,
    ENVELOPE_INVALID,
    STORAGE_WRITE_FAILED,
}

internal data class IdentityProtectionStatus(
    val level: IdentityProtectionLevel,
    val code: IdentityProtectionCode,
    val durable: Boolean,
    val recoverable: Boolean,
) {
    val isDegraded: Boolean
        get() = level != IdentityProtectionLevel.KEYSTORE_AES_GCM

    companion object {
        val READY = IdentityProtectionStatus(
            level = IdentityProtectionLevel.KEYSTORE_AES_GCM,
            code = IdentityProtectionCode.READY,
            durable = true,
            recoverable = true,
        )
        val API_BELOW_23 = IdentityProtectionStatus(
            level = IdentityProtectionLevel.UNSUPPORTED_API,
            code = IdentityProtectionCode.API_BELOW_23,
            durable = false,
            recoverable = false,
        )
        val KEYSTORE_UNAVAILABLE = IdentityProtectionStatus(
            level = IdentityProtectionLevel.KEYSTORE_UNAVAILABLE,
            code = IdentityProtectionCode.KEYSTORE_INIT_FAILED,
            durable = false,
            recoverable = true,
        )
        val CORRUPT_OR_MISSING = IdentityProtectionStatus(
            level = IdentityProtectionLevel.CORRUPT_OR_MISSING,
            code = IdentityProtectionCode.ENVELOPE_INVALID,
            durable = false,
            recoverable = true,
        )
        val STORAGE_WRITE_FAILED = IdentityProtectionStatus(
            level = IdentityProtectionLevel.EPHEMERAL_MEMORY_ONLY,
            code = IdentityProtectionCode.STORAGE_WRITE_FAILED,
            durable = false,
            recoverable = true,
        )
    }
}

/** Generates non-hardware, process/install scoped identifiers. */
internal object IdentityIdGenerator {
    fun newInstallId(): String = UUID.randomUUID().toString()

    fun newSessionId(): String = "S" + UUID.randomUUID().toString().replace("-", "")
}

/** Only server-minted ids or locally generated UUIDs may enter durable state. */
internal object InstallIdAdmission {
    private val SERVER_PATTERN = Regex("^I[0-9a-f]{32}$")
    private val LOCAL_PATTERN = Regex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
    )

    fun isServer(value: String): Boolean = SERVER_PATTERN.matches(value)

    fun isUsable(value: String): Boolean = SERVER_PATTERN.matches(value) || LOCAL_PATTERN.matches(value)
}

/** One-way install-epoch evidence; missing PackageManager data stays missing. */
internal object InstallLifecycleHint {
    fun sha256(packageName: String, firstInstallTime: Long?): String? {
        val epoch = firstInstallTime?.takeIf { it > 0L }?.toString() ?: return null
        val seed = "$packageName:install-epoch:$epoch"
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(seed.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }
}

/** Pure envelope admission checks used by the store and JVM contract tests. */
internal object IdentityEnvelopePolicy {
    private const val MAX_ENVELOPE_LENGTH = 65_536
    private const val GCM_IV_LENGTH_BYTES = 12
    private const val GCM_TAG_LENGTH_BYTES = 16

    fun isApiSupported(apiLevel: Int): Boolean = apiLevel >= 23

    fun isAuthenticatedEnvelope(stored: String?): Boolean {
        if (stored.isNullOrBlank() || stored.length > MAX_ENVELOPE_LENGTH) return false
        val json = runCatching { JSONObject(stored) }.getOrNull() ?: return false
        if (json.optString("mode") != "keystore") return false
        return runCatching {
            val iv = decodedLengthNoWrap(json.getString("iv"))
            val ciphertext = decodedLengthNoWrap(json.getString("ct"))
            iv == GCM_IV_LENGTH_BYTES && ciphertext >= GCM_TAG_LENGTH_BYTES
        }.getOrDefault(false)
    }

    private fun decodedLengthNoWrap(encoded: String): Int {
        require(encoded.isNotEmpty() && encoded.matches(BASE64_NO_WRAP))
        require(encoded.length % 4 != 1)
        val padding = encoded.count { it == '=' }
        return (encoded.length * 6 / 8) - padding
    }

    private val BASE64_NO_WRAP = Regex("^[A-Za-z0-9+/]*={0,2}$")
}

internal object IdentityPersistencePolicy {
    fun shouldPersistSnapshot(status: IdentityProtectionStatus): Boolean = status.durable

    /**
     * A malformed snapshot is removed synchronously, but its observation stays
     * attached to the current report. If removal fails, the next attempt may
     * retry the quarantine, so the status remains recoverable while recording
     * the storage failure without pretending the snapshot is durable.
     */
    fun statusAfterSnapshotQuarantine(clearSucceeded: Boolean): IdentityProtectionStatus =
        if (clearSucceeded) {
            IdentityProtectionStatus.CORRUPT_OR_MISSING
        } else {
            IdentityProtectionStatus(
                level = IdentityProtectionLevel.CORRUPT_OR_MISSING,
                code = IdentityProtectionCode.STORAGE_WRITE_FAILED,
                durable = false,
                recoverable = true,
            )
        }

    fun statusForNextResolution(
        current: IdentityProtectionStatus,
        snapshotPresent: Boolean,
        quarantineCompleted: Boolean,
    ): IdentityProtectionStatus = if (
        quarantineCompleted &&
        !snapshotPresent &&
        current.level == IdentityProtectionLevel.CORRUPT_OR_MISSING &&
        current.code == IdentityProtectionCode.ENVELOPE_INVALID
    ) {
        IdentityProtectionStatus.READY
    } else {
        current
    }

    fun preserveProbeStatus(
        current: IdentityProtectionStatus,
        probeSucceeded: Boolean,
    ): IdentityProtectionStatus = if (probeSucceeded && current == IdentityProtectionStatus.READY) {
        IdentityProtectionStatus.READY
    } else {
        current
    }
}
