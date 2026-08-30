/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import io.leonasec.leona.LeonaDeviceEnvironmentEvidence
import io.leonasec.leona.internal.ClientEvidenceSignalMapper
import org.json.JSONArray
import org.json.JSONObject

internal data class DeviceFingerprintSnapshot(
    val fingerprintSchemaVersion: Int = DeviceFingerprintHasher.CACHE_SCHEMA_VERSION,
    val generatedAtMillis: Long,
    val installId: String,
    val canonicalDeviceId: String?,
    val resolvedDeviceId: String,
    val fingerprintHash: String,
    val fingerprintSource: String = "unknown",
    val identityAnchorSource: String = "unknown",
    val canonicalDeviceIdSource: String = "unknown",
    val packageName: String,
    val appVersionName: String?,
    val appVersionCode: Long,
    val installerPackage: String?,
    val androidId: String?,
    val signingCertSha256: List<String>,
    val brand: String,
    val model: String,
    val manufacturer: String,
    val sdkInt: Int,
    val abis: List<String>,
    val localeTag: String,
    val timeZoneId: String,
    val screenSummary: String?,
    val riskSignals: Set<String>,
    val deviceEnvironmentEvidence: LeonaDeviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.EMPTY,
    /** One-way app-install lifecycle handle used only for server install-id recovery. */
    val installLifecycleSha256: String? = null,
    /** Process-scoped correlation id; never persisted as install identity. */
    val sessionId: String = "",
    /** Typed evidence about how local identity state was protected. */
    val identityProtectionStatus: IdentityProtectionStatus = IdentityProtectionStatus.READY,
) {
    val evidenceSignals: Set<String>
        get() = ClientEvidenceSignalMapper.toEvidenceSignals(riskSignals)

    fun toJson(): String = JSONObject()
        .put("fingerprintSchemaVersion", fingerprintSchemaVersion)
        .put("generatedAtMillis", generatedAtMillis)
        .put("installId", installId)
        .put("canonicalDeviceId", canonicalDeviceId)
        .put("resolvedDeviceId", resolvedDeviceId)
        .put("fingerprintHash", fingerprintHash)
        .put("fingerprintSource", fingerprintSource)
        .put("identityAnchorSource", identityAnchorSource)
        .put("canonicalDeviceIdSource", canonicalDeviceIdSource)
        .put("packageName", packageName)
        .put("appVersionName", appVersionName)
        .put("appVersionCode", appVersionCode)
        .put("installerPackage", installerPackage)
        .put("androidId", androidId)
        .put("signingCertSha256", JSONArray(signingCertSha256))
        .put("brand", brand)
        .put("model", model)
        .put("manufacturer", manufacturer)
        .put("sdkInt", sdkInt)
        .put("abis", JSONArray(abis))
        .put("localeTag", localeTag)
        .put("timeZoneId", timeZoneId)
        .put("screenSummary", screenSummary)
        .put("riskSignals", JSONArray(riskSignals.toList().sorted()))
        .put("deviceEnvironmentEvidence", deviceEnvironmentEvidence.toPersistedJsonObject())
        .put("installLifecycleSha256", installLifecycleSha256)
        // sessionId is process-scoped and intentionally omitted from durable
        // identity JSON. It is attached after loading for the current process.
        .put("identityProtectionLevel", identityProtectionStatus.level.name)
        .put("identityProtectionCode", identityProtectionStatus.code.name)
        .put("identityProtectionDurable", identityProtectionStatus.durable)
        .put("identityProtectionRecoverable", identityProtectionStatus.recoverable)
        .toString()

    companion object {
        fun fromJson(
            json: String?,
            expectedPackageName: String? = null,
        ): DeviceFingerprintSnapshot? {
            if (json.isNullOrBlank()) return null
            return runCatching {
                val obj = JSONObject(json)
                validateSemantics(obj, expectedPackageName)
                DeviceFingerprintSnapshot(
                    fingerprintSchemaVersion = obj.requiredInt("fingerprintSchemaVersion"),
                    generatedAtMillis = obj.requiredLong("generatedAtMillis"),
                    installId = obj.requiredString("installId"),
                    canonicalDeviceId = obj.nullableString("canonicalDeviceId"),
                    resolvedDeviceId = obj.requiredString("resolvedDeviceId"),
                    fingerprintHash = obj.requiredString("fingerprintHash"),
                    fingerprintSource = obj.requiredNonBlankString("fingerprintSource"),
                    identityAnchorSource = obj.requiredNonBlankString("identityAnchorSource"),
                    canonicalDeviceIdSource = obj.requiredNonBlankString("canonicalDeviceIdSource"),
                    packageName = obj.requiredString("packageName"),
                    appVersionName = obj.nullableString("appVersionName"),
                    appVersionCode = obj.requiredLong("appVersionCode"),
                    installerPackage = obj.nullableString("installerPackage"),
                    androidId = obj.nullableString("androidId"),
                    signingCertSha256 = obj.requiredStringArray("signingCertSha256"),
                    brand = obj.requiredString("brand"),
                    model = obj.requiredString("model"),
                    manufacturer = obj.requiredString("manufacturer"),
                    sdkInt = obj.requiredInt("sdkInt"),
                    abis = obj.requiredStringArray("abis"),
                    localeTag = obj.requiredString("localeTag"),
                    timeZoneId = obj.requiredString("timeZoneId"),
                    screenSummary = obj.nullableString("screenSummary"),
                    riskSignals = obj.requiredStringArray("riskSignals").toSet(),
                    deviceEnvironmentEvidence = LeonaDeviceEnvironmentEvidence.fromJsonObject(
                        obj.requiredObject("deviceEnvironmentEvidence"),
                    ),
                    installLifecycleSha256 = obj.nullableString("installLifecycleSha256"),
                    // Session ids are process-only; ignore any legacy persisted
                    // field rather than resurrecting it across a restart.
                    sessionId = "",
                    identityProtectionStatus = parseProtectionStatus(obj),
                )
            }.getOrNull()
        }

        private fun validateSemantics(obj: JSONObject, expectedPackageName: String?) {
            val fingerprintSchemaVersion = obj.requiredInt("fingerprintSchemaVersion")
            require(fingerprintSchemaVersion == DeviceFingerprintHasher.CACHE_SCHEMA_VERSION)
            require(obj.requiredLong("generatedAtMillis") > 0L)

            val installId = obj.requiredString("installId")
            require(InstallIdAdmission.isUsable(installId))

            val canonicalDeviceId = obj.nullableString("canonicalDeviceId")
            if (canonicalDeviceId != null) require(CanonicalIdAdmission.isUsable(canonicalDeviceId))

            val resolvedDeviceId = obj.requiredString("resolvedDeviceId")
            if (canonicalDeviceId != null) {
                require(resolvedDeviceId == canonicalDeviceId)
            } else {
                require(TEMPORARY_DEVICE_ID_PATTERN.matches(resolvedDeviceId))
            }
            require(HASH64_PATTERN.matches(obj.requiredString("fingerprintHash")))
            require(obj.requiredNonBlankString("fingerprintSource").length <= 128)
            require(obj.requiredNonBlankString("identityAnchorSource").length <= 128)
            require(obj.requiredNonBlankString("canonicalDeviceIdSource").length <= 128)

            val packageName = obj.requiredString("packageName")
            require(PACKAGE_NAME_PATTERN.matches(packageName))
            if (expectedPackageName != null) require(packageName == expectedPackageName)

            obj.nullableString("appVersionName")?.let { require(it.length <= 256) }
            require(obj.requiredLong("appVersionCode") >= 0L)
            obj.nullableString("installerPackage")?.let { require(it.length <= 256) }
            obj.nullableString("androidId")?.let { require(it.length <= 256) }

            val signingCerts = obj.requiredStringArray("signingCertSha256")
            require(signingCerts.all(HASH64_PATTERN::matches))
            require(obj.requiredString("brand").length <= 256)
            require(obj.requiredString("model").length <= 256)
            require(obj.requiredString("manufacturer").length <= 256)
            require(obj.requiredInt("sdkInt") in 23..36)
            require(obj.requiredStringArray("abis").all { ABI_PATTERN.matches(it) })
            require(obj.requiredString("localeTag").length <= 128)
            require(obj.requiredString("timeZoneId").length <= 128)
            obj.nullableString("screenSummary")?.let { require(it.length <= 128) }
            require(obj.requiredStringArray("riskSignals").all { it.length <= 256 })

            validateEnvironmentObject(obj.requiredObject("deviceEnvironmentEvidence"))
            obj.nullableString("installLifecycleSha256")?.let { require(HASH64_PATTERN.matches(it)) }
            parseProtectionStatus(obj)
        }

        private fun validateEnvironmentObject(obj: JSONObject) {
            requireStringArray(obj, "evidenceIds")
            listOf("build", "bootloader", "verifiedBoot", "rom", "gsi").forEach { key ->
                val nested = obj.requiredObject(key)
                nested.keys().forEach { nestedKey ->
                    require(nestedKey.isNotBlank())
                    require(nested.opt(nestedKey) is String)
                }
            }
        }

        private fun requireStringArray(obj: JSONObject, key: String): List<String> {
            val array = obj.requiredArray(key)
            return buildList {
                for (index in 0 until array.length()) {
                    val value = array.get(index) as? String ?: error("$key[$index] type")
                    require(value.isNotBlank())
                    add(value)
                }
            }
        }

        private fun JSONObject.requiredStringArray(key: String): List<String> =
            requireStringArray(this, key)

        private fun JSONObject.requiredObject(key: String): JSONObject =
            get(key) as? JSONObject ?: error("$key type")

        private fun JSONObject.requiredArray(key: String): JSONArray =
            get(key) as? JSONArray ?: error("$key type")

        private fun JSONObject.requiredString(key: String): String =
            get(key) as? String ?: error("$key type")

        private fun JSONObject.requiredNonBlankString(key: String): String =
            requiredString(key).also { require(it.isNotBlank()) }

        private fun JSONObject.nullableString(key: String): String? {
            if (!has(key) || isNull(key)) return null
            return get(key) as? String ?: error("$key type")
        }

        private fun JSONObject.requiredLong(key: String): Long {
            val value = get(key) as? Number ?: error("$key type")
            val result = value.toLong()
            require(value.toDouble() == result.toDouble())
            return result
        }

        private fun JSONObject.requiredInt(key: String): Int {
            val value = requiredLong(key)
            require(value in Int.MIN_VALUE..Int.MAX_VALUE)
            return value.toInt()
        }

        private fun parseProtectionStatus(obj: JSONObject): IdentityProtectionStatus {
            val keys = listOf(
                "identityProtectionLevel",
                "identityProtectionCode",
                "identityProtectionDurable",
                "identityProtectionRecoverable",
            )
            if (keys.none(obj::has)) return IdentityProtectionStatus.READY
            require(keys.all(obj::has))
            val level = runCatching { IdentityProtectionLevel.valueOf(obj.requiredString("identityProtectionLevel")) }
                .getOrElse { error("identity protection level") }
            val code = runCatching { IdentityProtectionCode.valueOf(obj.requiredString("identityProtectionCode")) }
                .getOrElse { error("identity protection code") }
            val durable = obj.get("identityProtectionDurable") as? Boolean ?: error("identity durable type")
            val recoverable = obj.get("identityProtectionRecoverable") as? Boolean
                ?: error("identity recoverable type")
            return IdentityProtectionStatus(level, code, durable, recoverable).also {
                require(it.isSemanticallyCoherent())
            }
        }

        private val HASH64_PATTERN = Regex("^[0-9a-f]{64}$")
        private val TEMPORARY_DEVICE_ID_PATTERN = Regex("^T[A-Za-z0-9_-]{43}$")
        private val PACKAGE_NAME_PATTERN = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)+$")
        private val ABI_PATTERN = Regex("^[A-Za-z0-9._-]+$")
    }
}
