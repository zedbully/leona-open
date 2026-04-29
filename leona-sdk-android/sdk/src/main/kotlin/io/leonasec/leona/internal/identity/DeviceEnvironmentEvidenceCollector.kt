/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import android.os.Build
import io.leonasec.leona.LeonaDeviceEnvironmentEvidence
import java.security.MessageDigest
import java.util.Locale

internal object DeviceEnvironmentEvidenceCollector {

    fun collect(): LeonaDeviceEnvironmentEvidence = summarize(
        BuildProfile(
            tags = Build.TAGS.orEmpty(),
            type = Build.TYPE.orEmpty(),
            fingerprint = Build.FINGERPRINT.orEmpty(),
            brand = Build.BRAND.orEmpty(),
            manufacturer = Build.MANUFACTURER.orEmpty(),
            product = Build.PRODUCT.orEmpty(),
            device = Build.DEVICE.orEmpty(),
            model = Build.MODEL.orEmpty(),
            display = Build.DISPLAY.orEmpty(),
            incremental = Build.VERSION.INCREMENTAL.orEmpty(),
            verifiedBootState = systemProperty("ro.boot.verifiedbootstate"),
            vbmetaDeviceState = systemProperty("ro.boot.vbmeta.device_state"),
            flashLocked = systemProperty("ro.boot.flash.locked"),
            verityMode = systemProperty("ro.boot.veritymode"),
            gsiImageRunning = systemProperty("ro.gsid.image_running"),
            systemProductName = systemProperty("ro.product.system.name"),
            systemProductBrand = systemProperty("ro.product.system.brand"),
            systemProductDevice = systemProperty("ro.product.system.device"),
        ),
    )

    internal fun summarize(profile: BuildProfile): LeonaDeviceEnvironmentEvidence {
        val evidenceIds = linkedSetOf<String>()
        val build = linkedMapOf<String, String>()
        val bootloader = linkedMapOf<String, String>()
        val verifiedBoot = linkedMapOf<String, String>()
        val rom = linkedMapOf<String, String>()
        val gsi = linkedMapOf<String, String>()

        profile.tags.takeIf(String::isNotBlank)?.let { tags ->
            build["tags"] = tags
            tags.split(',', ' ')
                .map { it.trim().lowercase(Locale.ROOT) }
                .filter(String::isNotBlank)
                .forEach { tag ->
                    when (tag) {
                        "test-keys" -> evidenceIds += "build.tags.test_keys"
                        "dev-keys" -> evidenceIds += "build.tags.dev_keys"
                    }
                }
        }
        profile.type.takeIf(String::isNotBlank)?.let { type ->
            build["type"] = type
            when (type.lowercase(Locale.ROOT)) {
                "userdebug", "eng" -> evidenceIds += "build.type.userdebug_or_eng"
            }
        }
        profile.fingerprint.takeIf(String::isNotBlank)?.let { fingerprint ->
            build["fingerprintSha256"] = sha256Hex(fingerprint)
        }
        putIfPresent(build, "brand", profile.brand)
        putIfPresent(build, "manufacturer", profile.manufacturer)
        putIfPresent(build, "product", profile.product)
        putIfPresent(build, "device", profile.device)
        putIfPresent(build, "model", profile.model)

        putIfPresent(bootloader, "vbmetaDeviceState", profile.vbmetaDeviceState)
        putIfPresent(bootloader, "flashLocked", profile.flashLocked)
        val vbmetaState = profile.vbmetaDeviceState?.lowercase(Locale.ROOT)
        val flashLocked = profile.flashLocked?.lowercase(Locale.ROOT)
        if (vbmetaState == "unlocked" || flashLocked == "0" || flashLocked == "false") {
            evidenceIds += "bootloader.unlocked"
        }

        profile.verifiedBootState?.lowercase(Locale.ROOT)?.let { state ->
            verifiedBoot["state"] = state
            evidenceIds += "verified_boot.${state.toEvidenceSegment()}"
            if (state == "orange") evidenceIds += "bootloader.unlocked"
        }
        profile.verityMode?.lowercase(Locale.ROOT)?.let { mode ->
            verifiedBoot["verityMode"] = mode
            evidenceIds += "verified_boot.veritymode_${mode.toEvidenceSegment()}"
        }

        if (isTruthy(profile.gsiImageRunning)) {
            evidenceIds += "gsi.running"
            gsi["imageRunning"] = "true"
        } else {
            putIfPresent(gsi, "imageRunning", profile.gsiImageRunning)
        }
        putIfPresent(gsi, "systemProductName", profile.systemProductName)
        putIfPresent(gsi, "systemProductBrand", profile.systemProductBrand)
        putIfPresent(gsi, "systemProductDevice", profile.systemProductDevice)

        val haystack = listOf(
            profile.fingerprint,
            profile.display,
            profile.incremental,
            profile.product,
            profile.device,
            profile.brand,
            profile.manufacturer,
            profile.systemProductName.orEmpty(),
            profile.systemProductBrand.orEmpty(),
            profile.systemProductDevice.orEmpty(),
        ).joinToString(" ").lowercase(Locale.ROOT)
        knownRomSignals.forEach { (needle, evidenceId) ->
            if (haystack.contains(needle)) evidenceIds += evidenceId
        }
        if (evidenceIds.any { it.startsWith("build.tags.") || it == "build.type.userdebug_or_eng" } ||
            evidenceIds.any { it.startsWith("rom.") || it.startsWith("gsi.") }
        ) {
            evidenceIds += "rom.custom_aosp_like"
        }
        val romIds = evidenceIds.filter { it.startsWith("rom.") }.sorted()
        if (romIds.isNotEmpty()) rom["signals"] = romIds.joinToString(",")

        return LeonaDeviceEnvironmentEvidence(
            evidenceIds = evidenceIds,
            build = build,
            bootloader = bootloader,
            verifiedBoot = verifiedBoot,
            rom = rom,
            gsi = gsi,
        )
    }

    internal data class BuildProfile(
        val tags: String = "",
        val type: String = "",
        val fingerprint: String = "",
        val brand: String = "",
        val manufacturer: String = "",
        val product: String = "",
        val device: String = "",
        val model: String = "",
        val display: String = "",
        val incremental: String = "",
        val verifiedBootState: String? = null,
        val vbmetaDeviceState: String? = null,
        val flashLocked: String? = null,
        val verityMode: String? = null,
        val gsiImageRunning: String? = null,
        val systemProductName: String? = null,
        val systemProductBrand: String? = null,
        val systemProductDevice: String? = null,
    )

    private fun putIfPresent(target: MutableMap<String, String>, key: String, value: String?) {
        value?.trim()?.takeIf(String::isNotEmpty)?.let { target[key] = it }
    }

    private fun isTruthy(value: String?): Boolean =
        value?.trim()?.lowercase(Locale.ROOT) in setOf("1", "true", "yes", "y")

    private fun String.toEvidenceSegment(): String =
        lowercase(Locale.ROOT).replace(Regex("[^a-z0-9]+"), "_").trim('_').ifBlank { "unknown" }

    private fun sha256Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun systemProperty(key: String): String? = runCatching {
        val clazz = Class.forName("android.os.SystemProperties")
        clazz.getMethod("get", String::class.java).invoke(null, key) as? String
    }.getOrNull()?.trim()?.ifEmpty { null }

    private val knownRomSignals = listOf(
        "lineage" to "rom.lineageos_like",
        "crdroid" to "rom.crdroid_like",
        "pixel experience" to "rom.pixelexperience_like",
        "pixelexperience" to "rom.pixelexperience_like",
        "pixelos" to "rom.pixelos_like",
        "graphene" to "rom.grapheneos_like",
        "calyx" to "rom.calyxos_like",
        "evolution" to "rom.evolutionx_like",
        "omni" to "rom.omnirom_like",
        "paranoid" to "rom.paranoidandroid_like",
        "aosp" to "rom.aosp_like",
        "generic" to "rom.generic_aosp_like",
    )
}
