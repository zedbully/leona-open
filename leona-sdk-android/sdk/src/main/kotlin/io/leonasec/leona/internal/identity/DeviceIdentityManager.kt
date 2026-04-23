/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.util.Base64
import io.leonasec.leona.config.LeonaConfig
import java.security.MessageDigest
import java.net.NetworkInterface
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

internal class DeviceIdentityManager(
    private val context: Context,
    private val config: LeonaConfig,
) {
    private val appContext = context.applicationContext
    private val store = LeonaIdentityStore(appContext)

    @Synchronized
    fun resolve(policy: CollectionPolicy = CollectionPolicy()): DeviceFingerprintSnapshot {
        val cached = store.loadLastSnapshot()
        val persistedCanonicalDeviceId = store.loadCanonicalDeviceId()
        if (policy.disableCollectionWindowMs >= 0 && cached != null && cached.canonicalDeviceId == persistedCanonicalDeviceId) {
            val age = System.currentTimeMillis() - cached.generatedAtMillis
            if (age in 0..policy.disableCollectionWindowMs) {
                return cached
            }
        }

        val installId = store.loadInstallId() ?: UUID.randomUUID().toString().also(store::persistInstallId)
        val canonicalDeviceId = persistedCanonicalDeviceId
        val packageInfo = packageInfo()
        val androidId = if ("androidId" in policy.disabledSignals) null else loadAndroidId()
        val signingCerts = if ("signingCert" in policy.disabledSignals) emptyList() else loadSigningCertDigests()
        val installerPackage = if ("installer" in policy.disabledSignals) null else loadInstallerPackage()
        val riskSignals = collectRiskSignals(
            policy = policy,
            packageInfo = packageInfo,
            signingCerts = signingCerts,
            installerPackage = installerPackage,
        )
        val localeTag = Locale.getDefault().toLanguageTag()
        val timeZoneId = TimeZone.getDefault().id
        val screenSummary = if ("screen" in policy.disabledSignals) null else runCatching {
            val metrics = appContext.resources.displayMetrics
            "${metrics.widthPixels}x${metrics.heightPixels}@${metrics.densityDpi}"
        }.getOrNull()

        val fingerprintSeed = linkedMapOf(
            "tenantId" to config.tenantId.orEmpty(),
            "appId" to config.appId,
            "packageName" to appContext.packageName,
            "identityAnchor" to buildIdentityAnchor(androidId, installId),
            "signingCerts" to signingCerts.joinToString(","),
            "installerPackage" to installerPackage.orEmpty(),
            "brand" to Build.BRAND.orEmpty(),
            "model" to Build.MODEL.orEmpty(),
            "manufacturer" to Build.MANUFACTURER.orEmpty(),
            "sdkInt" to Build.VERSION.SDK_INT.toString(),
            "abis" to Build.SUPPORTED_ABIS.joinToString(","),
            "locale" to localeTag,
            "timezone" to timeZoneId,
            "riskSignals" to riskSignals.toList().sorted().joinToString(","),
            "extraInfo" to (config.extraInfo ?: ""),
        )
        val fingerprintHash = sha256Hex(canonicalizeMap(fingerprintSeed).toByteArray())
        val resolvedDeviceId = canonicalDeviceId?.let(::normalizeCanonicalId)
            ?: buildTemporaryDeviceId(
                tenantId = config.tenantId,
                appId = config.appId,
                packageName = appContext.packageName,
                signingCerts = signingCerts,
                androidId = androidId,
                installId = installId,
                fingerprintHash = fingerprintHash,
            )

        val snapshot = DeviceFingerprintSnapshot(
            generatedAtMillis = System.currentTimeMillis(),
            installId = installId,
            canonicalDeviceId = canonicalDeviceId,
            resolvedDeviceId = resolvedDeviceId,
            fingerprintHash = fingerprintHash,
            packageName = appContext.packageName,
            appVersionName = packageInfo?.versionName,
            appVersionCode = packageInfo.versionCodeCompat,
            installerPackage = installerPackage,
            androidId = androidId,
            signingCertSha256 = signingCerts,
            brand = Build.BRAND.orEmpty(),
            model = Build.MODEL.orEmpty(),
            manufacturer = Build.MANUFACTURER.orEmpty(),
            sdkInt = Build.VERSION.SDK_INT,
            abis = Build.SUPPORTED_ABIS?.toList().orEmpty(),
            localeTag = localeTag,
            timeZoneId = timeZoneId,
            screenSummary = screenSummary,
            riskSignals = riskSignals,
        )
        store.persistLastSnapshot(snapshot)
        return snapshot
    }

    fun currentSnapshot(): DeviceFingerprintSnapshot? = store.loadLastSnapshot()

    fun updateCanonicalDeviceId(deviceId: String?) {
        val normalized = deviceId?.trim()?.ifEmpty { null } ?: return
        store.persistCanonicalDeviceId(stripKnownPrefix(normalized))
    }

    private fun buildIdentityAnchor(androidId: String?, installId: String): String =
        when {
            !androidId.isNullOrBlank() -> "android:$androidId"
            else -> "install:$installId"
        }

    private fun buildTemporaryDeviceId(
        tenantId: String?,
        appId: String,
        packageName: String,
        signingCerts: List<String>,
        androidId: String?,
        installId: String,
        fingerprintHash: String,
    ): String {
        val seed = linkedMapOf(
            "tenantId" to tenantId.orEmpty(),
            "appId" to appId,
            "packageName" to packageName,
            "signingCerts" to signingCerts.joinToString(","),
            "androidId" to androidId.orEmpty(),
            "installId" to installId,
            "fingerprintHash" to fingerprintHash,
        )
        return "T" + base64UrlNoPadding(sha256(canonicalizeMap(seed).toByteArray()))
    }

    private fun collectRiskSignals(
        policy: CollectionPolicy,
        packageInfo: PackageInfo?,
        signingCerts: List<String>,
        installerPackage: String?,
    ): Set<String> = buildSet {
        if ("root" !in policy.disabledSignals && isBasicRootLikely()) add("root.basic")
        if ("rootPackages" !in policy.disabledSignals && hasKnownRootPackages()) add("root.packages")
        if ("emulator" !in policy.disabledSignals && isEmulatorLikely()) add("environment.emulator")
        if ("debugger" !in policy.disabledSignals && Debug.isDebuggerConnected()) add("debugger.attached")
        if ("developerOptions" !in policy.disabledSignals && isDeveloperOptionsEnabled()) add("developer.options_enabled")
        if ("adb" !in policy.disabledSignals && isAdbEnabled()) add("developer.adb_enabled")
        if ("vpn" !in policy.disabledSignals && isVpnActive()) add("network.vpn_active")
        if ("proxy" !in policy.disabledSignals && isProxyConfigured()) add("network.proxy_configured")
        if ("accessibility" !in policy.disabledSignals && hasThirdPartyAccessibilityServicesEnabled()) {
            add("accessibility.third_party_enabled")
        }
        if ("virtualContainer" !in policy.disabledSignals && hasKnownVirtualContainerPackages()) {
            add("environment.virtual_container")
        }
        if ("packageName" !in policy.disabledSignals &&
            config.expectedPackageName != null &&
            config.expectedPackageName != appContext.packageName
        ) {
            add("package.name_mismatch")
        }
        if ("installerTrust" !in policy.disabledSignals &&
            config.allowedInstallerPackages.isNotEmpty() &&
            installerPackage != null &&
            installerPackage !in config.allowedInstallerPackages
        ) {
            add("installer.untrusted")
        }
        if ("signingCertTrust" !in policy.disabledSignals &&
            config.allowedSigningCertSha256.isNotEmpty() &&
            signingCerts.isNotEmpty() &&
            signingCerts.none { it in config.allowedSigningCertSha256 }
        ) {
            add("signature.untrusted")
        }
        if ("debuggable" !in policy.disabledSignals &&
            packageInfo?.applicationInfo?.flags?.and(android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        ) {
            add("app.debuggable")
        }
    }

    private fun isBasicRootLikely(): Boolean {
        val suspiciousPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk",
            "/system/bin/.ext/.su",
            "/system/usr/we-need-root/su-backup",
            "/system/xbin/daemonsu",
            "/su/bin/su",
            "/system/bin/busybox",
            "/system/xbin/busybox",
        )
        if (suspiciousPaths.any { path -> runCatching { java.io.File(path).exists() }.getOrDefault(false) }) {
            return true
        }
        return Build.TAGS?.contains("test-keys", ignoreCase = true) == true
    }

    private fun hasKnownRootPackages(): Boolean {
        val knownPackages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.saurik.substrate",
            "de.robv.android.xposed.installer",
            "org.lsposed.manager",
        )
        return knownPackages.any(::isPackageInstalled)
    }

    private fun hasKnownVirtualContainerPackages(): Boolean {
        val knownPackages = listOf(
            "com.lbe.parallel",
            "com.parallel.space",
            "com.parallel.space.pro",
            "com.excean.dualaid",
            "com.excelliance.multiaccounts",
            "com.applisto.appcloner",
            "com.app.hider.master.dual.app",
            "com.polestar.super.clone",
            "com.vphonegaga.titan",
            "io.virtualapp",
            "com.lody.virtual",
        )
        return knownPackages.any(::isPackageInstalled)
    }

    private fun isEmulatorLikely(): Boolean {
        val fingerprint = Build.FINGERPRINT.orEmpty().lowercase()
        val model = Build.MODEL.orEmpty().lowercase()
        val manufacturer = Build.MANUFACTURER.orEmpty().lowercase()
        val hardware = Build.HARDWARE.orEmpty().lowercase()
        val product = Build.PRODUCT.orEmpty().lowercase()
        return fingerprint.contains("generic") ||
            fingerprint.contains("emulator") ||
            fingerprint.contains("vbox") ||
            model.contains("sdk_gphone") ||
            model.contains("emulator") ||
            model.contains("android sdk built for") ||
            manufacturer.contains("genymotion") ||
            hardware.contains("goldfish") ||
            hardware.contains("ranchu") ||
            hardware.contains("vbox86") ||
            product.contains("sdk") ||
            product.contains("emulator") ||
            product.contains("simulator")
    }

    private fun isDeveloperOptionsEnabled(): Boolean = runCatching {
        Settings.Global.getInt(appContext.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
    }.getOrDefault(false)

    private fun isAdbEnabled(): Boolean = runCatching {
        Settings.Global.getInt(appContext.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
    }.getOrDefault(false)

    private fun isProxyConfigured(): Boolean = runCatching {
        val host = System.getProperty("http.proxyHost")?.trim().orEmpty()
        val port = System.getProperty("http.proxyPort")?.trim().orEmpty()
        host.isNotEmpty() || port.isNotEmpty()
    }.getOrDefault(false)

    private fun hasThirdPartyAccessibilityServicesEnabled(): Boolean = runCatching {
        val enabled = Settings.Secure.getString(
            appContext.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ).orEmpty()
        if (enabled.isBlank()) return@runCatching false
        enabled.split(':')
            .map { it.substringBefore('/').trim() }
            .filter { it.isNotEmpty() }
            .any { servicePackage ->
                val appInfo = packageInfoFor(servicePackage)?.applicationInfo ?: return@any true
                val isSystemApp =
                    (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0 ||
                        (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                !isSystemApp
            }
    }.getOrDefault(false)

    private fun isVpnActive(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val cm = appContext.getSystemService(ConnectivityManager::class.java)
            val caps = runCatching { cm?.getNetworkCapabilities(cm.activeNetwork) }.getOrNull()
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                return true
            }
        }
        return runCatching {
            NetworkInterface.getNetworkInterfaces()
                ?.toList()
                .orEmpty()
                .filter { it.isUp }
                .any { network ->
                    val name = network.name.lowercase()
                    name.startsWith("tun") || name.startsWith("ppp") || name.startsWith("utun")
                }
        }.getOrDefault(false)
    }

    private fun isPackageInstalled(packageName: String): Boolean =
        packageInfoFor(packageName) != null

    private fun packageInfoFor(packageName: String): PackageInfo? = runCatching {
        val pm = appContext.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(packageName, 0)
        }
    }.getOrNull()

    private fun loadAndroidId(): String? = runCatching {
        Settings.Secure.getString(appContext.contentResolver, Settings.Secure.ANDROID_ID)
            ?.trim()
            ?.ifEmpty { null }
    }.getOrNull()

    private fun loadInstallerPackage(): String? = runCatching {
        val pm = appContext.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            pm.getInstallSourceInfo(appContext.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(appContext.packageName)
        }
    }.getOrNull()?.trim()?.ifEmpty { null }

    private fun loadSigningCertDigests(): List<String> = runCatching {
        val pm = appContext.packageManager
        val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            pm.getPackageInfo(appContext.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(appContext.packageName, PackageManager.GET_SIGNATURES)
        }
        val rawSignatures: List<ByteArray> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            packageInfo.signingInfo?.apkContentsSigners?.map { it.toByteArray() }.orEmpty()
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures?.map { it.toByteArray() }.orEmpty()
        }
        rawSignatures.map(::sha256Hex).sorted()
    }.getOrDefault(emptyList())

    private fun packageInfo(): PackageInfo? = runCatching {
        val pm = appContext.packageManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getPackageInfo(appContext.packageName, PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(appContext.packageName, 0)
        }
    }.getOrNull()

    private val PackageInfo?.versionCodeCompat: Long
        get() {
            val info = this ?: return 0L
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                info.longVersionCode
            } else {
                @Suppress("DEPRECATION")
                info.versionCode.toLong()
            }
        }

    companion object {
        private fun normalizeCanonicalId(value: String): String =
            if (value.startsWith("L")) value else "L$value"

        private fun stripKnownPrefix(value: String): String =
            when {
                value.startsWith("L") -> value.removePrefix("L")
                value.startsWith("T") -> value.removePrefix("T")
                else -> value
            }

        private fun canonicalizeMap(values: Map<String, String>): String = buildString {
            values.toSortedMap().forEach { (key, value) ->
                append(key)
                append('=')
                append(value)
                append('\n')
            }
        }

        private fun sha256(bytes: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(bytes)

        private fun sha256Hex(bytes: ByteArray): String =
            sha256(bytes).joinToString(separator = "") { b -> "%02x".format(b) }

        private fun base64UrlNoPadding(bytes: ByteArray): String =
            Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }
}
