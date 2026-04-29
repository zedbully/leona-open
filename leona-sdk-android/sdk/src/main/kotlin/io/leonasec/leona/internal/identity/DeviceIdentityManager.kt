/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import android.Manifest
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
    fun resolve(
        policy: CollectionPolicy = CollectionPolicy(),
        refreshRiskSignals: Boolean = false,
    ): DeviceFingerprintSnapshot {
        val cached = store.loadLastSnapshot()
        val persistedCanonicalDeviceId = store.loadCanonicalDeviceId()
            ?.let(::normalizeCanonicalId)
            ?.also { normalized ->
                if (normalized != store.loadCanonicalDeviceId()) {
                    store.persistCanonicalDeviceId(normalized)
                }
            }
        if (policy.disableCollectionWindowMs >= 0 && cached != null && cached.canonicalDeviceId == persistedCanonicalDeviceId) {
            val age = System.currentTimeMillis() - cached.generatedAtMillis
            if (age in 0..policy.disableCollectionWindowMs) {
                return if (refreshRiskSignals) refreshCachedRiskSignals(cached, policy) else cached
            }
        }

        val installId = store.loadInstallId() ?: UUID.randomUUID().toString().also(store::persistInstallId)
        val canonicalDeviceId = persistedCanonicalDeviceId
        val packageInfo = packageInfo()
        val localAndroidId = loadAndroidId()
        val androidId = if ("androidId" in policy.disabledSignals) null else localAndroidId
        val localSigningCerts = loadSigningCertDigests()
        val signingCerts = if ("signingCert" in policy.disabledSignals) emptyList() else localSigningCerts
        val installerPackage = if ("installer" in policy.disabledSignals) null else loadInstallerPackage()
        val deviceEnvironmentEvidence = DeviceEnvironmentEvidenceCollector.collect()
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
            "version" to "2",
            "identityAnchor" to buildIdentityAnchor(localAndroidId),
            "buildFingerprint" to Build.FINGERPRINT.orEmpty(),
            "device" to Build.DEVICE.orEmpty(),
            "product" to Build.PRODUCT.orEmpty(),
            "hardware" to Build.HARDWARE.orEmpty(),
            "brand" to Build.BRAND.orEmpty(),
            "model" to Build.MODEL.orEmpty(),
            "manufacturer" to Build.MANUFACTURER.orEmpty(),
            "sdkInt" to Build.VERSION.SDK_INT.toString(),
            "abis" to Build.SUPPORTED_ABIS.joinToString(","),
        )
        val fingerprintHash = sha256Hex(canonicalizeMap(fingerprintSeed).toByteArray())
        val resolvedDeviceId = canonicalDeviceId?.let(::normalizeCanonicalId)
            ?: buildTemporaryDeviceId(fingerprintHash = fingerprintHash)

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
            deviceEnvironmentEvidence = deviceEnvironmentEvidence,
        )
        store.persistLastSnapshot(snapshot)
        return snapshot
    }

    private fun refreshCachedRiskSignals(
        cached: DeviceFingerprintSnapshot,
        policy: CollectionPolicy,
    ): DeviceFingerprintSnapshot {
        val packageInfo = packageInfo()
        val signingCerts = if ("signingCert" in policy.disabledSignals) emptyList() else loadSigningCertDigests()
        val installerPackage = if ("installer" in policy.disabledSignals) null else loadInstallerPackage()
        val deviceEnvironmentEvidence = DeviceEnvironmentEvidenceCollector.collect()
        return CachedSnapshotRiskSignals.refresh(
            cached = cached,
            installerPackage = installerPackage,
            signingCertSha256 = signingCerts,
            riskSignals = collectRiskSignals(
                policy = policy,
                packageInfo = packageInfo,
                signingCerts = signingCerts,
                installerPackage = installerPackage,
            ),
            deviceEnvironmentEvidence = deviceEnvironmentEvidence,
        )
    }

    fun currentSnapshot(): DeviceFingerprintSnapshot? = store.loadLastSnapshot()

    fun updateCanonicalDeviceId(deviceId: String?) {
        val normalized = deviceId?.trim()?.ifEmpty { null } ?: return
        store.persistCanonicalDeviceId(normalizeCanonicalId(normalized))
    }

    private fun buildIdentityAnchor(androidId: String?): String =
        when {
            !androidId.isNullOrBlank() -> "android:$androidId"
            else -> "device-profile"
        }

    private fun buildTemporaryDeviceId(
        fingerprintHash: String,
    ): String {
        val seed = linkedMapOf(
            "version" to "2",
            "fingerprintHash" to fingerprintHash,
        )
        return "T" + base64UrlNoPadding(sha256(canonicalizeMap(seed).toByteArray()))
    }

    private fun collectRiskSignals(
        policy: CollectionPolicy,
        packageInfo: PackageInfo?,
        signingCerts: List<String>,
        installerPackage: String?,
    ): Set<String> =
        collectVolatileRiskSignals(policy) + collectStableRiskSignals(
            policy = policy,
            packageInfo = packageInfo,
            signingCerts = signingCerts,
            installerPackage = installerPackage,
        )

    private fun collectVolatileRiskSignals(policy: CollectionPolicy): Set<String> = buildSet {
        if ("debugger" !in policy.disabledSignals && Debug.isDebuggerConnected()) add("debugger.attached")
        if ("developerOptions" !in policy.disabledSignals && isDeveloperOptionsEnabled()) add("developer.options_enabled")
        if ("adb" !in policy.disabledSignals && isAdbEnabled()) add("developer.adb_enabled")
        if ("vpn" !in policy.disabledSignals && isVpnActive()) add("network.vpn_active")
        if ("proxy" !in policy.disabledSignals && isProxyConfigured()) add("network.proxy_configured")
        if ("accessibility" !in policy.disabledSignals && hasThirdPartyAccessibilityServicesEnabled()) {
            add("accessibility.third_party_enabled")
        }
    }

    private fun collectStableRiskSignals(
        policy: CollectionPolicy,
        packageInfo: PackageInfo?,
        signingCerts: List<String>,
        installerPackage: String?,
    ): Set<String> = buildSet {
        if ("root" !in policy.disabledSignals && isBasicRootLikely()) add("root.basic")
        if ("rootPackages" !in policy.disabledSignals && hasKnownRootPackages()) add("root.packages")
        if ("emulator" !in policy.disabledSignals && isEmulatorLikely()) add("environment.emulator")
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
        return false
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
        val brand = Build.BRAND.orEmpty().lowercase()
        val device = Build.DEVICE.orEmpty().lowercase()
        val board = Build.BOARD.orEmpty().lowercase()
        return fingerprint.contains("generic") ||
            fingerprint.contains("emulator") ||
            fingerprint.contains("vbox") ||
            fingerprint.contains("nemu") ||
            fingerprint.contains("mumu") ||
            model.contains("sdk_gphone") ||
            model.contains("emulator") ||
            model.contains("android sdk built for") ||
            model.contains("mumu") ||
            model.contains("nox") ||
            model.contains("ldplayer") ||
            model.contains("bluestacks") ||
            manufacturer.contains("genymotion") ||
            manufacturer.contains("netease") ||
            manufacturer.contains("mumu") ||
            hardware.contains("goldfish") ||
            hardware.contains("ranchu") ||
            hardware.contains("vbox86") ||
            hardware.contains("qemu") ||
            hardware.contains("nemu") ||
            hardware.contains("dummy-virt") ||
            product.contains("sdk") ||
            product.contains("emulator") ||
            product.contains("simulator") ||
            product.contains("mumu") ||
            product.contains("nemu") ||
            brand.contains("generic") ||
            device.contains("generic") ||
            device.contains("mumu") ||
            device.contains("nemu") ||
            board.contains("qemu") ||
            board.contains("goldfish") ||
            board.contains("ranchu") ||
            hasKnownEmulatorSystemProperties() ||
            hasKnownEmulatorFiles() ||
            hasKnownEmulatorMounts() ||
            hasKnownEmulatorPackages()
    }

    private fun hasKnownEmulatorSystemProperties(): Boolean {
        val exactMatches = mapOf(
            "ro.kernel.qemu" to setOf("1"),
            "ro.boot.qemu" to setOf("1"),
            "ro.build.hv.platform" to setOf("qemu"),
            "ro.build.version.nemux" to setOf("true", "1"),
            "nemud.player_package" to setOf("mumu"),
            "nemud.player_engine" to setOf("macpro"),
            "init.svc.nemuinit" to setOf("running"),
            "init.svc.nemuinput" to setOf("running"),
            "init.svc.nemu_sys_opt" to setOf("running"),
            "persist.nemu.root_state" to setOf("open", "close"),
        )
        if (exactMatches.any { (key, values) ->
                systemProperty(key)?.lowercase(Locale.ROOT) in values
            }
        ) {
            return true
        }

        val needleProps = listOf(
            "ro.product.model",
            "ro.product.manufacturer",
            "ro.hardware",
            "ro.board.platform",
            "ro.boot.hardware",
            "ro.build.fingerprint",
            "ro.build.description",
            "ro.product.name",
            "ro.product.device",
        )
        val needles = listOf(
            "mumu",
            "nemu",
            "netease",
            "nox",
            "ldplayer",
            "bluestacks",
            "genymotion",
            "goldfish",
            "ranchu",
            "vbox",
        )
        return needleProps.any { key ->
            val value = systemProperty(key)?.lowercase(Locale.ROOT).orEmpty()
            value.isNotBlank() && needles.any(value::contains)
        }
    }

    private fun hasKnownEmulatorFiles(): Boolean {
        val paths = listOf(
            "/dev/qemu_pipe",
            "/dev/socket/qemud",
            "/dev/socket/genyd",
            "/dev/socket/baseband_genyd",
            "/system/bin/nemuinit",
            "/system/bin/nemuinput",
            "/system/bin/nemu_sys_opt",
            "/system/lib/libldutils.so",
            "/data/data/com.bluestacks",
        )
        return paths.any { path -> runCatching { java.io.File(path).exists() }.getOrDefault(false) }
    }

    private fun hasKnownEmulatorMounts(): Boolean = runCatching {
        java.io.File("/proc/mounts")
            .takeIf { it.exists() }
            ?.useLines { lines ->
                lines.any { line ->
                    val normalized = line.lowercase(Locale.ROOT)
                    normalized.contains("mumu") ||
                        normalized.contains("nemu") ||
                        normalized.contains("vbox") ||
                        normalized.contains("qemu") ||
                        normalized.contains("virtio") && normalized.contains("9p")
                }
            }
            ?: false
    }.getOrDefault(false)

    private fun hasKnownEmulatorPackages(): Boolean {
        val knownPackages = listOf(
            "com.yhd.yofun.mumu",
            "com.mumu.launcher",
            "com.bignox.app",
            "com.vphone.launcher",
            "com.microvirt.launcher",
            "com.bluestacks.home",
        )
        return knownPackages.any(::isPackageInstalled)
    }

    private fun systemProperty(key: String): String? = runCatching {
        val clazz = Class.forName("android.os.SystemProperties")
        clazz.getMethod("get", String::class.java).invoke(null, key) as? String
    }.getOrNull()?.trim()?.ifEmpty { null }

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
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
            appContext.checkSelfPermission(Manifest.permission.ACCESS_NETWORK_STATE) ==
            PackageManager.PERMISSION_GRANTED
        ) {
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
