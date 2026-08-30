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

internal class DeviceIdentityManager(
    private val context: Context,
    private val config: LeonaConfig,
) {
    private val appContext = context.applicationContext
    private val store = LeonaIdentityStore(appContext)
    /** A process initialization is a new session even when the install is stable. */
    private val sessionId = IdentityIdGenerator.newSessionId()
    /** Used only when Keystore persistence is unavailable; never persisted as plaintext. */
    private val ephemeralInstallId = IdentityIdGenerator.newInstallId()

    fun currentSessionId(): String = sessionId

    @Synchronized
    fun resolve(
        policy: CollectionPolicy = CollectionPolicy(),
        refreshRiskSignals: Boolean = false,
    ): DeviceFingerprintSnapshot {
        store.beginResolution()
        val currentInstallId = resolveLocalInstallId()
        val cached = store.loadLastSnapshot()
        val persistedCanonicalDeviceId = store.loadCanonicalDeviceId()
            ?.let(::normalizeCanonicalId)
            ?.also { normalized ->
                if (normalized != store.loadCanonicalDeviceId()) {
                    store.persistCanonicalDeviceId(normalized)
                }
            }
        if (
            policy.disableCollectionWindowMs >= 0 &&
            cached != null &&
            cached.fingerprintSchemaVersion == DeviceFingerprintHasher.CACHE_SCHEMA_VERSION &&
            cached.installId == currentInstallId &&
            cached.canonicalDeviceId == persistedCanonicalDeviceId &&
            cached.identityProtectionStatus.durable &&
            store.protectionStatus().durable
        ) {
            val age = System.currentTimeMillis() - cached.generatedAtMillis
            if (age in 0..policy.disableCollectionWindowMs) {
                val currentSessionSnapshot = cached.copy(
                    // Session ids are memory-only and must never be trusted from
                    // the persisted snapshot written by an earlier process.
                    sessionId = sessionId,
                    identityProtectionStatus = store.protectionStatus(),
                )
                return if (refreshRiskSignals) {
                    refreshCachedRiskSignals(currentSessionSnapshot, policy)
                } else {
                    currentSessionSnapshot
                }
            }
        }

        val canonicalDeviceId = persistedCanonicalDeviceId
        val packageInfo = packageInfo()
        val installId = currentInstallId
        val installLifecycleSha256 = resolveInstallLifecycleSha256(packageInfo)
        val localAndroidId = loadAndroidId()
            ?.takeIf(DeviceFingerprintHasher::isUsableAnchorValue)
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

        val virtualInstanceAnchorHash = loadVirtualInstanceAnchorHash(localAndroidId)
        val fingerprintSource = if (virtualInstanceAnchorHash == null) {
            DeviceFingerprintHasher.FINGERPRINT_SOURCE_BASE_V2
        } else {
            DeviceFingerprintHasher.FINGERPRINT_SOURCE_VIRTUAL_ANCHOR_V4
        }
        val identityAnchorSource = when {
            virtualInstanceAnchorHash != null -> DeviceFingerprintHasher.ANCHOR_SOURCE_VIRTUAL_INSTANCE
            !localAndroidId.isNullOrBlank() -> DeviceFingerprintHasher.ANCHOR_SOURCE_ANDROID_ID
            else -> DeviceFingerprintHasher.ANCHOR_SOURCE_DEVICE_PROFILE
        }
        val canonicalDeviceIdSource = if (canonicalDeviceId == null) {
            DeviceFingerprintHasher.CANONICAL_SOURCE_TEMPORARY_FINGERPRINT
        } else {
            DeviceFingerprintHasher.CANONICAL_SOURCE_SERVER_PERSISTED
        }
        val identityAnchor = if (virtualInstanceAnchorHash == null) {
            buildIdentityAnchor(localAndroidId)
        } else {
            "virtual:$virtualInstanceAnchorHash"
        }
        val fingerprintSeed = linkedMapOf(
            "version" to if (virtualInstanceAnchorHash == null) {
                DeviceFingerprintHasher.BASE_SEED_VERSION.toString()
            } else {
                DeviceFingerprintHasher.VIRTUAL_ANCHOR_SEED_VERSION.toString()
            },
            "identityAnchor" to identityAnchor,
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
        virtualInstanceAnchorHash?.let { fingerprintSeed["virtualInstanceAnchorHash"] = it }
        val fingerprintHash = DeviceFingerprintHasher.hashFingerprintSeed(fingerprintSeed)
        val resolvedDeviceId = canonicalDeviceId?.let(::normalizeCanonicalId)
            ?: buildTemporaryDeviceId(fingerprintHash = fingerprintHash)

        val snapshot = DeviceFingerprintSnapshot(
            fingerprintSchemaVersion = DeviceFingerprintHasher.CACHE_SCHEMA_VERSION,
            generatedAtMillis = System.currentTimeMillis(),
            installId = installId,
            canonicalDeviceId = canonicalDeviceId,
            resolvedDeviceId = resolvedDeviceId,
            fingerprintHash = fingerprintHash,
            fingerprintSource = fingerprintSource,
            identityAnchorSource = identityAnchorSource,
            canonicalDeviceIdSource = canonicalDeviceIdSource,
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
            installLifecycleSha256 = installLifecycleSha256,
            sessionId = sessionId,
            identityProtectionStatus = store.protectionStatus(),
        )
        if (IdentityPersistencePolicy.shouldPersistSnapshot(snapshot.identityProtectionStatus)) {
            val persisted = runCatching {
                // Never write the process-only session id into the durable cache.
                store.persistLastSnapshot(snapshot.copy(sessionId = ""))
            }.isSuccess
            if (!persisted) {
                return snapshot.copy(identityProtectionStatus = store.protectionStatus())
            }
        }
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

    fun currentSnapshot(): DeviceFingerprintSnapshot? = store.loadLastSnapshot()?.copy(
        sessionId = sessionId,
        identityProtectionStatus = store.protectionStatus(),
    )

    fun updateCanonicalDeviceId(deviceId: String?) {
        normalizeServerCanonicalId(deviceId)?.let { normalized ->
            runCatching { store.persistCanonicalDeviceId(normalized) }
        }
    }

    /**
     * Accept only the opaque id minted by the Leona server. A changed server
     * install id invalidates the cached snapshot so the next report hashes the
     * accepted value rather than continuing to report the previous install.
     */
    @Synchronized
    fun updateServerInstallId(installId: String?) {
        val normalized = normalizeServerInstallId(installId) ?: return
        if (store.loadInstallId() == normalized) return
        runCatching {
            store.replaceInstallIdAndClearSnapshot(normalized)
        }
    }

    private fun normalizeServerInstallId(value: String?): String? =
        value?.trim()?.takeIf(InstallIdAdmission::isServer)

    /** The server-issued value is persisted whenever the encrypted store works. */
    private fun resolveLocalInstallId(): String {
        store.loadInstallId()
            ?.trim()
            ?.takeIf(::isUsableInstallId)
            ?.let { return it }

        // A fresh installation receives a random value; package metadata is
        // never used as an install identity seed.
        val installId = ephemeralInstallId
        // A new local install value invalidates any stale cached snapshot in
        // the same synchronous transaction; a failed commit leaves both old
        // values untouched and the caller receives this process-only value.
        runCatching { store.replaceInstallIdAndClearSnapshot(installId) }
        return installId
    }

    /** A one-way lifecycle hint is emitted only when PackageManager has an epoch. */
    private fun resolveInstallLifecycleSha256(packageInfo: PackageInfo?): String? {
        // The lifecycle handle is a one-way recovery hint, not install_id. It
        // is emitted only when PackageManager provides a positive install epoch.
        return InstallLifecycleHint.sha256(
            packageName = appContext.packageName,
            firstInstallTime = packageInfo?.firstInstallTime,
        )
    }

    private fun isUsableInstallId(value: String): Boolean =
        InstallIdAdmission.isUsable(value)

    private fun buildIdentityAnchor(androidId: String?): String =
        when {
            !androidId.isNullOrBlank() -> "android:$androidId"
            else -> "device-profile"
        }

    private fun buildTemporaryDeviceId(
        fingerprintHash: String,
    ): String {
        val seed = linkedMapOf(
            "version" to DeviceFingerprintHasher.BASE_SEED_VERSION.toString(),
            "fingerprintHash" to fingerprintHash,
        )
        return "T" + DeviceFingerprintHasher.base64UrlNoPadding(
            DeviceFingerprintHasher.sha256(DeviceFingerprintHasher.canonicalizeMap(seed).toByteArray()),
        )
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
        return DeviceEmulatorHeuristics.isEmulatorLikely(
            fingerprint = Build.FINGERPRINT,
            model = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            hardware = Build.HARDWARE,
            product = Build.PRODUCT,
            device = Build.DEVICE,
            board = Build.BOARD,
            hasKnownRuntimeEvidence = hasKnownEmulatorSystemProperties() ||
                hasKnownEmulatorFiles() ||
                hasKnownEmulatorMounts() ||
                hasKnownEmulatorPackages(),
        )
    }

    private fun hasKnownEmulatorSystemProperties(): Boolean {
        if (systemProperty("nemud.player_uuid") != null) {
            return true
        }
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

    private fun loadVirtualInstanceAnchorHash(androidId: String?): String? {
        val hasRuntimeEvidence = hasKnownEmulatorSystemProperties() ||
            hasKnownEmulatorFiles() ||
            hasKnownEmulatorMounts() ||
            hasKnownEmulatorPackages()
        val emulatorLikely = DeviceEmulatorHeuristics.isEmulatorLikely(
            fingerprint = Build.FINGERPRINT,
            model = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            hardware = Build.HARDWARE,
            product = Build.PRODUCT,
            device = Build.DEVICE,
            board = Build.BOARD,
            hasKnownRuntimeEvidence = hasRuntimeEvidence,
        )
        if (!emulatorLikely) return null

        val anchors = linkedMapOf<String, String>()
        listOf(
            "nemud.player_uuid",
            "ro.serialno",
            "ro.boot.serialno",
            "ro.boot.qemu.avd_name",
            "ro.boot.hardware.sku",
        ).forEach { key ->
            systemProperty(key)?.let { value -> anchors["prop.$key"] = value }
        }
        // ANDROID_ID is application-signing-key/user/device scoped on modern
        // Android and remains stable across clear-data and same-signer
        // reinstall. Including it before profile/network fallbacks prevents
        // two AVDs created from the same image from collapsing onto the same
        // virtual-instance fingerprint when hidden AVD-name properties are not
        // visible to applications.
        androidId?.let { anchors["identity.android_id"] = it }
        val selectedAnchors = DeviceFingerprintHasher.selectVirtualInstanceAnchors(anchors)
        return DeviceFingerprintHasher.hashVirtualInstanceAnchors(selectedAnchors)
    }

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
        rawSignatures.map(DeviceFingerprintHasher::sha256Hex).sorted()
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
        private fun normalizeCanonicalId(value: String): String? =
            normalizeServerCanonicalId(value)

        /**
         * Only a server-minted canonical id may become durable client state.
         * Client temporary ids and arbitrary response fields remain telemetry;
         * accepting them here could poison the next fingerprint/session.
         */
        internal fun normalizeServerCanonicalId(value: String?): String? {
            val candidate = value?.trim()?.ifEmpty { null } ?: return null
            val canonical = if (candidate.startsWith("L")) candidate else "L$candidate"
            return canonical.takeIf { it.matches(SERVER_CANONICAL_ID_PATTERN) }
        }

        private val SERVER_CANONICAL_ID_PATTERN = Regex("L[0-9a-f]{32}")
    }
}

internal object DeviceFingerprintHasher {
    const val BASE_SEED_VERSION = 2
    const val VIRTUAL_ANCHOR_SEED_VERSION = 4
    const val CACHE_SCHEMA_VERSION = 4
    const val FINGERPRINT_SOURCE_BASE_V2 = "base_device_v2"
    const val FINGERPRINT_SOURCE_VIRTUAL_ANCHOR_V4 = "virtual_instance_anchor_v4"
    const val ANCHOR_SOURCE_ANDROID_ID = "android_id"
    const val ANCHOR_SOURCE_DEVICE_PROFILE = "device_profile"
    const val ANCHOR_SOURCE_VIRTUAL_INSTANCE = "virtual_instance_anchor"
    const val CANONICAL_SOURCE_SERVER_PERSISTED = "server_persisted"
    const val CANONICAL_SOURCE_TEMPORARY_FINGERPRINT = "temporary_from_fingerprint"

    fun hashFingerprintSeed(values: Map<String, String>): String =
        sha256Hex(canonicalizeMap(values).toByteArray())

    fun fixtureFingerprintHash(
        appScopedAndroidId: String?,
        buildFingerprint: String,
        device: String,
        product: String,
        hardware: String,
        brand: String,
        model: String,
        manufacturer: String,
        sdkInt: Int,
        abis: List<String>,
        virtualInstanceAnchorHash: String? = null,
    ): String {
        val identityAnchor = virtualInstanceAnchorHash?.let { "virtual:$it" }
            ?: appScopedAndroidId?.takeIf { it.isNotBlank() }?.let { "android:$it" }
            ?: "device-profile"
        val seed = linkedMapOf(
            "version" to if (virtualInstanceAnchorHash == null) {
                BASE_SEED_VERSION.toString()
            } else {
                VIRTUAL_ANCHOR_SEED_VERSION.toString()
            },
            "identityAnchor" to identityAnchor,
            "buildFingerprint" to buildFingerprint,
            "device" to device,
            "product" to product,
            "hardware" to hardware,
            "brand" to brand,
            "model" to model,
            "manufacturer" to manufacturer,
            "sdkInt" to sdkInt.toString(),
            "abis" to abis.joinToString(","),
        )
        virtualInstanceAnchorHash?.let { seed["virtualInstanceAnchorHash"] = it }
        return hashFingerprintSeed(seed)
    }

    fun hashVirtualInstanceAnchors(values: Map<String, String>): String? {
        val sanitized = values
            .mapNotNull { (key, value) ->
                val normalized = value.trim()
                if (isUsableAnchorValue(normalized)) key to normalized else null
            }
            .toMap()
        if (sanitized.isEmpty()) return null
        return sha256Hex(canonicalizeMap(sanitized).toByteArray())
    }

    fun selectVirtualInstanceAnchors(properties: Map<String, String>): Map<String, String> {
        val stableProperties = properties.filterValues(::isUsableAnchorValue)
        // Network MACs rotate on several AOSP and third-party emulator
        // releases. Never promote them into a commercial identity anchor; if
        // no stable property/ANDROID_ID is available, the caller falls back to
        // the explicitly lower-confidence base device profile.
        return stableProperties
    }

    fun isUsableAnchorValue(value: String): Boolean {
        val normalized = value.trim().lowercase(Locale.ROOT)
        return normalized.isNotEmpty() &&
            normalized !in setOf(
                "unknown",
                "none",
                "null",
                "0",
                "000000000000000",
                "0123456789abcdef",
                "9774d56d682e549c",
                "02:00:00:00:00:00",
                "00:00:00:00:00:00",
                "ff:ff:ff:ff:ff:ff",
                "<redacted>",
            )
    }

    fun canonicalizeMap(values: Map<String, String>): String = buildString {
        values.toSortedMap().forEach { (key, value) ->
            append(key)
            append('=')
            append(value)
            append('\n')
        }
    }

    fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    fun base64UrlNoPadding(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun sha256Hex(bytes: ByteArray): String =
        sha256(bytes).joinToString(separator = "") { b -> "%02x".format(b) }
}

internal object DeviceEmulatorHeuristics {
    fun isEmulatorLikely(
        fingerprint: String?,
        model: String?,
        manufacturer: String?,
        hardware: String?,
        product: String?,
        device: String?,
        board: String?,
        hasKnownRuntimeEvidence: Boolean,
    ): Boolean {
        val normalizedFingerprint = fingerprint.orEmpty().lowercase()
        val normalizedModel = model.orEmpty().lowercase()
        val normalizedManufacturer = manufacturer.orEmpty().lowercase()
        val normalizedHardware = hardware.orEmpty().lowercase()
        val normalizedProduct = product.orEmpty().lowercase()
        val normalizedDevice = device.orEmpty().lowercase()
        val normalizedBoard = board.orEmpty().lowercase()

        return normalizedFingerprint.contains("emulator") ||
            normalizedFingerprint.contains("vbox") ||
            normalizedFingerprint.contains("nemu") ||
            normalizedFingerprint.contains("mumu") ||
            normalizedModel.contains("sdk_gphone") ||
            normalizedModel.contains("emulator") ||
            normalizedModel.contains("android sdk built for") ||
            normalizedModel.contains("mumu") ||
            normalizedModel.contains("nox") ||
            normalizedModel.contains("ldplayer") ||
            normalizedModel.contains("bluestacks") ||
            normalizedManufacturer.contains("genymotion") ||
            normalizedManufacturer.contains("netease") ||
            normalizedManufacturer.contains("mumu") ||
            normalizedHardware.contains("goldfish") ||
            normalizedHardware.contains("ranchu") ||
            normalizedHardware.contains("vbox86") ||
            normalizedHardware.contains("qemu") ||
            normalizedHardware.contains("nemu") ||
            normalizedHardware.contains("dummy-virt") ||
            normalizedProduct == "sdk" ||
            normalizedProduct.startsWith("sdk_") ||
            normalizedProduct.startsWith("sdk-") ||
            normalizedProduct == "google_sdk" ||
            normalizedProduct.startsWith("sdk_gphone") ||
            normalizedProduct.contains("emulator") ||
            normalizedProduct.contains("simulator") ||
            normalizedProduct.contains("mumu") ||
            normalizedProduct.contains("nemu") ||
            normalizedDevice.contains("mumu") ||
            normalizedDevice.contains("nemu") ||
            normalizedBoard.contains("qemu") ||
            normalizedBoard.contains("goldfish") ||
            normalizedBoard.contains("ranchu") ||
            hasKnownRuntimeEvidence
    }
}
