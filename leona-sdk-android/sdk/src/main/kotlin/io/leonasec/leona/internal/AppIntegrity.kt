/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.pm.ComponentInfo
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import java.io.File
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.ZipFile

/**
 * Minimal JVM-side integrity snapshot used by the native tamper skeleton.
 *
 * This does not make client-side decisions. It only serializes runtime facts
 * that are awkward to collect from native code alone: package manager state,
 * signing cert digests, installer package, and APK/lib paths.
 *
 * TODO(v0.1): compare these values against server-provisioned expectations
 * instead of heuristic-only checks in native code.
 */
internal object AppIntegrity {

    private val applicationSemanticsManifestFields = listOf(
        "name",
        "appComponentFactory",
        "extractNativeLibs",
        "usesCleartextTraffic",
        "networkSecurityConfig",
    )

    private val applicationDriftManifestFields = listOf(
        "name",
        "appComponentFactory",
        "allowBackup",
        "backupAgent",
        "dataExtractionRules",
        "debuggable",
        "extractNativeLibs",
        "fullBackupContent",
        "fullBackupOnly",
        "hasCode",
        "hardwareAccelerated",
        "killAfterRestore",
        "largeHeap",
        "localeConfig",
        "networkSecurityConfig",
        "requestLegacyExternalStorage",
        "restoreAnyVersion",
        "testOnly",
        "usesCleartextTraffic",
        "usesNonSdkApi",
        "vmSafeMode",
    )

    fun capture(context: Context, policy: TamperPolicy): String {
        val packageManager = context.packageManager
        val packageName = context.packageName
        val packageInfo = packageManager.safePackageInfo(packageName)
        val manifestInfo = packageManager.safeManifestPackageInfo(packageName)
        val appInfo = context.applicationInfo

        val lines = linkedMapOf(
            "package" to packageName,
            "debuggable" to if ((appInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) "1" else "0",
            "installer" to packageManager.safeInstaller(packageName).orEmpty(),
            "sourceDir" to appInfo.sourceDir.orEmpty(),
            "nativeLibraryDir" to appInfo.nativeLibraryDir.orEmpty(),
            "splitCount" to (appInfo.splitSourceDirs?.size ?: 0).toString(),
            "versionCode" to (packageInfo?.safeLongVersionCode() ?: 0L).toString(),
            "certSha256" to packageInfo.signingDigestsSha256().joinToString(","),
        )

        if (policy.expectedApkSha256 != null) {
            lines["apkSha256"] = hashFileHex(appInfo.sourceDir).orEmpty()
        }

        if (policy.expectedNativeLibSha256.isNotEmpty()) {
            policy.expectedNativeLibSha256.keys.sorted().forEach { fileName ->
                val actual = hashNativeLibraryHex(appInfo.nativeLibraryDir, fileName).orEmpty()
                lines["libSha256.$fileName"] = actual
            }
        }

        if (policy.expectedManifestEntrySha256 != null || policy.expectedDexSha256.isNotEmpty()) {
            val zipEntries = hashZipEntries(
                apkPath = appInfo.sourceDir,
                entryNames = buildSet {
                    if (policy.expectedManifestEntrySha256 != null) add("AndroidManifest.xml")
                    addAll(policy.expectedDexSha256.keys)
                },
            )
            policy.expectedManifestEntrySha256?.let {
                lines["manifestEntrySha256"] = zipEntries["AndroidManifest.xml"].orEmpty()
            }
            policy.expectedDexSha256.keys.sorted().forEach { entryName ->
                lines["dexSha256.$entryName"] = zipEntries[entryName].orEmpty()
            }
        }

        if (policy.expectedDexSectionSha256.isNotEmpty()) {
            val requested = policy.expectedDexSectionSha256.keys
            val sectionsByEntry = requested.groupBy(
                keySelector = { it.substringBefore('#', missingDelimiterValue = "") },
                valueTransform = { it.substringAfter('#', missingDelimiterValue = "") },
            ).filterKeys { it.isNotBlank() }

            val sectionHashes = hashDexSections(appInfo.sourceDir, sectionsByEntry)
            requested.sorted().forEach { key ->
                lines["dexSectionSha256.$key"] = sectionHashes[key].orEmpty()
            }
        }

        if (policy.expectedDexMethodSha256.isNotEmpty()) {
            val requested = policy.expectedDexMethodSha256.keys
            val methodsByEntry = requested.groupBy(
                keySelector = { it.substringBefore('#', missingDelimiterValue = "") },
                valueTransform = { it.substringAfter('#', missingDelimiterValue = "") },
            ).filterKeys { it.isNotBlank() }

            val methodHashes = hashDexMethods(appInfo.sourceDir, methodsByEntry)
            requested.sorted().forEach { key ->
                lines["dexMethodSha256.$key"] = methodHashes[key].orEmpty()
            }
        }

        if (policy.expectedSplitApkSha256.isNotEmpty()) {
            appInfo.splitSourceDirs.orEmpty().forEach { splitPath ->
                val file = File(splitPath)
                lines["splitSha256.${file.name}"] = hashFileHex(splitPath).orEmpty()
            }
        }

        if (policy.expectedSplitInventorySha256 != null) {
            lines["splitInventorySha256"] = hashSplitInventory(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedDynamicFeatureSplitSha256 != null) {
            lines["dynamicFeatureSplitSha256"] =
                hashDynamicFeatureSplits(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedDynamicFeatureSplitNameSha256 != null) {
            lines["dynamicFeatureSplitNameSha256"] =
                hashDynamicFeatureSplitNames(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedConfigSplitAxisSha256 != null) {
            lines["configSplitAxisSha256"] =
                hashConfigSplitAxes(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedConfigSplitNameSha256 != null) {
            lines["configSplitNameSha256"] =
                hashConfigSplitNames(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedConfigSplitAbiSha256 != null) {
            lines["configSplitAbiSha256"] =
                hashConfigSplitAbis(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedConfigSplitLocaleSha256 != null) {
            lines["configSplitLocaleSha256"] =
                hashConfigSplitLocales(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedConfigSplitDensitySha256 != null) {
            lines["configSplitDensitySha256"] =
                hashConfigSplitDensities(appInfo.splitSourceDirs.orEmpty().toList())
        }

        if (policy.expectedElfSectionSha256.isNotEmpty()) {
            val requested = policy.expectedElfSectionSha256.keys
            val sectionsByLib = requested.groupBy(
                keySelector = { it.substringBefore('#', missingDelimiterValue = "") },
                valueTransform = { it.substringAfter('#', missingDelimiterValue = "") },
            ).filterKeys { it.isNotBlank() }

            val elfHashes = hashElfSections(appInfo.nativeLibraryDir, sectionsByLib)
            requested.sorted().forEach { key ->
                lines["elfSectionSha256.$key"] = elfHashes[key].orEmpty()
            }
        }

        if (policy.expectedElfExportSymbolSha256.isNotEmpty()) {
            val requested = policy.expectedElfExportSymbolSha256.keys
            val symbolsByLib = requested.groupBy(
                keySelector = { it.substringBefore('#', missingDelimiterValue = "") },
                valueTransform = { it.substringAfter('#', missingDelimiterValue = "") },
            ).filterKeys { it.isNotBlank() }

            val symbolHashes = hashElfExportSymbols(appInfo.nativeLibraryDir, symbolsByLib)
            requested.sorted().forEach { key ->
                lines["elfExportSymbolSha256.$key"] = symbolHashes[key].orEmpty()
            }
        }

        if (policy.expectedElfExportGraphSha256.isNotEmpty()) {
            val graphHashes = hashElfExportGraphs(
                appInfo.nativeLibraryDir,
                policy.expectedElfExportGraphSha256.keys,
            )
            policy.expectedElfExportGraphSha256.keys.sorted().forEach { libName ->
                lines["elfExportGraphSha256.$libName"] = graphHashes[libName].orEmpty()
            }
        }

        if (policy.expectedRequestedPermissionsSha256 != null) {
            lines["requestedPermissionsSha256"] = hashRequestedPermissions(manifestInfo).orEmpty()
        }

        if (policy.expectedRequestedPermissionSemanticsSha256 != null) {
            lines["requestedPermissionSemanticsSha256"] =
                hashRequestedPermissionSemantics(manifestInfo).orEmpty()
        }

        if (policy.expectedDeclaredPermissionSemanticsSha256 != null) {
            lines["declaredPermissionSemanticsSha256"] =
                hashDeclaredPermissionSemantics(manifestInfo).orEmpty()
        }

        if (policy.expectedDeclaredPermissionFieldValues.isNotEmpty()) {
            val permissionFields = collectDeclaredPermissionFieldValues(manifestInfo)
            policy.expectedDeclaredPermissionFieldValues.keys.sorted().forEach { key ->
                lines["declaredPermissionField.$key"] = permissionFields[key].orEmpty()
            }
        }

        if (policy.expectedComponentSignatureSha256.isNotEmpty()) {
            val componentSignatures = collectComponentSignatures(manifestInfo)
            policy.expectedComponentSignatureSha256.keys.sorted().forEach { key ->
                lines["componentSignatureSha256.$key"] = componentSignatures[key].orEmpty()
            }
        }

        if (policy.expectedComponentFieldValues.isNotEmpty()) {
            val componentFields = collectComponentFieldValues(manifestInfo)
            policy.expectedComponentFieldValues.keys.sorted().forEach { key ->
                lines["componentField.$key"] = componentFields[key].orEmpty()
            }
        }

        if (policy.expectedProviderUriPermissionPatternsSha256.isNotEmpty()) {
            val providerHashes = collectProviderUriPermissionPatternFingerprints(manifestInfo)
            policy.expectedProviderUriPermissionPatternsSha256.keys.sorted().forEach { key ->
                lines["providerUriPermissionPatternsSha256.$key"] = providerHashes[key].orEmpty()
            }
        }

        if (policy.expectedProviderPathPermissionsSha256.isNotEmpty()) {
            val providerHashes = collectProviderPathPermissionFingerprints(manifestInfo)
            policy.expectedProviderPathPermissionsSha256.keys.sorted().forEach { key ->
                lines["providerPathPermissionsSha256.$key"] = providerHashes[key].orEmpty()
            }
        }

        if (policy.expectedProviderAuthoritySetSha256.isNotEmpty()) {
            val providerHashes = collectProviderAuthoritySetFingerprints(manifestInfo)
            policy.expectedProviderAuthoritySetSha256.keys.sorted().forEach { key ->
                lines["providerAuthoritySetSha256.$key"] = providerHashes[key].orEmpty()
            }
        }

        if (policy.expectedProviderSemanticsSha256.isNotEmpty()) {
            val providerHashes = collectProviderSemanticsFingerprints(manifestInfo)
            policy.expectedProviderSemanticsSha256.keys.sorted().forEach { key ->
                lines["providerSemanticsSha256.$key"] = providerHashes[key].orEmpty()
            }
        }

        if (policy.expectedIntentFilterSha256.isNotEmpty() ||
            policy.expectedIntentFilterActionSha256.isNotEmpty() ||
            policy.expectedIntentFilterCategorySha256.isNotEmpty() ||
            policy.expectedIntentFilterDataSha256.isNotEmpty() ||
            policy.expectedIntentFilterDataSchemeSha256.isNotEmpty() ||
            policy.expectedIntentFilterDataAuthoritySha256.isNotEmpty() ||
            policy.expectedIntentFilterDataPathSha256.isNotEmpty() ||
            policy.expectedIntentFilterDataMimeTypeSha256.isNotEmpty() ||
            policy.expectedGrantUriPermissionSha256.isNotEmpty()
        ) {
            val requestedIntentFilterKeys = buildSet {
                addAll(policy.expectedIntentFilterSha256.keys)
                addAll(policy.expectedIntentFilterActionSha256.keys)
                addAll(policy.expectedIntentFilterCategorySha256.keys)
                addAll(policy.expectedIntentFilterDataSha256.keys)
                addAll(policy.expectedIntentFilterDataSchemeSha256.keys)
                addAll(policy.expectedIntentFilterDataAuthoritySha256.keys)
                addAll(policy.expectedIntentFilterDataPathSha256.keys)
                addAll(policy.expectedIntentFilterDataMimeTypeSha256.keys)
            }
            val manifestHashes = collectManifestSubtreeFingerprints(
                apkPath = appInfo.sourceDir,
                requestedIntentFilters = requestedIntentFilterKeys,
                requestedGrantUriPermissions = policy.expectedGrantUriPermissionSha256.keys,
            )
            policy.expectedIntentFilterSha256.keys.sorted().forEach { key ->
                lines["intentFilterSha256.$key"] = manifestHashes.intentFilterHashes[key].orEmpty()
            }
            policy.expectedIntentFilterActionSha256.keys.sorted().forEach { key ->
                lines["intentFilterActionSha256.$key"] = manifestHashes.intentFilterActionHashes[key].orEmpty()
            }
            policy.expectedIntentFilterCategorySha256.keys.sorted().forEach { key ->
                lines["intentFilterCategorySha256.$key"] = manifestHashes.intentFilterCategoryHashes[key].orEmpty()
            }
            policy.expectedIntentFilterDataSha256.keys.sorted().forEach { key ->
                lines["intentFilterDataSha256.$key"] = manifestHashes.intentFilterDataHashes[key].orEmpty()
            }
            policy.expectedIntentFilterDataSchemeSha256.keys.sorted().forEach { key ->
                lines["intentFilterDataSchemeSha256.$key"] = manifestHashes.intentFilterDataSchemeHashes[key].orEmpty()
            }
            policy.expectedIntentFilterDataAuthoritySha256.keys.sorted().forEach { key ->
                lines["intentFilterDataAuthoritySha256.$key"] = manifestHashes.intentFilterDataAuthorityHashes[key].orEmpty()
            }
            policy.expectedIntentFilterDataPathSha256.keys.sorted().forEach { key ->
                lines["intentFilterDataPathSha256.$key"] = manifestHashes.intentFilterDataPathHashes[key].orEmpty()
            }
            policy.expectedIntentFilterDataMimeTypeSha256.keys.sorted().forEach { key ->
                lines["intentFilterDataMimeTypeSha256.$key"] = manifestHashes.intentFilterDataMimeTypeHashes[key].orEmpty()
            }
            policy.expectedGrantUriPermissionSha256.keys.sorted().forEach { key ->
                lines["grantUriPermissionSha256.$key"] = manifestHashes.grantUriPermissionHashes[key].orEmpty()
            }
        }

        if (policy.expectedUsesFeatureSha256 != null ||
            policy.expectedUsesFeatureNameSha256 != null ||
            policy.expectedUsesFeatureRequiredSha256 != null ||
            policy.expectedUsesFeatureGlEsVersionSha256 != null ||
            policy.expectedUsesSdkSha256 != null ||
            policy.expectedUsesSdkMinSha256 != null ||
            policy.expectedUsesSdkTargetSha256 != null ||
            policy.expectedUsesSdkMaxSha256 != null ||
            policy.expectedSupportsScreensSha256 != null ||
            policy.expectedSupportsScreensSmallScreensSha256 != null ||
            policy.expectedSupportsScreensNormalScreensSha256 != null ||
            policy.expectedSupportsScreensLargeScreensSha256 != null ||
            policy.expectedSupportsScreensXlargeScreensSha256 != null ||
            policy.expectedSupportsScreensResizeableSha256 != null ||
            policy.expectedSupportsScreensAnyDensitySha256 != null ||
            policy.expectedSupportsScreensRequiresSmallestWidthDpSha256 != null ||
            policy.expectedSupportsScreensCompatibleWidthLimitDpSha256 != null ||
            policy.expectedSupportsScreensLargestWidthLimitDpSha256 != null ||
            policy.expectedCompatibleScreensSha256 != null ||
            policy.expectedCompatibleScreensScreenSizeSha256 != null ||
            policy.expectedCompatibleScreensScreenDensitySha256 != null ||
            policy.expectedUsesLibrarySha256 != null ||
            policy.expectedUsesLibraryNameSha256 != null ||
            policy.expectedUsesLibraryRequiredSha256 != null ||
            policy.expectedUsesLibraryOnlySha256 != null ||
            policy.expectedUsesLibraryOnlyNameSha256 != null ||
            policy.expectedUsesLibraryOnlyRequiredSha256 != null ||
            policy.expectedUsesNativeLibrarySha256 != null ||
            policy.expectedUsesNativeLibraryNameSha256 != null ||
            policy.expectedUsesNativeLibraryRequiredSha256 != null ||
            policy.expectedQueriesSha256 != null ||
            policy.expectedQueriesPackageSha256 != null ||
            policy.expectedQueriesPackageNameSha256 != null ||
            policy.expectedQueriesProviderSha256 != null ||
            policy.expectedQueriesProviderAuthoritySha256 != null ||
            policy.expectedQueriesIntentSha256 != null ||
            policy.expectedQueriesIntentActionSha256 != null ||
            policy.expectedQueriesIntentCategorySha256 != null ||
            policy.expectedQueriesIntentDataSha256 != null ||
            policy.expectedQueriesIntentDataSchemeSha256 != null ||
            policy.expectedQueriesIntentDataAuthoritySha256 != null ||
            policy.expectedQueriesIntentDataPathSha256 != null ||
            policy.expectedQueriesIntentDataMimeTypeSha256 != null ||
            policy.expectedApplicationSemanticsSha256 != null ||
            policy.expectedApplicationFieldValues.isNotEmpty()
        ) {
            val manifestHashes = collectManifestGlobalFingerprints(appInfo.sourceDir)
            policy.expectedUsesFeatureSha256?.let {
                lines["usesFeatureSha256"] = manifestHashes.usesFeatureSha256.orEmpty()
            }
            policy.expectedUsesFeatureNameSha256?.let {
                lines["usesFeatureNameSha256"] = manifestHashes.usesFeatureNameSha256.orEmpty()
            }
            policy.expectedUsesFeatureRequiredSha256?.let {
                lines["usesFeatureRequiredSha256"] = manifestHashes.usesFeatureRequiredSha256.orEmpty()
            }
            policy.expectedUsesFeatureGlEsVersionSha256?.let {
                lines["usesFeatureGlEsVersionSha256"] = manifestHashes.usesFeatureGlEsVersionSha256.orEmpty()
            }
            policy.expectedUsesSdkSha256?.let {
                lines["usesSdkSha256"] = manifestHashes.usesSdkSha256.orEmpty()
            }
            policy.expectedUsesSdkMinSha256?.let {
                lines["usesSdkMinSha256"] = manifestHashes.usesSdkMinVersionSha256.orEmpty()
            }
            policy.expectedUsesSdkTargetSha256?.let {
                lines["usesSdkTargetSha256"] = manifestHashes.usesSdkTargetVersionSha256.orEmpty()
            }
            policy.expectedUsesSdkMaxSha256?.let {
                lines["usesSdkMaxSha256"] = manifestHashes.usesSdkMaxVersionSha256.orEmpty()
            }
            policy.expectedSupportsScreensSha256?.let {
                lines["supportsScreensSha256"] = manifestHashes.supportsScreensSha256.orEmpty()
            }
            policy.expectedSupportsScreensSmallScreensSha256?.let {
                lines["supportsScreensSmallScreensSha256"] =
                    manifestHashes.supportsScreensSmallScreensSha256.orEmpty()
            }
            policy.expectedSupportsScreensNormalScreensSha256?.let {
                lines["supportsScreensNormalScreensSha256"] =
                    manifestHashes.supportsScreensNormalScreensSha256.orEmpty()
            }
            policy.expectedSupportsScreensLargeScreensSha256?.let {
                lines["supportsScreensLargeScreensSha256"] =
                    manifestHashes.supportsScreensLargeScreensSha256.orEmpty()
            }
            policy.expectedSupportsScreensXlargeScreensSha256?.let {
                lines["supportsScreensXlargeScreensSha256"] =
                    manifestHashes.supportsScreensXlargeScreensSha256.orEmpty()
            }
            policy.expectedSupportsScreensResizeableSha256?.let {
                lines["supportsScreensResizeableSha256"] =
                    manifestHashes.supportsScreensResizeableSha256.orEmpty()
            }
            policy.expectedSupportsScreensAnyDensitySha256?.let {
                lines["supportsScreensAnyDensitySha256"] =
                    manifestHashes.supportsScreensAnyDensitySha256.orEmpty()
            }
            policy.expectedSupportsScreensRequiresSmallestWidthDpSha256?.let {
                lines["supportsScreensRequiresSmallestWidthDpSha256"] =
                    manifestHashes.supportsScreensRequiresSmallestWidthDpSha256.orEmpty()
            }
            policy.expectedSupportsScreensCompatibleWidthLimitDpSha256?.let {
                lines["supportsScreensCompatibleWidthLimitDpSha256"] =
                    manifestHashes.supportsScreensCompatibleWidthLimitDpSha256.orEmpty()
            }
            policy.expectedSupportsScreensLargestWidthLimitDpSha256?.let {
                lines["supportsScreensLargestWidthLimitDpSha256"] =
                    manifestHashes.supportsScreensLargestWidthLimitDpSha256.orEmpty()
            }
            policy.expectedCompatibleScreensSha256?.let {
                lines["compatibleScreensSha256"] = manifestHashes.compatibleScreensSha256.orEmpty()
            }
            policy.expectedCompatibleScreensScreenSizeSha256?.let {
                lines["compatibleScreensScreenSizeSha256"] =
                    manifestHashes.compatibleScreensScreenSizeSha256.orEmpty()
            }
            policy.expectedCompatibleScreensScreenDensitySha256?.let {
                lines["compatibleScreensScreenDensitySha256"] =
                    manifestHashes.compatibleScreensScreenDensitySha256.orEmpty()
            }
            policy.expectedUsesLibrarySha256?.let {
                lines["usesLibrarySha256"] = manifestHashes.usesLibrarySha256.orEmpty()
            }
            policy.expectedUsesLibraryNameSha256?.let {
                lines["usesLibraryNameSha256"] = manifestHashes.usesLibraryNameSha256.orEmpty()
            }
            policy.expectedUsesLibraryRequiredSha256?.let {
                lines["usesLibraryRequiredSha256"] = manifestHashes.usesLibraryRequiredSha256.orEmpty()
            }
            policy.expectedUsesLibraryOnlySha256?.let {
                lines["usesLibraryOnlySha256"] = manifestHashes.usesLibraryOnlySha256.orEmpty()
            }
            policy.expectedUsesLibraryOnlyNameSha256?.let {
                lines["usesLibraryOnlyNameSha256"] = manifestHashes.usesLibraryOnlyNameSha256.orEmpty()
            }
            policy.expectedUsesLibraryOnlyRequiredSha256?.let {
                lines["usesLibraryOnlyRequiredSha256"] =
                    manifestHashes.usesLibraryOnlyRequiredSha256.orEmpty()
            }
            policy.expectedUsesNativeLibrarySha256?.let {
                lines["usesNativeLibrarySha256"] = manifestHashes.usesNativeLibrarySha256.orEmpty()
            }
            policy.expectedUsesNativeLibraryNameSha256?.let {
                lines["usesNativeLibraryNameSha256"] =
                    manifestHashes.usesNativeLibraryNameSha256.orEmpty()
            }
            policy.expectedUsesNativeLibraryRequiredSha256?.let {
                lines["usesNativeLibraryRequiredSha256"] =
                    manifestHashes.usesNativeLibraryRequiredSha256.orEmpty()
            }
            policy.expectedQueriesSha256?.let {
                lines["queriesSha256"] = manifestHashes.queriesSha256.orEmpty()
            }
            policy.expectedQueriesPackageSha256?.let {
                lines["queriesPackageSha256"] = manifestHashes.queriesPackageSha256.orEmpty()
            }
            policy.expectedQueriesPackageNameSha256?.let {
                lines["queriesPackageNameSha256"] = manifestHashes.queriesPackageNameSha256.orEmpty()
            }
            policy.expectedQueriesProviderSha256?.let {
                lines["queriesProviderSha256"] = manifestHashes.queriesProviderSha256.orEmpty()
            }
            policy.expectedQueriesProviderAuthoritySha256?.let {
                lines["queriesProviderAuthoritySha256"] = manifestHashes.queriesProviderAuthoritySha256.orEmpty()
            }
            policy.expectedQueriesIntentSha256?.let {
                lines["queriesIntentSha256"] = manifestHashes.queriesIntentSha256.orEmpty()
            }
            policy.expectedQueriesIntentActionSha256?.let {
                lines["queriesIntentActionSha256"] = manifestHashes.queriesIntentActionSha256.orEmpty()
            }
            policy.expectedQueriesIntentCategorySha256?.let {
                lines["queriesIntentCategorySha256"] = manifestHashes.queriesIntentCategorySha256.orEmpty()
            }
            policy.expectedQueriesIntentDataSha256?.let {
                lines["queriesIntentDataSha256"] = manifestHashes.queriesIntentDataSha256.orEmpty()
            }
            policy.expectedQueriesIntentDataSchemeSha256?.let {
                lines["queriesIntentDataSchemeSha256"] = manifestHashes.queriesIntentDataSchemeSha256.orEmpty()
            }
            policy.expectedQueriesIntentDataAuthoritySha256?.let {
                lines["queriesIntentDataAuthoritySha256"] = manifestHashes.queriesIntentDataAuthoritySha256.orEmpty()
            }
            policy.expectedQueriesIntentDataPathSha256?.let {
                lines["queriesIntentDataPathSha256"] = manifestHashes.queriesIntentDataPathSha256.orEmpty()
            }
            policy.expectedQueriesIntentDataMimeTypeSha256?.let {
                lines["queriesIntentDataMimeTypeSha256"] = manifestHashes.queriesIntentDataMimeTypeSha256.orEmpty()
            }
            policy.expectedApplicationSemanticsSha256?.let {
                lines["applicationSemanticsSha256"] = manifestHashes.applicationSemanticsSha256.orEmpty()
            }
            if (policy.expectedApplicationFieldValues.isNotEmpty()) {
                policy.expectedApplicationFieldValues.keys.sorted().forEach { key ->
                    lines["applicationField.$key"] = manifestHashes.applicationFieldValues[key].orEmpty()
                }
            }
        }

        if (policy.expectedMetaData.isNotEmpty()) {
            val metaData = packageManager.safeMetaData(packageName)
            policy.expectedMetaData.keys.sorted().forEach { key ->
                lines["metaData.$key"] = sanitizeMetaData(metaData?.get(key))
            }
        }

        return lines.entries.joinToString(separator = "\n") { (key, value) ->
            "$key=${sanitize(value)}"
        }
    }

    fun capturePolicy(policy: TamperPolicy): String {
        val lines = linkedMapOf<String, String>()
        policy.expectedPackageName?.let { lines["expectedPackage"] = sanitize(it) }
        if (policy.allowedInstallerPackages.isNotEmpty()) {
            lines["allowedInstaller"] = policy.allowedInstallerPackages.sorted().joinToString(",")
        }
        if (policy.allowedSigningCertSha256.isNotEmpty()) {
            lines["allowedCertSha256"] = policy.allowedSigningCertSha256.sorted().joinToString(",")
        }
        policy.expectedApkSha256?.let { lines["expectedApkSha256"] = it }
        policy.expectedNativeLibSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedLibSha256.${sanitize(name)}"] = digest
        }
        policy.expectedManifestEntrySha256?.let { lines["expectedManifestEntrySha256"] = it }
        policy.expectedDexSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedDexSha256.${sanitize(name)}"] = digest
        }
        policy.expectedDexSectionSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedDexSectionSha256.${sanitize(name)}"] = digest
        }
        policy.expectedDexMethodSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedDexMethodSha256.${sanitize(name)}"] = digest
        }
        policy.expectedSplitApkSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedSplitSha256.${sanitize(name)}"] = digest
        }
        policy.expectedSplitInventorySha256?.let { lines["expectedSplitInventorySha256"] = it }
        policy.expectedDynamicFeatureSplitSha256?.let { lines["expectedDynamicFeatureSplitSha256"] = it }
        policy.expectedDynamicFeatureSplitNameSha256?.let { lines["expectedDynamicFeatureSplitNameSha256"] = it }
        policy.expectedConfigSplitAxisSha256?.let { lines["expectedConfigSplitAxisSha256"] = it }
        policy.expectedConfigSplitNameSha256?.let { lines["expectedConfigSplitNameSha256"] = it }
        policy.expectedConfigSplitAbiSha256?.let { lines["expectedConfigSplitAbiSha256"] = it }
        policy.expectedConfigSplitLocaleSha256?.let { lines["expectedConfigSplitLocaleSha256"] = it }
        policy.expectedConfigSplitDensitySha256?.let { lines["expectedConfigSplitDensitySha256"] = it }
        policy.expectedElfSectionSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedElfSectionSha256.${sanitize(name)}"] = digest
        }
        policy.expectedElfExportSymbolSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedElfExportSymbolSha256.${sanitize(name)}"] = digest
        }
        policy.expectedRequestedPermissionsSha256?.let { lines["expectedRequestedPermissionsSha256"] = it }
        policy.expectedElfExportGraphSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedElfExportGraphSha256.${sanitize(name)}"] = digest
        }
        policy.expectedRequestedPermissionSemanticsSha256?.let {
            lines["expectedRequestedPermissionSemanticsSha256"] = it
        }
        policy.expectedDeclaredPermissionSemanticsSha256?.let {
            lines["expectedDeclaredPermissionSemanticsSha256"] = it
        }
        policy.expectedDeclaredPermissionFieldValues.toSortedMap().forEach { (name, value) ->
            lines["expectedDeclaredPermissionField.${sanitize(name)}"] = sanitize(value)
        }
        policy.expectedComponentSignatureSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedComponentSignatureSha256.${sanitize(name)}"] = digest
        }
        policy.expectedComponentFieldValues.toSortedMap().forEach { (name, value) ->
            lines["expectedComponentField.${sanitize(name)}"] = sanitize(value)
        }
        policy.expectedProviderUriPermissionPatternsSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedProviderUriPermissionPatternsSha256.${sanitize(name)}"] = digest
        }
        policy.expectedProviderPathPermissionsSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedProviderPathPermissionsSha256.${sanitize(name)}"] = digest
        }
        policy.expectedProviderAuthoritySetSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedProviderAuthoritySetSha256.${sanitize(name)}"] = digest
        }
        policy.expectedProviderSemanticsSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedProviderSemanticsSha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterSha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterActionSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterActionSha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterCategorySha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterCategorySha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterDataSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterDataSha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterDataSchemeSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterDataSchemeSha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterDataAuthoritySha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterDataAuthoritySha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterDataPathSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterDataPathSha256.${sanitize(name)}"] = digest
        }
        policy.expectedIntentFilterDataMimeTypeSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedIntentFilterDataMimeTypeSha256.${sanitize(name)}"] = digest
        }
        policy.expectedGrantUriPermissionSha256.toSortedMap().forEach { (name, digest) ->
            lines["expectedGrantUriPermissionSha256.${sanitize(name)}"] = digest
        }
        policy.expectedUsesFeatureSha256?.let { lines["expectedUsesFeatureSha256"] = it }
        policy.expectedUsesFeatureNameSha256?.let { lines["expectedUsesFeatureNameSha256"] = it }
        policy.expectedUsesFeatureRequiredSha256?.let { lines["expectedUsesFeatureRequiredSha256"] = it }
        policy.expectedUsesFeatureGlEsVersionSha256?.let { lines["expectedUsesFeatureGlEsVersionSha256"] = it }
        policy.expectedUsesSdkSha256?.let { lines["expectedUsesSdkSha256"] = it }
        policy.expectedUsesSdkMinSha256?.let { lines["expectedUsesSdkMinSha256"] = it }
        policy.expectedUsesSdkTargetSha256?.let { lines["expectedUsesSdkTargetSha256"] = it }
        policy.expectedUsesSdkMaxSha256?.let { lines["expectedUsesSdkMaxSha256"] = it }
        policy.expectedSupportsScreensSha256?.let { lines["expectedSupportsScreensSha256"] = it }
        policy.expectedSupportsScreensSmallScreensSha256?.let {
            lines["expectedSupportsScreensSmallScreensSha256"] = it
        }
        policy.expectedSupportsScreensNormalScreensSha256?.let {
            lines["expectedSupportsScreensNormalScreensSha256"] = it
        }
        policy.expectedSupportsScreensLargeScreensSha256?.let {
            lines["expectedSupportsScreensLargeScreensSha256"] = it
        }
        policy.expectedSupportsScreensXlargeScreensSha256?.let {
            lines["expectedSupportsScreensXlargeScreensSha256"] = it
        }
        policy.expectedSupportsScreensResizeableSha256?.let {
            lines["expectedSupportsScreensResizeableSha256"] = it
        }
        policy.expectedSupportsScreensAnyDensitySha256?.let {
            lines["expectedSupportsScreensAnyDensitySha256"] = it
        }
        policy.expectedSupportsScreensRequiresSmallestWidthDpSha256?.let {
            lines["expectedSupportsScreensRequiresSmallestWidthDpSha256"] = it
        }
        policy.expectedSupportsScreensCompatibleWidthLimitDpSha256?.let {
            lines["expectedSupportsScreensCompatibleWidthLimitDpSha256"] = it
        }
        policy.expectedSupportsScreensLargestWidthLimitDpSha256?.let {
            lines["expectedSupportsScreensLargestWidthLimitDpSha256"] = it
        }
        policy.expectedCompatibleScreensSha256?.let { lines["expectedCompatibleScreensSha256"] = it }
        policy.expectedCompatibleScreensScreenSizeSha256?.let {
            lines["expectedCompatibleScreensScreenSizeSha256"] = it
        }
        policy.expectedCompatibleScreensScreenDensitySha256?.let {
            lines["expectedCompatibleScreensScreenDensitySha256"] = it
        }
        policy.expectedUsesLibrarySha256?.let { lines["expectedUsesLibrarySha256"] = it }
        policy.expectedUsesLibraryNameSha256?.let { lines["expectedUsesLibraryNameSha256"] = it }
        policy.expectedUsesLibraryRequiredSha256?.let { lines["expectedUsesLibraryRequiredSha256"] = it }
        policy.expectedUsesLibraryOnlySha256?.let { lines["expectedUsesLibraryOnlySha256"] = it }
        policy.expectedUsesLibraryOnlyNameSha256?.let {
            lines["expectedUsesLibraryOnlyNameSha256"] = it
        }
        policy.expectedUsesLibraryOnlyRequiredSha256?.let {
            lines["expectedUsesLibraryOnlyRequiredSha256"] = it
        }
        policy.expectedUsesNativeLibrarySha256?.let { lines["expectedUsesNativeLibrarySha256"] = it }
        policy.expectedUsesNativeLibraryNameSha256?.let {
            lines["expectedUsesNativeLibraryNameSha256"] = it
        }
        policy.expectedUsesNativeLibraryRequiredSha256?.let {
            lines["expectedUsesNativeLibraryRequiredSha256"] = it
        }
        policy.expectedQueriesSha256?.let { lines["expectedQueriesSha256"] = it }
        policy.expectedQueriesPackageSha256?.let { lines["expectedQueriesPackageSha256"] = it }
        policy.expectedQueriesPackageNameSha256?.let { lines["expectedQueriesPackageNameSha256"] = it }
        policy.expectedQueriesProviderSha256?.let { lines["expectedQueriesProviderSha256"] = it }
        policy.expectedQueriesProviderAuthoritySha256?.let { lines["expectedQueriesProviderAuthoritySha256"] = it }
        policy.expectedQueriesIntentSha256?.let { lines["expectedQueriesIntentSha256"] = it }
        policy.expectedQueriesIntentActionSha256?.let { lines["expectedQueriesIntentActionSha256"] = it }
        policy.expectedQueriesIntentCategorySha256?.let { lines["expectedQueriesIntentCategorySha256"] = it }
        policy.expectedQueriesIntentDataSha256?.let { lines["expectedQueriesIntentDataSha256"] = it }
        policy.expectedQueriesIntentDataSchemeSha256?.let { lines["expectedQueriesIntentDataSchemeSha256"] = it }
        policy.expectedQueriesIntentDataAuthoritySha256?.let { lines["expectedQueriesIntentDataAuthoritySha256"] = it }
        policy.expectedQueriesIntentDataPathSha256?.let { lines["expectedQueriesIntentDataPathSha256"] = it }
        policy.expectedQueriesIntentDataMimeTypeSha256?.let { lines["expectedQueriesIntentDataMimeTypeSha256"] = it }
        policy.expectedApplicationSemanticsSha256?.let { lines["expectedApplicationSemanticsSha256"] = it }
        policy.expectedApplicationFieldValues.toSortedMap().forEach { (name, value) ->
            lines["expectedApplicationField.${sanitize(name)}"] = sanitize(value)
        }
        policy.expectedMetaData.toSortedMap().forEach { (name, value) ->
            lines["expectedMetaData.${sanitize(name)}"] = sanitize(value)
        }
        return lines.entries.joinToString(separator = "\n") { (key, value) -> "$key=$value" }
    }

    private fun sanitize(value: String): String =
        value.replace('\n', '_').replace('\r', '_')

    private fun sanitizeMetaData(value: Any?): String = when (value) {
        null -> ""
        is Boolean, is Int, is Long, is Float, is Double -> value.toString()
        else -> sanitize(value.toString())
    }

    private fun hashNativeLibraryHex(nativeLibraryDir: String?, fileName: String): String? {
        if (nativeLibraryDir.isNullOrBlank()) return null
        return hashFileHex(File(nativeLibraryDir, fileName).absolutePath)
    }

    private fun hashFileHex(path: String?): String? {
        if (path.isNullOrBlank()) return null
        val file = File(path)
        if (!file.isFile) return null
        return try {
            FileInputStream(file).use { input ->
                val digest = MessageDigest.getInstance("SHA-256")
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = input.read(buffer)
                    if (read <= 0) break
                    digest.update(buffer, 0, read)
                }
                digest.digest().toHex()
            }
        } catch (_: Throwable) {
            null
        }
    }

    private fun hashZipEntries(apkPath: String?, entryNames: Set<String>): Map<String, String> {
        if (apkPath.isNullOrBlank() || entryNames.isEmpty()) return emptyMap()
        val file = File(apkPath)
        if (!file.isFile) return emptyMap()
        return try {
            ZipFile(file).use { zip ->
                entryNames.associateWith { entryName ->
                    val entry = zip.getEntry(entryName) ?: return@associateWith ""
                    zip.getInputStream(entry).use { input ->
                        val digest = MessageDigest.getInstance("SHA-256")
                        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                        while (true) {
                            val read = input.read(buffer)
                            if (read <= 0) break
                            digest.update(buffer, 0, read)
                        }
                        digest.digest().toHex()
                    }
                }
            }
        } catch (_: Throwable) {
            emptyMap()
        }
    }

    private fun collectManifestSubtreeFingerprints(
        apkPath: String?,
        requestedIntentFilters: Set<String>,
        requestedGrantUriPermissions: Set<String>,
    ): ManifestSubtreeFingerprints {
        if (apkPath.isNullOrBlank() || (requestedIntentFilters.isEmpty() && requestedGrantUriPermissions.isEmpty())) {
            return ManifestSubtreeFingerprints.EMPTY
        }
        val file = File(apkPath)
        if (!file.isFile) return ManifestSubtreeFingerprints.EMPTY
        return try {
            ZipFile(file).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return ManifestSubtreeFingerprints.EMPTY
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                parseManifestSubtreeFingerprints(bytes, requestedIntentFilters, requestedGrantUriPermissions)
            }
        } catch (_: Throwable) {
            ManifestSubtreeFingerprints.EMPTY
        }
    }

    private fun collectManifestGlobalFingerprints(apkPath: String?): ManifestGlobalFingerprints {
        if (apkPath.isNullOrBlank()) return ManifestGlobalFingerprints.EMPTY
        val file = File(apkPath)
        if (!file.isFile) return ManifestGlobalFingerprints.EMPTY
        return try {
            ZipFile(file).use { zip ->
                val entry = zip.getEntry("AndroidManifest.xml") ?: return ManifestGlobalFingerprints.EMPTY
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                parseManifestGlobalFingerprints(bytes)
            }
        } catch (_: Throwable) {
            ManifestGlobalFingerprints.EMPTY
        }
    }

    private fun parseManifestGlobalFingerprints(manifestBytes: ByteArray): ManifestGlobalFingerprints {
        val usesFeatures = mutableListOf<String>()
        val usesFeatureNames = mutableListOf<String>()
        val usesFeatureRequired = mutableListOf<String>()
        val usesFeatureGlEsVersions = mutableListOf<String>()
        val usesSdk = mutableListOf<String>()
        val usesSdkMin = mutableListOf<String>()
        val usesSdkTarget = mutableListOf<String>()
        val usesSdkMax = mutableListOf<String>()
        val supportsScreens = mutableListOf<String>()
        val supportsScreensSmallScreens = mutableListOf<String>()
        val supportsScreensNormalScreens = mutableListOf<String>()
        val supportsScreensLargeScreens = mutableListOf<String>()
        val supportsScreensXlargeScreens = mutableListOf<String>()
        val supportsScreensResizeable = mutableListOf<String>()
        val supportsScreensAnyDensity = mutableListOf<String>()
        val supportsScreensRequiresSmallestWidthDp = mutableListOf<String>()
        val supportsScreensCompatibleWidthLimitDp = mutableListOf<String>()
        val supportsScreensLargestWidthLimitDp = mutableListOf<String>()
        val compatibleScreens = mutableListOf<String>()
        val compatibleScreensScreenSizes = mutableListOf<String>()
        val compatibleScreensScreenDensities = mutableListOf<String>()
        val usesLibraries = mutableListOf<String>()
        val usesLibraryNames = mutableListOf<String>()
        val usesLibraryRequired = mutableListOf<String>()
        val usesLibraryOnly = mutableListOf<String>()
        val usesLibraryOnlyNames = mutableListOf<String>()
        val usesLibraryOnlyRequired = mutableListOf<String>()
        val usesNativeLibraries = mutableListOf<String>()
        val usesNativeLibraryNames = mutableListOf<String>()
        val usesNativeLibraryRequired = mutableListOf<String>()
        val queryPackages = mutableListOf<String>()
        val queryPackageNames = mutableListOf<String>()
        val queryProviders = mutableListOf<String>()
        val queryProviderAuthorities = mutableListOf<String>()
        val queryIntents = mutableListOf<String>()
        val queryIntentActions = mutableListOf<String>()
        val queryIntentCategories = mutableListOf<String>()
        val queryIntentData = mutableListOf<String>()
        val queryIntentDataSchemes = mutableListOf<String>()
        val queryIntentDataAuthorities = mutableListOf<String>()
        val queryIntentDataPaths = mutableListOf<String>()
        val queryIntentDataMimeTypes = mutableListOf<String>()
        val applicationFieldValues = linkedMapOf<String, String>()
        val applicationSemanticsFieldValues = linkedMapOf<String, String>()
        var inQueries = false
        var inCompatibleScreens = false
        var currentQueryIntent: MutableList<String>? = null

        val parsed = walkBinaryXml(
            xmlBytes = manifestBytes,
            onStartTag = { name, attrs ->
                when (name) {
                    "queries" -> inQueries = true
                    "compatible-screens" -> inCompatibleScreens = true
                    "application" -> {
                        applicationDriftManifestFields.forEach { field ->
                            attrs[field]?.takeIf { it.isNotBlank() }?.let {
                                applicationFieldValues["application#$field"] = it
                                if (field in applicationSemanticsManifestFields) {
                                    applicationSemanticsFieldValues["application#$field"] = it
                                }
                            }
                        }
                    }
                    "uses-feature" -> {
                        usesFeatures += canonicalizeManifestNode(name, attrs)
                        attrs["name"]?.takeIf { it.isNotBlank() }?.let(usesFeatureNames::add)
                        attrs["required"]?.takeIf { it.isNotBlank() }?.let(usesFeatureRequired::add)
                        attrs["glEsVersion"]?.takeIf { it.isNotBlank() }?.let(usesFeatureGlEsVersions::add)
                    }
                    "uses-sdk" -> {
                        usesSdk += canonicalizeManifestNode(name, attrs)
                        attrs["minSdkVersion"]?.takeIf { it.isNotBlank() }?.let(usesSdkMin::add)
                        attrs["targetSdkVersion"]?.takeIf { it.isNotBlank() }?.let(usesSdkTarget::add)
                        attrs["maxSdkVersion"]?.takeIf { it.isNotBlank() }?.let(usesSdkMax::add)
                    }
                    "supports-screens" -> {
                        supportsScreens += canonicalizeManifestNode(name, attrs)
                        attrs["smallScreens"]?.takeIf { it.isNotBlank() }?.let(supportsScreensSmallScreens::add)
                        attrs["normalScreens"]?.takeIf { it.isNotBlank() }?.let(supportsScreensNormalScreens::add)
                        attrs["largeScreens"]?.takeIf { it.isNotBlank() }?.let(supportsScreensLargeScreens::add)
                        attrs["xlargeScreens"]?.takeIf { it.isNotBlank() }?.let(supportsScreensXlargeScreens::add)
                        attrs["resizeable"]?.takeIf { it.isNotBlank() }?.let(supportsScreensResizeable::add)
                        attrs["anyDensity"]?.takeIf { it.isNotBlank() }?.let(supportsScreensAnyDensity::add)
                        attrs["requiresSmallestWidthDp"]?.takeIf { it.isNotBlank() }
                            ?.let(supportsScreensRequiresSmallestWidthDp::add)
                        attrs["compatibleWidthLimitDp"]?.takeIf { it.isNotBlank() }
                            ?.let(supportsScreensCompatibleWidthLimitDp::add)
                        attrs["largestWidthLimitDp"]?.takeIf { it.isNotBlank() }
                            ?.let(supportsScreensLargestWidthLimitDp::add)
                    }
                    "screen" -> if (inCompatibleScreens) {
                        compatibleScreens += canonicalizeManifestNode(name, attrs)
                        attrs["screenSize"]?.takeIf { it.isNotBlank() }?.let(compatibleScreensScreenSizes::add)
                        attrs["screenDensity"]?.takeIf { it.isNotBlank() }?.let(compatibleScreensScreenDensities::add)
                    }
                    "uses-library" -> {
                        val node = canonicalizeManifestNode(name, attrs)
                        usesLibraries += node
                        usesLibraryOnly += node
                        attrs["name"]?.takeIf { it.isNotBlank() }?.let {
                            usesLibraryNames += it
                            usesLibraryOnlyNames += it
                        }
                        attrs["required"]?.takeIf { it.isNotBlank() }?.let {
                            usesLibraryRequired += it
                            usesLibraryOnlyRequired += it
                        }
                    }
                    "uses-native-library" -> {
                        val node = canonicalizeManifestNode(name, attrs)
                        usesLibraries += node
                        usesNativeLibraries += node
                        attrs["name"]?.takeIf { it.isNotBlank() }?.let {
                            usesLibraryNames += it
                            usesNativeLibraryNames += it
                        }
                        attrs["required"]?.takeIf { it.isNotBlank() }?.let {
                            usesLibraryRequired += it
                            usesNativeLibraryRequired += it
                        }
                    }
                    "package" -> if (inQueries) {
                        queryPackages += canonicalizeManifestNode(name, attrs)
                        attrs["name"]?.takeIf { it.isNotBlank() }?.let(queryPackageNames::add)
                    }
                    "provider" -> if (inQueries) {
                        queryProviders += canonicalizeManifestNode(name, attrs)
                        attrs["authorities"]?.takeIf { it.isNotBlank() }?.let { authorities ->
                            authorities.split(';')
                                .map { value -> value.trim() }
                                .filter { value -> value.isNotBlank() }
                                .sorted()
                                .forEach(queryProviderAuthorities::add)
                        }
                    }
                    "intent" -> if (inQueries) currentQueryIntent = mutableListOf(canonicalizeManifestNode(name, attrs))
                    "action" -> if (inQueries) {
                        val node = canonicalizeManifestNode(name, attrs)
                        currentQueryIntent?.add(node)
                        queryIntentActions += node
                    }
                    "category" -> if (inQueries) {
                        val node = canonicalizeManifestNode(name, attrs)
                        currentQueryIntent?.add(node)
                        queryIntentCategories += node
                    }
                    "data" -> if (inQueries) {
                        val node = canonicalizeManifestNode(name, attrs)
                        currentQueryIntent?.add(node)
                        queryIntentData += node
                        attrs["scheme"]?.takeIf { it.isNotBlank() }?.let(queryIntentDataSchemes::add)
                        buildString {
                            val host = attrs["host"].orEmpty()
                            val port = attrs["port"].orEmpty()
                            if (host.isNotBlank()) {
                                append(host)
                                if (port.isNotBlank()) {
                                    append(':')
                                    append(port)
                                }
                            }
                        }.takeIf { it.isNotBlank() }?.let(queryIntentDataAuthorities::add)
                        listOf("path", "pathPrefix", "pathPattern", "pathAdvancedPattern", "pathSuffix")
                            .mapNotNull { field -> attrs[field]?.takeIf { it.isNotBlank() }?.let { "$field=$it" } }
                            .forEach(queryIntentDataPaths::add)
                        attrs["mimeType"]?.takeIf { it.isNotBlank() }?.let(queryIntentDataMimeTypes::add)
                    }
                }
            },
            onEndTag = { name ->
                when (name) {
                    "queries" -> inQueries = false
                    "compatible-screens" -> inCompatibleScreens = false
                    "intent" -> {
                        currentQueryIntent?.let { lines ->
                            queryIntents += lines.joinToString(separator = "\n")
                        }
                        currentQueryIntent = null
                    }
                }
            },
        )
        if (!parsed) return ManifestGlobalFingerprints.EMPTY

        val queriesLines = buildList {
            addAll(queryPackages.sorted().map { "package::$it" })
            addAll(queryProviders.sorted().map { "provider::$it" })
            addAll(queryIntents.sorted().map { "intent::$it" })
        }
        fun hashLines(values: List<String>): String? = values.sorted()
            .joinToString(separator = "\n")
            .takeIf { it.isNotBlank() }
            ?.let { sha256Hex(it.toByteArray()) }
        return ManifestGlobalFingerprints(
            usesFeatureSha256 = hashLines(usesFeatures),
            usesFeatureNameSha256 = hashLines(usesFeatureNames),
            usesFeatureRequiredSha256 = hashLines(usesFeatureRequired),
            usesFeatureGlEsVersionSha256 = hashLines(usesFeatureGlEsVersions),
            usesSdkSha256 = hashLines(usesSdk),
            usesSdkMinVersionSha256 = hashLines(usesSdkMin),
            usesSdkTargetVersionSha256 = hashLines(usesSdkTarget),
            usesSdkMaxVersionSha256 = hashLines(usesSdkMax),
            supportsScreensSha256 = hashLines(supportsScreens),
            supportsScreensSmallScreensSha256 = hashLines(supportsScreensSmallScreens),
            supportsScreensNormalScreensSha256 = hashLines(supportsScreensNormalScreens),
            supportsScreensLargeScreensSha256 = hashLines(supportsScreensLargeScreens),
            supportsScreensXlargeScreensSha256 = hashLines(supportsScreensXlargeScreens),
            supportsScreensResizeableSha256 = hashLines(supportsScreensResizeable),
            supportsScreensAnyDensitySha256 = hashLines(supportsScreensAnyDensity),
            supportsScreensRequiresSmallestWidthDpSha256 =
                hashLines(supportsScreensRequiresSmallestWidthDp),
            supportsScreensCompatibleWidthLimitDpSha256 =
                hashLines(supportsScreensCompatibleWidthLimitDp),
            supportsScreensLargestWidthLimitDpSha256 =
                hashLines(supportsScreensLargestWidthLimitDp),
            compatibleScreensSha256 = hashLines(compatibleScreens),
            compatibleScreensScreenSizeSha256 = hashLines(compatibleScreensScreenSizes),
            compatibleScreensScreenDensitySha256 = hashLines(compatibleScreensScreenDensities),
            usesLibrarySha256 = hashLines(usesLibraries),
            usesLibraryNameSha256 = hashLines(usesLibraryNames),
            usesLibraryRequiredSha256 = hashLines(usesLibraryRequired),
            usesLibraryOnlySha256 = hashLines(usesLibraryOnly),
            usesLibraryOnlyNameSha256 = hashLines(usesLibraryOnlyNames),
            usesLibraryOnlyRequiredSha256 = hashLines(usesLibraryOnlyRequired),
            usesNativeLibrarySha256 = hashLines(usesNativeLibraries),
            usesNativeLibraryNameSha256 = hashLines(usesNativeLibraryNames),
            usesNativeLibraryRequiredSha256 = hashLines(usesNativeLibraryRequired),
            queriesPackageSha256 = hashLines(queryPackages),
            queriesPackageNameSha256 = hashLines(queryPackageNames),
            queriesProviderSha256 = hashLines(queryProviders),
            queriesProviderAuthoritySha256 = hashLines(queryProviderAuthorities),
            queriesIntentSha256 = hashLines(queryIntents),
            queriesIntentActionSha256 = hashLines(queryIntentActions),
            queriesIntentCategorySha256 = hashLines(queryIntentCategories),
            queriesIntentDataSha256 = hashLines(queryIntentData),
            queriesIntentDataSchemeSha256 = hashLines(queryIntentDataSchemes),
            queriesIntentDataAuthoritySha256 = hashLines(queryIntentDataAuthorities),
            queriesIntentDataPathSha256 = hashLines(queryIntentDataPaths),
            queriesIntentDataMimeTypeSha256 = hashLines(queryIntentDataMimeTypes),
            queriesSha256 = hashLines(queriesLines),
            applicationSemanticsSha256 = applicationSemanticsFieldValues.entries
                .sortedBy { it.key }
                .joinToString(separator = "\n") { (key, value) -> "$key=$value" }
                .takeIf { it.isNotBlank() }
                ?.let { sha256Hex(it.toByteArray()) },
            applicationFieldValues = applicationFieldValues,
        )
    }

    private fun parseManifestSubtreeFingerprints(
        manifestBytes: ByteArray,
        requestedIntentFilters: Set<String>,
        requestedGrantUriPermissions: Set<String>,
    ): ManifestSubtreeFingerprints {
        val intentFilters = linkedMapOf<String, MutableList<String>>()
        val intentFilterActions = linkedMapOf<String, MutableList<String>>()
        val intentFilterCategories = linkedMapOf<String, MutableList<String>>()
        val intentFilterData = linkedMapOf<String, MutableList<String>>()
        val intentFilterDataSchemes = linkedMapOf<String, MutableList<String>>()
        val intentFilterDataAuthorities = linkedMapOf<String, MutableList<String>>()
        val intentFilterDataPaths = linkedMapOf<String, MutableList<String>>()
        val intentFilterDataMimeTypes = linkedMapOf<String, MutableList<String>>()
        val grantUriPermissions = linkedMapOf<String, MutableList<String>>()
        var manifestPackage = ""
        var currentComponent: ManifestComponent? = null
        var currentIntentFilterLines: MutableList<String>? = null
        var currentIntentFilterActions: MutableList<String>? = null
        var currentIntentFilterCategories: MutableList<String>? = null
        var currentIntentFilterData: MutableList<String>? = null

        val parsed = walkBinaryXml(
            xmlBytes = manifestBytes,
            onStartTag = { name, attrs ->
                when (name) {
                    "manifest" -> manifestPackage = attrs["package"].orEmpty()
                    "activity", "activity-alias", "service", "receiver", "provider" -> {
                        val rawName = attrs["name"].orEmpty()
                        if (rawName.isNotBlank()) {
                            currentComponent = ManifestComponent(
                                type = name,
                                name = normalizeManifestClassName(manifestPackage, rawName),
                            )
                        }
                    }
                    "intent-filter" -> {
                        val component = currentComponent ?: return@walkBinaryXml
                        val componentKey = "${component.type}:${component.name}"
                        if (componentKey !in requestedIntentFilters) return@walkBinaryXml
                        currentIntentFilterLines = mutableListOf(
                            canonicalizeManifestNode("intent-filter", attrs),
                        )
                        currentIntentFilterActions = mutableListOf()
                        currentIntentFilterCategories = mutableListOf()
                        currentIntentFilterData = mutableListOf()
                    }
                    "action", "category", "data" -> {
                        currentIntentFilterLines?.add(canonicalizeManifestNode(name, attrs))
                        when (name) {
                            "action" -> currentIntentFilterActions?.add(canonicalizeManifestNode(name, attrs))
                            "category" -> currentIntentFilterCategories?.add(canonicalizeManifestNode(name, attrs))
                            "data" -> {
                                currentIntentFilterData?.add(canonicalizeManifestNode(name, attrs))
                                val component = currentComponent ?: return@walkBinaryXml
                                val componentKey = "${component.type}:${component.name}"
                                if (componentKey !in requestedIntentFilters) return@walkBinaryXml
                                attrs["scheme"]?.takeIf { it.isNotBlank() }?.let {
                                    intentFilterDataSchemes.getOrPut(componentKey) { mutableListOf() }.add(it)
                                }
                                buildString {
                                    val host = attrs["host"].orEmpty()
                                    val port = attrs["port"].orEmpty()
                                    if (host.isNotBlank()) {
                                        append(host)
                                        if (port.isNotBlank()) {
                                            append(':')
                                            append(port)
                                        }
                                    }
                                }.takeIf { it.isNotBlank() }?.let {
                                    intentFilterDataAuthorities.getOrPut(componentKey) { mutableListOf() }.add(it)
                                }
                                listOf("path", "pathPrefix", "pathPattern", "pathAdvancedPattern", "pathSuffix")
                                    .mapNotNull { field -> attrs[field]?.takeIf { it.isNotBlank() }?.let { "$field=$it" } }
                                    .forEach {
                                        intentFilterDataPaths.getOrPut(componentKey) { mutableListOf() }.add(it)
                                    }
                                attrs["mimeType"]?.takeIf { it.isNotBlank() }?.let {
                                    intentFilterDataMimeTypes.getOrPut(componentKey) { mutableListOf() }.add(it)
                                }
                            }
                        }
                    }
                    "grant-uri-permission" -> {
                        val component = currentComponent ?: return@walkBinaryXml
                        if (component.type != "provider") return@walkBinaryXml
                        val providerKey = "provider:${component.name}"
                        if (providerKey !in requestedGrantUriPermissions) return@walkBinaryXml
                        grantUriPermissions.getOrPut(providerKey) { mutableListOf() }
                            .add(canonicalizeManifestNode(name, attrs))
                    }
                }
            },
            onEndTag = { name ->
                when (name) {
                    "intent-filter" -> {
                        val component = currentComponent
                        val lines = currentIntentFilterLines
                        if (component != null && lines != null) {
                            val componentKey = "${component.type}:${component.name}"
                            if (componentKey in requestedIntentFilters) {
                                intentFilters.getOrPut(componentKey) { mutableListOf() }
                                    .add(lines.joinToString(separator = "\n"))
                                currentIntentFilterActions
                                    ?.takeIf { it.isNotEmpty() }
                                    ?.let { values ->
                                        intentFilterActions.getOrPut(componentKey) { mutableListOf() }
                                            .addAll(values)
                                    }
                                currentIntentFilterCategories
                                    ?.takeIf { it.isNotEmpty() }
                                    ?.let { values ->
                                        intentFilterCategories.getOrPut(componentKey) { mutableListOf() }
                                            .addAll(values)
                                    }
                                currentIntentFilterData
                                    ?.takeIf { it.isNotEmpty() }
                                    ?.let { values ->
                                        intentFilterData.getOrPut(componentKey) { mutableListOf() }
                                            .addAll(values)
                                    }
                            }
                        }
                        currentIntentFilterLines = null
                        currentIntentFilterActions = null
                        currentIntentFilterCategories = null
                        currentIntentFilterData = null
                    }
                    "activity", "activity-alias", "service", "receiver", "provider" -> {
                        if (currentComponent?.type == name) {
                            currentComponent = null
                        }
                    }
                }
            },
        )
        if (!parsed) return ManifestSubtreeFingerprints.EMPTY

        return ManifestSubtreeFingerprints(
            intentFilterHashes = requestedIntentFilters.associateWith { key ->
                intentFilters[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n---\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            intentFilterActionHashes = requestedIntentFilters.associateWith { key ->
                intentFilterActions[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            intentFilterCategoryHashes = requestedIntentFilters.associateWith { key ->
                intentFilterCategories[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            intentFilterDataHashes = requestedIntentFilters.associateWith { key ->
                intentFilterData[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            intentFilterDataSchemeHashes = requestedIntentFilters.associateWith { key ->
                intentFilterDataSchemes[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            intentFilterDataAuthorityHashes = requestedIntentFilters.associateWith { key ->
                intentFilterDataAuthorities[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            intentFilterDataPathHashes = requestedIntentFilters.associateWith { key ->
                intentFilterDataPaths[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            intentFilterDataMimeTypeHashes = requestedIntentFilters.associateWith { key ->
                intentFilterDataMimeTypes[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
            grantUriPermissionHashes = requestedGrantUriPermissions.associateWith { key ->
                grantUriPermissions[key]
                    ?.sorted()
                    ?.joinToString(separator = "\n")
                    ?.takeIf { it.isNotBlank() }
                    ?.let { sha256Hex(it.toByteArray()) }
                    .orEmpty()
            },
        )
    }

    private fun hashDexSections(
        apkPath: String?,
        sectionsByEntry: Map<String, List<String>>,
    ): Map<String, String> {
        if (apkPath.isNullOrBlank() || sectionsByEntry.isEmpty()) return emptyMap()
        val file = File(apkPath)
        if (!file.isFile) return emptyMap()
        return try {
            ZipFile(file).use { zip ->
                buildMap {
                    sectionsByEntry.forEach { (entryName, sectionNames) ->
                        val entry = zip.getEntry(entryName) ?: return@forEach
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        val hashes = parseDexSectionHashes(bytes, sectionNames.toSet())
                        sectionNames.forEach { sectionName ->
                            put("$entryName#$sectionName", hashes[sectionName].orEmpty())
                        }
                    }
                }
            }
        } catch (_: Throwable) {
            emptyMap()
        }
    }

    private fun hashDexMethods(
        apkPath: String?,
        methodsByEntry: Map<String, List<String>>,
    ): Map<String, String> {
        if (apkPath.isNullOrBlank() || methodsByEntry.isEmpty()) return emptyMap()
        val file = File(apkPath)
        if (!file.isFile) return emptyMap()
        return try {
            ZipFile(file).use { zip ->
                buildMap {
                    methodsByEntry.forEach { (entryName, methodKeys) ->
                        val entry = zip.getEntry(entryName) ?: return@forEach
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        val hashes = parseDexMethodHashes(bytes, methodKeys.toSet())
                        methodKeys.forEach { methodKey ->
                            put("$entryName#$methodKey", hashes[methodKey].orEmpty())
                        }
                    }
                }
            }
        } catch (_: Throwable) {
            emptyMap()
        }
    }

    private fun hashSplitInventory(splitSourceDirs: List<String>): String {
        val payload = splitSourceDirs
            .map { File(it).name }
            .filter { it.isNotBlank() }
            .sorted()
            .joinToString(separator = "\n")
        return sha256Hex(payload.toByteArray())
    }

    private fun hashDynamicFeatureSplits(splitSourceDirs: List<String>): String =
        sha256Hex(
            splitSourceDirs
                .map { File(it).name }
                .mapNotNull(::normalizeDynamicFeatureSplitName)
                .sorted()
                .joinToString(separator = "\n")
                .toByteArray(),
        )

    private fun hashDynamicFeatureSplitNames(splitSourceDirs: List<String>): String =
        sha256Hex(
            splitSourceDirs
                .map { File(it).name }
                .filter(::isDynamicFeatureSplitFileName)
                .sorted()
                .joinToString(separator = "\n")
                .toByteArray(),
        )

    private fun hashConfigSplitAxes(splitSourceDirs: List<String>): String =
        sha256Hex(
            splitSourceDirs
                .map { File(it).name }
                .mapNotNull(::normalizeConfigSplitAxis)
                .sorted()
                .joinToString(separator = "\n")
                .toByteArray(),
        )

    private fun hashConfigSplitNames(splitSourceDirs: List<String>): String =
        sha256Hex(
            splitSourceDirs
                .map { File(it).name }
                .filter { normalizeConfigSplitAxis(it) != null }
                .sorted()
                .joinToString(separator = "\n")
                .toByteArray(),
        )

    private fun hashConfigSplitAbis(splitSourceDirs: List<String>): String =
        sha256Hex(
            splitSourceDirs
                .map { File(it).name }
                .mapNotNull(::normalizeConfigSplitAxis)
                .mapNotNull(::normalizeConfigSplitAbiAxis)
                .sorted()
                .joinToString(separator = "\n")
                .toByteArray(),
        )

    private fun hashConfigSplitLocales(splitSourceDirs: List<String>): String =
        sha256Hex(
            splitSourceDirs
                .map { File(it).name }
                .mapNotNull(::normalizeConfigSplitAxis)
                .mapNotNull(::normalizeConfigSplitLocaleAxis)
                .sorted()
                .joinToString(separator = "\n")
                .toByteArray(),
        )

    private fun hashConfigSplitDensities(splitSourceDirs: List<String>): String =
        sha256Hex(
            splitSourceDirs
                .map { File(it).name }
                .mapNotNull(::normalizeConfigSplitAxis)
                .mapNotNull(::normalizeConfigSplitDensityAxis)
                .sorted()
                .joinToString(separator = "\n")
                .toByteArray(),
        )

    private fun normalizeDynamicFeatureSplitName(fileName: String): String? {
        val stem = fileName.removeSuffix(".apk")
        if (stem.isBlank()) return null
        if (stem == "base") return null
        if (normalizeConfigSplitAxis(fileName) != null) return null
        return stem
            .removePrefix("split_")
            .removePrefix("feature_")
            .ifBlank { null }
    }

    private fun isDynamicFeatureSplitFileName(fileName: String): Boolean {
        val stem = fileName.removeSuffix(".apk")
        if (stem.isBlank() || stem == "base") return false
        if (normalizeConfigSplitAxis(fileName) != null) return false
        return true
    }

    private fun normalizeConfigSplitAxis(fileName: String): String? {
        val stem = fileName.removeSuffix(".apk")
        return when {
            stem.startsWith("config.") -> stem.removePrefix("config.").ifBlank { null }
            stem.startsWith("split_config.") -> stem.removePrefix("split_config.").ifBlank { null }
            else -> null
        }
    }

    private fun normalizeConfigSplitAbiAxis(axis: String): String? =
        axis.takeIf { it in KNOWN_CONFIG_SPLIT_ABI_AXES }

    private fun normalizeConfigSplitLocaleAxis(axis: String): String? =
        axis.takeIf {
            CONFIG_SPLIT_LOCALE_REGEX.matches(it) || CONFIG_SPLIT_BCP47_LOCALE_REGEX.matches(it)
        }

    private fun normalizeConfigSplitDensityAxis(axis: String): String? =
        axis.takeIf { CONFIG_SPLIT_DENSITY_REGEX.matches(it) }

    private fun parseDexSectionHashes(
        dexBytes: ByteArray,
        requestedSections: Set<String>,
    ): Map<String, String> {
        if (dexBytes.size < 0x70 || requestedSections.isEmpty()) return emptyMap()
        val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)
        if (dexBytes.copyOfRange(0, 3).decodeToString() != "dex") return emptyMap()
        val fileSize = buffer.getInt(0x20)
        val mapOff = buffer.getInt(0x34)
        if (fileSize <= 0 || fileSize > dexBytes.size || mapOff <= 0 || mapOff + 4 > dexBytes.size) {
            return emptyMap()
        }

        val mapCount = buffer.getInt(mapOff)
        var cursor = mapOff + 4
        val result = linkedMapOf<String, String>()
        repeat(mapCount) {
            if (cursor + 12 > dexBytes.size) return@repeat
            val type = buffer.getShort(cursor).toInt() and 0xFFFF
            val size = buffer.getInt(cursor + 4)
            val offset = buffer.getInt(cursor + 8)
            cursor += 12

            val sectionName = dexSectionName(type)
            if (sectionName !in requestedSections) return@repeat

            val length = dexSectionLength(type, size)
            if (offset < 0 || length <= 0 || offset + length > dexBytes.size) {
                result[sectionName] = ""
                return@repeat
            }
            result[sectionName] = sha256Hex(dexBytes.copyOfRange(offset, offset + length))
        }
        return result
    }

    private fun parseDexMethodHashes(
        dexBytes: ByteArray,
        requestedMethods: Set<String>,
    ): Map<String, String> {
        if (dexBytes.size < 0x70 || requestedMethods.isEmpty()) return emptyMap()
        val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)
        if (dexBytes.copyOfRange(0, 3).decodeToString() != "dex") return emptyMap()

        val stringIdsSize = buffer.getInt(0x38)
        val stringIdsOff = buffer.getInt(0x3C)
        val typeIdsSize = buffer.getInt(0x40)
        val typeIdsOff = buffer.getInt(0x44)
        val protoIdsSize = buffer.getInt(0x48)
        val protoIdsOff = buffer.getInt(0x4C)
        val methodIdsSize = buffer.getInt(0x58)
        val methodIdsOff = buffer.getInt(0x5C)
        val classDefsSize = buffer.getInt(0x60)
        val classDefsOff = buffer.getInt(0x64)
        if (stringIdsSize < 0 || typeIdsSize < 0 || protoIdsSize < 0 || methodIdsSize < 0 || classDefsSize < 0) {
            return emptyMap()
        }
        if (stringIdsOff < 0 || typeIdsOff < 0 || protoIdsOff < 0 || methodIdsOff < 0 || classDefsOff < 0) {
            return emptyMap()
        }
        if (stringIdsOff + stringIdsSize * 4 > dexBytes.size ||
            typeIdsOff + typeIdsSize * 4 > dexBytes.size ||
            protoIdsOff + protoIdsSize * 12 > dexBytes.size ||
            methodIdsOff + methodIdsSize * 8 > dexBytes.size ||
            classDefsOff + classDefsSize * 32 > dexBytes.size
        ) return emptyMap()

        val stringCache = hashMapOf<Int, String>()
        val typeCache = hashMapOf<Int, String>()
        val protoCache = hashMapOf<Int, String>()

        fun readDexString(stringIndex: Int): String {
            if (stringIndex !in 0 until stringIdsSize) return ""
            return stringCache.getOrPut(stringIndex) {
                val stringDataOff = buffer.getInt(stringIdsOff + stringIndex * 4)
                if (stringDataOff !in 0 until dexBytes.size) return@getOrPut ""
                val utf16Length = readUleb128(dexBytes, stringDataOff) ?: return@getOrPut ""
                var end = utf16Length.nextOffset
                while (end < dexBytes.size && dexBytes[end] != 0.toByte()) end++
                if (end > dexBytes.size) return@getOrPut ""
                dexBytes.copyOfRange(utf16Length.nextOffset, end).decodeToString()
            }
        }

        fun readTypeDescriptor(typeIndex: Int): String {
            if (typeIndex !in 0 until typeIdsSize) return ""
            return typeCache.getOrPut(typeIndex) {
                readDexString(buffer.getInt(typeIdsOff + typeIndex * 4))
            }
        }

        fun readProtoDescriptor(protoIndex: Int): String {
            if (protoIndex !in 0 until protoIdsSize) return ""
            return protoCache.getOrPut(protoIndex) {
                val off = protoIdsOff + protoIndex * 12
                val returnType = readTypeDescriptor(buffer.getInt(off + 4))
                val parametersOff = buffer.getInt(off + 8)
                val parameters = if (parametersOff > 0 && parametersOff + 4 <= dexBytes.size) {
                    val size = buffer.getInt(parametersOff)
                    buildString {
                        for (i in 0 until size) {
                            val typeOff = parametersOff + 4 + i * 2
                            if (typeOff + 2 > dexBytes.size) break
                            append(readTypeDescriptor(buffer.getShort(typeOff).toInt() and 0xFFFF))
                        }
                    }
                } else {
                    ""
                }
                "($parameters)$returnType"
            }
        }

        val methodCodeOffsets = hashMapOf<Int, Int>()
        for (classIndex in 0 until classDefsSize) {
            val classDefOff = classDefsOff + classIndex * 32
            val classDataOff = buffer.getInt(classDefOff + 24)
            if (classDataOff <= 0 || classDataOff >= dexBytes.size) continue
            var cursor = classDataOff

            val staticFieldsSize = readUleb128(dexBytes, cursor) ?: continue
            cursor = staticFieldsSize.nextOffset
            val instanceFieldsSize = readUleb128(dexBytes, cursor) ?: continue
            cursor = instanceFieldsSize.nextOffset
            val directMethodsSize = readUleb128(dexBytes, cursor) ?: continue
            cursor = directMethodsSize.nextOffset
            val virtualMethodsSize = readUleb128(dexBytes, cursor) ?: continue
            cursor = virtualMethodsSize.nextOffset

            repeat(staticFieldsSize.value + instanceFieldsSize.value) {
                val fieldIdxDiff = readUleb128(dexBytes, cursor) ?: return@repeat
                cursor = fieldIdxDiff.nextOffset
                val accessFlags = readUleb128(dexBytes, cursor) ?: return@repeat
                cursor = accessFlags.nextOffset
            }

            fun consumeMethods(count: Int) {
                var methodIndex = 0
                repeat(count) {
                    val methodIdxDiff = readUleb128(dexBytes, cursor) ?: return
                    cursor = methodIdxDiff.nextOffset
                    val accessFlags = readUleb128(dexBytes, cursor) ?: return
                    cursor = accessFlags.nextOffset
                    val codeOff = readUleb128(dexBytes, cursor) ?: return
                    cursor = codeOff.nextOffset
                    methodIndex += methodIdxDiff.value
                    methodCodeOffsets[methodIndex] = codeOff.value
                }
            }

            consumeMethods(directMethodsSize.value)
            consumeMethods(virtualMethodsSize.value)
        }

        return buildMap {
            for (methodIndex in 0 until methodIdsSize) {
                val methodOff = methodIdsOff + methodIndex * 8
                val classDescriptor = readTypeDescriptor(buffer.getShort(methodOff).toInt() and 0xFFFF)
                val protoDescriptor = readProtoDescriptor(buffer.getShort(methodOff + 2).toInt() and 0xFFFF)
                val methodName = readDexString(buffer.getInt(methodOff + 4))
                if (classDescriptor.isBlank() || protoDescriptor.isBlank() || methodName.isBlank()) continue

                val methodSignature = "$classDescriptor->$methodName$protoDescriptor"
                if (methodSignature !in requestedMethods) continue

                val codeOff = methodCodeOffsets[methodIndex] ?: 0
                val codeLen = parseDexCodeItemLength(dexBytes, codeOff)
                put(
                    methodSignature,
                    if (codeOff > 0 && codeLen > 0 && codeOff + codeLen <= dexBytes.size) {
                        sha256Hex(dexBytes.copyOfRange(codeOff, codeOff + codeLen))
                    } else {
                        ""
                    },
                )
            }
        }
    }

    private fun dexSectionName(type: Int): String = when (type) {
        0x0000 -> "header"
        0x0001 -> "string_ids"
        0x0002 -> "type_ids"
        0x0003 -> "proto_ids"
        0x0004 -> "field_ids"
        0x0005 -> "method_ids"
        0x0006 -> "class_defs"
        0x0007 -> "call_site_ids"
        0x0008 -> "method_handles"
        0x1000 -> "map_list"
        0x1001 -> "type_list"
        0x1002 -> "annotation_set_ref_list"
        0x1003 -> "annotation_set_item"
        0x2000 -> "class_data_item"
        0x2001 -> "code_item"
        0x2002 -> "string_data_item"
        0x2003 -> "debug_info_item"
        0x2004 -> "annotation_item"
        0x2005 -> "encoded_array_item"
        0x2006 -> "annotations_directory_item"
        0xF000 -> "hiddenapi_class_data_item"
        else -> "type_0x${type.toString(16)}"
    }

    private fun dexSectionLength(type: Int, count: Int): Int = when (type) {
        0x0000 -> 0x70
        0x0001 -> count * 4
        0x0002 -> count * 4
        0x0003 -> count * 12
        0x0004 -> count * 8
        0x0005 -> count * 8
        0x0006 -> count * 32
        0x0007 -> count * 4
        0x0008 -> count * 8
        0x1000 -> 4 + count * 12
        0xF000 -> count
        else -> -1
    }

    private fun parseDexCodeItemLength(dexBytes: ByteArray, codeOff: Int): Int {
        if (codeOff <= 0 || codeOff + 16 > dexBytes.size) return -1
        val buffer = ByteBuffer.wrap(dexBytes).order(ByteOrder.LITTLE_ENDIAN)
        val triesSize = buffer.getShort(codeOff + 6).toInt() and 0xFFFF
        val insnsSize = buffer.getInt(codeOff + 12)
        if (insnsSize < 0) return -1

        var cursor = codeOff + 16 + (insnsSize * 2)
        if (cursor > dexBytes.size) return -1
        if (triesSize > 0 && (insnsSize and 1) == 1) {
            cursor += 2
        }
        val triesBytes = triesSize * 8
        if (cursor + triesBytes > dexBytes.size) return -1
        cursor += triesBytes
        if (triesSize == 0) return cursor - codeOff

        val handlerCount = readUleb128(dexBytes, cursor) ?: return -1
        cursor = handlerCount.nextOffset
        repeat(handlerCount.value) {
            val handlerSize = readSleb128(dexBytes, cursor) ?: return -1
            cursor = handlerSize.nextOffset
            val typedCount = kotlin.math.abs(handlerSize.value)
            repeat(typedCount) {
                val typeIdx = readUleb128(dexBytes, cursor) ?: return -1
                cursor = typeIdx.nextOffset
                val addr = readUleb128(dexBytes, cursor) ?: return -1
                cursor = addr.nextOffset
            }
            if (handlerSize.value <= 0) {
                val catchAll = readUleb128(dexBytes, cursor) ?: return -1
                cursor = catchAll.nextOffset
            }
        }
        return cursor - codeOff
    }

    private data class Leb128Value(
        val value: Int,
        val nextOffset: Int,
    )

    private fun readUleb128(bytes: ByteArray, start: Int): Leb128Value? {
        if (start !in bytes.indices) return null
        var offset = start
        var result = 0
        var shift = 0
        repeat(5) {
            if (offset >= bytes.size) return null
            val byteValue = bytes[offset].toInt() and 0xFF
            offset++
            result = result or ((byteValue and 0x7F) shl shift)
            if ((byteValue and 0x80) == 0) return Leb128Value(result, offset)
            shift += 7
        }
        return null
    }

    private fun readSleb128(bytes: ByteArray, start: Int): Leb128Value? {
        if (start !in bytes.indices) return null
        var offset = start
        var result = 0
        var shift = 0
        var byteValue: Int
        do {
            if (offset >= bytes.size || shift >= 35) return null
            byteValue = bytes[offset].toInt() and 0xFF
            offset++
            result = result or ((byteValue and 0x7F) shl shift)
            shift += 7
        } while ((byteValue and 0x80) != 0)

        if (shift < 32 && (byteValue and 0x40) != 0) {
            result = result or (-1 shl shift)
        }
        return Leb128Value(result, offset)
    }

    private fun hashElfSections(
        nativeLibraryDir: String?,
        sectionsByLib: Map<String, List<String>>,
    ): Map<String, String> {
        if (nativeLibraryDir.isNullOrBlank() || sectionsByLib.isEmpty()) return emptyMap()
        return buildMap {
            sectionsByLib.forEach { (libName, sectionNames) ->
                val file = File(nativeLibraryDir, libName)
                val bytes = try {
                    file.takeIf { it.isFile }?.readBytes()
                } catch (_: Throwable) {
                    null
                } ?: return@forEach
                val hashes = parseElfSectionHashes(bytes, sectionNames.toSet())
                sectionNames.forEach { sectionName ->
                    put("$libName#$sectionName", hashes[sectionName].orEmpty())
                }
            }
        }
    }

    private fun parseElfSectionHashes(
        elfBytes: ByteArray,
        requestedSections: Set<String>,
    ): Map<String, String> {
        if (elfBytes.size < 0x40 || requestedSections.isEmpty()) return emptyMap()
        if (elfBytes[0] != 0x7F.toByte() || elfBytes[1].toInt() != 'E'.code ||
            elfBytes[2].toInt() != 'L'.code || elfBytes[3].toInt() != 'F'.code
        ) return emptyMap()

        val is64 = elfBytes[4].toInt() == 2
        val order = if (elfBytes[5].toInt() == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val buffer = ByteBuffer.wrap(elfBytes).order(order)

        val shOff = if (is64) buffer.getLong(0x28).toInt() else buffer.getInt(0x20)
        val shEntSize = if (is64) buffer.getShort(0x3A).toInt() and 0xFFFF else buffer.getShort(0x2E).toInt() and 0xFFFF
        val shNum = if (is64) buffer.getShort(0x3C).toInt() and 0xFFFF else buffer.getShort(0x30).toInt() and 0xFFFF
        val shStrIndex = if (is64) buffer.getShort(0x3E).toInt() and 0xFFFF else buffer.getShort(0x32).toInt() and 0xFFFF
        if (shOff <= 0 || shEntSize <= 0 || shNum <= 0 || shStrIndex >= shNum) return emptyMap()
        if (shOff + shEntSize * shNum > elfBytes.size) return emptyMap()

        val shStrHeader = shOff + shStrIndex * shEntSize
        val shStrOffset = if (is64) buffer.getLong(shStrHeader + 0x18).toInt() else buffer.getInt(shStrHeader + 0x10)
        val shStrSize = if (is64) buffer.getLong(shStrHeader + 0x20).toInt() else buffer.getInt(shStrHeader + 0x14)
        if (shStrOffset < 0 || shStrSize <= 0 || shStrOffset + shStrSize > elfBytes.size) return emptyMap()
        val shStr = elfBytes.copyOfRange(shStrOffset, shStrOffset + shStrSize)

        return buildMap {
            for (index in 0 until shNum) {
                val header = shOff + index * shEntSize
                val nameOffset = buffer.getInt(header)
                val sectionName = readElfString(shStr, nameOffset)
                if (sectionName !in requestedSections) continue

                val sectionOffset = if (is64) buffer.getLong(header + 0x18).toInt() else buffer.getInt(header + 0x10)
                val sectionSize = if (is64) buffer.getLong(header + 0x20).toInt() else buffer.getInt(header + 0x14)
                if (sectionOffset < 0 || sectionSize <= 0 || sectionOffset + sectionSize > elfBytes.size) {
                    put(sectionName, "")
                    continue
                }
                put(sectionName, sha256Hex(elfBytes.copyOfRange(sectionOffset, sectionOffset + sectionSize)))
            }
        }
    }

    private fun hashElfExportSymbols(
        nativeLibraryDir: String?,
        symbolsByLib: Map<String, List<String>>,
    ): Map<String, String> {
        if (nativeLibraryDir.isNullOrBlank() || symbolsByLib.isEmpty()) return emptyMap()
        return buildMap {
            symbolsByLib.forEach { (libName, symbolNames) ->
                val file = File(nativeLibraryDir, libName)
                val bytes = try {
                    file.takeIf { it.isFile }?.readBytes()
                } catch (_: Throwable) {
                    null
                } ?: return@forEach
                val hashes = parseElfExportSymbolHashes(bytes, symbolNames.toSet())
                symbolNames.forEach { symbolName ->
                    put("$libName#$symbolName", hashes[symbolName].orEmpty())
                }
            }
        }
    }

    private fun parseElfExportSymbolHashes(
        elfBytes: ByteArray,
        requestedSymbols: Set<String>,
    ): Map<String, String> {
        if (elfBytes.size < 0x40 || requestedSymbols.isEmpty()) return emptyMap()
        if (elfBytes[0] != 0x7F.toByte() || elfBytes[1].toInt() != 'E'.code ||
            elfBytes[2].toInt() != 'L'.code || elfBytes[3].toInt() != 'F'.code
        ) return emptyMap()

        val is64 = elfBytes[4].toInt() == 2
        val order = if (elfBytes[5].toInt() == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val buffer = ByteBuffer.wrap(elfBytes).order(order)

        val shOff = if (is64) buffer.getLong(0x28).toInt() else buffer.getInt(0x20)
        val shEntSize = if (is64) buffer.getShort(0x3A).toInt() and 0xFFFF else buffer.getShort(0x2E).toInt() and 0xFFFF
        val shNum = if (is64) buffer.getShort(0x3C).toInt() and 0xFFFF else buffer.getShort(0x30).toInt() and 0xFFFF
        val shStrIndex = if (is64) buffer.getShort(0x3E).toInt() and 0xFFFF else buffer.getShort(0x32).toInt() and 0xFFFF
        if (shOff <= 0 || shEntSize <= 0 || shNum <= 0 || shStrIndex >= shNum) return emptyMap()
        if (shOff + shEntSize * shNum > elfBytes.size) return emptyMap()

        val shStrHeader = shOff + shStrIndex * shEntSize
        val shStrOffset = if (is64) buffer.getLong(shStrHeader + 0x18).toInt() else buffer.getInt(shStrHeader + 0x10)
        val shStrSize = if (is64) buffer.getLong(shStrHeader + 0x20).toInt() else buffer.getInt(shStrHeader + 0x14)
        if (shStrOffset < 0 || shStrSize <= 0 || shStrOffset + shStrSize > elfBytes.size) return emptyMap()
        val shStr = elfBytes.copyOfRange(shStrOffset, shStrOffset + shStrSize)

        var dynSymHeader = -1
        var dynStrHeader = -1
        for (index in 0 until shNum) {
            val header = shOff + index * shEntSize
            val sectionName = readElfString(shStr, buffer.getInt(header))
            if (sectionName == ".dynsym") dynSymHeader = header
            if (sectionName == ".dynstr") dynStrHeader = header
        }
        if (dynSymHeader < 0 || dynStrHeader < 0) return emptyMap()

        val dynSymOffset = if (is64) buffer.getLong(dynSymHeader + 0x18).toInt() else buffer.getInt(dynSymHeader + 0x10)
        val dynSymSize = if (is64) buffer.getLong(dynSymHeader + 0x20).toInt() else buffer.getInt(dynSymHeader + 0x14)
        val dynSymEntSize = if (is64) buffer.getLong(dynSymHeader + 0x38).toInt() else buffer.getInt(dynSymHeader + 0x24)
        val dynStrOffset = if (is64) buffer.getLong(dynStrHeader + 0x18).toInt() else buffer.getInt(dynStrHeader + 0x10)
        val dynStrSize = if (is64) buffer.getLong(dynStrHeader + 0x20).toInt() else buffer.getInt(dynStrHeader + 0x14)
        if (dynSymOffset < 0 || dynSymSize <= 0 || dynSymOffset + dynSymSize > elfBytes.size) return emptyMap()
        if (dynStrOffset < 0 || dynStrSize <= 0 || dynStrOffset + dynStrSize > elfBytes.size) return emptyMap()
        if (dynSymEntSize <= 0) return emptyMap()
        val dynStr = elfBytes.copyOfRange(dynStrOffset, dynStrOffset + dynStrSize)

        return buildMap {
            val count = dynSymSize / dynSymEntSize
            for (index in 0 until count) {
                val off = dynSymOffset + index * dynSymEntSize
                if (off + dynSymEntSize > elfBytes.size) break
                val nameOffset = buffer.getInt(off)
                val symbolName = readElfString(dynStr, nameOffset)
                if (symbolName !in requestedSymbols) continue

                val info = if (is64) buffer.get(off + 4).toInt() and 0xFF else buffer.get(off + 12).toInt() and 0xFF
                val other = if (is64) buffer.get(off + 5).toInt() and 0xFF else buffer.get(off + 13).toInt() and 0xFF
                val shndx = if (is64) buffer.getShort(off + 6).toInt() and 0xFFFF else buffer.getShort(off + 14).toInt() and 0xFFFF
                val value = if (is64) buffer.getLong(off + 8) else buffer.getInt(off + 4).toLong() and 0xFFFFFFFFL
                val size = if (is64) buffer.getLong(off + 16) else buffer.getInt(off + 8).toLong() and 0xFFFFFFFFL
                if (shndx == 0) continue
                val fingerprint = "$symbolName|$value|$size|$info|$other|$shndx"
                put(symbolName, sha256Hex(fingerprint.toByteArray()))
            }
        }
    }

    private fun hashElfExportGraphs(
        nativeLibraryDir: String?,
        requestedLibs: Set<String>,
    ): Map<String, String> {
        if (nativeLibraryDir.isNullOrBlank() || requestedLibs.isEmpty()) return emptyMap()
        return buildMap {
            requestedLibs.forEach { libName ->
                val file = File(nativeLibraryDir, libName)
                val bytes = try {
                    file.takeIf { it.isFile }?.readBytes()
                } catch (_: Throwable) {
                    null
                } ?: return@forEach
                put(libName, parseElfExportGraphHash(bytes).orEmpty())
            }
        }
    }

    private fun parseElfExportGraphHash(elfBytes: ByteArray): String? {
        if (elfBytes.size < 0x40) return null
        if (elfBytes[0] != 0x7F.toByte() || elfBytes[1].toInt() != 'E'.code ||
            elfBytes[2].toInt() != 'L'.code || elfBytes[3].toInt() != 'F'.code
        ) return null

        val is64 = elfBytes[4].toInt() == 2
        val order = if (elfBytes[5].toInt() == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val buffer = ByteBuffer.wrap(elfBytes).order(order)

        val shOff = if (is64) buffer.getLong(0x28).toInt() else buffer.getInt(0x20)
        val shEntSize = if (is64) buffer.getShort(0x3A).toInt() and 0xFFFF else buffer.getShort(0x2E).toInt() and 0xFFFF
        val shNum = if (is64) buffer.getShort(0x3C).toInt() and 0xFFFF else buffer.getShort(0x30).toInt() and 0xFFFF
        val shStrIndex = if (is64) buffer.getShort(0x3E).toInt() and 0xFFFF else buffer.getShort(0x32).toInt() and 0xFFFF
        if (shOff <= 0 || shEntSize <= 0 || shNum <= 0 || shStrIndex >= shNum) return null
        if (shOff + shEntSize * shNum > elfBytes.size) return null

        val shStrHeader = shOff + shStrIndex * shEntSize
        val shStrOffset = if (is64) buffer.getLong(shStrHeader + 0x18).toInt() else buffer.getInt(shStrHeader + 0x10)
        val shStrSize = if (is64) buffer.getLong(shStrHeader + 0x20).toInt() else buffer.getInt(shStrHeader + 0x14)
        if (shStrOffset < 0 || shStrSize <= 0 || shStrOffset + shStrSize > elfBytes.size) return null
        val shStr = elfBytes.copyOfRange(shStrOffset, shStrOffset + shStrSize)

        var dynSymHeader = -1
        var dynStrHeader = -1
        for (index in 0 until shNum) {
            val header = shOff + index * shEntSize
            val sectionName = readElfString(shStr, buffer.getInt(header))
            if (sectionName == ".dynsym") dynSymHeader = header
            if (sectionName == ".dynstr") dynStrHeader = header
        }
        if (dynSymHeader < 0 || dynStrHeader < 0) return null

        val dynSymOffset = if (is64) buffer.getLong(dynSymHeader + 0x18).toInt() else buffer.getInt(dynSymHeader + 0x10)
        val dynSymSize = if (is64) buffer.getLong(dynSymHeader + 0x20).toInt() else buffer.getInt(dynSymHeader + 0x14)
        val dynSymEntSize = if (is64) buffer.getLong(dynSymHeader + 0x38).toInt() else buffer.getInt(dynSymHeader + 0x24)
        val dynStrOffset = if (is64) buffer.getLong(dynStrHeader + 0x18).toInt() else buffer.getInt(dynStrHeader + 0x10)
        val dynStrSize = if (is64) buffer.getLong(dynStrHeader + 0x20).toInt() else buffer.getInt(dynStrHeader + 0x14)
        if (dynSymOffset < 0 || dynSymSize <= 0 || dynSymOffset + dynSymSize > elfBytes.size) return null
        if (dynStrOffset < 0 || dynStrSize <= 0 || dynStrOffset + dynStrSize > elfBytes.size) return null
        if (dynSymEntSize <= 0) return null
        val dynStr = elfBytes.copyOfRange(dynStrOffset, dynStrOffset + dynStrSize)

        val lines = mutableListOf<String>()
        val count = dynSymSize / dynSymEntSize
        for (index in 0 until count) {
            val off = dynSymOffset + index * dynSymEntSize
            if (off + dynSymEntSize > elfBytes.size) break
            val nameOffset = buffer.getInt(off)
            val symbolName = readElfString(dynStr, nameOffset)
            if (symbolName.isBlank()) continue

            val info = if (is64) buffer.get(off + 4).toInt() and 0xFF else buffer.get(off + 12).toInt() and 0xFF
            val other = if (is64) buffer.get(off + 5).toInt() and 0xFF else buffer.get(off + 13).toInt() and 0xFF
            val shndx = if (is64) buffer.getShort(off + 6).toInt() and 0xFFFF else buffer.getShort(off + 14).toInt() and 0xFFFF
            val value = if (is64) buffer.getLong(off + 8) else buffer.getInt(off + 4).toLong() and 0xFFFFFFFFL
            val size = if (is64) buffer.getLong(off + 16) else buffer.getInt(off + 8).toLong() and 0xFFFFFFFFL
            if (shndx == 0) continue
            lines += "$symbolName|$value|$size|$info|$other|$shndx"
        }
        if (lines.isEmpty()) return null
        lines.sort()
        return sha256Hex(lines.joinToString(separator = "\n").toByteArray())
    }

    private fun readElfString(table: ByteArray, offset: Int): String {
        if (offset < 0 || offset >= table.size) return ""
        var end = offset
        while (end < table.size && table[end] != 0.toByte()) end++
        return table.copyOfRange(offset, end).decodeToString()
    }

    private fun hashRequestedPermissions(info: PackageInfo?): String? {
        val permissions = info?.requestedPermissions
            ?.filterNotNull()
            ?.sorted()
            .orEmpty()
        if (permissions.isEmpty()) return null
        return sha256Hex(permissions.joinToString(separator = "\n").toByteArray())
    }

    private fun hashRequestedPermissionSemantics(info: PackageInfo?): String? {
        val permissions = info?.requestedPermissions.orEmpty()
        val flags = info?.requestedPermissionsFlags ?: intArrayOf()
        if (permissions.isEmpty()) return null
        val lines = permissions.mapIndexed { index, name ->
            val flag = flags.getOrElse(index) { 0 }
            "${name.orEmpty()}|0x${flag.toString(16)}"
        }.sorted()
        return sha256Hex(lines.joinToString(separator = "\n").toByteArray())
    }

    private fun hashDeclaredPermissionSemantics(info: PackageInfo?): String? {
        val permissions = info?.permissions
            ?.filterNotNull()
            ?.map { permission ->
                listOf(
                    permission.name.orEmpty(),
                    permission.group.orEmpty(),
                    permission.protectionLevel.toString(),
                    permission.flags.toString(),
                ).joinToString("|")
            }
            ?.sorted()
            .orEmpty()
        if (permissions.isEmpty()) return null
        return sha256Hex(permissions.joinToString(separator = "\n").toByteArray())
    }

    private fun collectDeclaredPermissionFieldValues(info: PackageInfo?): Map<String, String> =
        info?.permissions
            ?.filterNotNull()
            ?.flatMap { permission ->
                val base = "permission:${permission.name.orEmpty()}"
                listOf(
                    "$base#group" to permission.group.orEmpty(),
                    "$base#protectionLevel" to permission.protectionLevel.toString(),
                    "$base#flags" to permission.flags.toString(),
                )
            }
            ?.toMap()
            .orEmpty()

    private fun collectComponentSignatures(info: PackageInfo?): Map<String, String> {
        if (info == null) return emptyMap()
        return buildMap {
            putAll(componentHashes("activity", info.activities))
            putAll(componentHashes("service", info.services))
            putAll(componentHashes("receiver", info.receivers))
            putAll(providerHashes(info.providers))
        }
    }

    private fun collectComponentFieldValues(info: PackageInfo?): Map<String, String> {
        if (info == null) return emptyMap()
        return buildMap {
            putAll(componentFieldValues("activity", info.activities))
            putAll(componentFieldValues("service", info.services))
            putAll(componentFieldValues("receiver", info.receivers))
            putAll(providerFieldValues(info.providers))
        }
    }

    private fun componentHashes(
        type: String,
        components: Array<out ComponentInfo>?,
    ): Map<String, String> = components
        ?.filterNotNull()
        ?.associate { component ->
            val permission = when (component) {
                is android.content.pm.ActivityInfo -> component.permission.orEmpty()
                is android.content.pm.ServiceInfo -> component.permission.orEmpty()
                else -> ""
            }
            val signature = listOf(
                component.name.orEmpty(),
                component.enabled.toString(),
                component.exported.toString(),
                permission,
                component.processName.orEmpty(),
                component.directBootAware.toString(),
            ).joinToString("|")
            "$type:${component.name}" to sha256Hex(signature.toByteArray())
        }
        .orEmpty()

    private fun providerHashes(
        providers: Array<out android.content.pm.ProviderInfo>?,
    ): Map<String, String> = providers
        ?.filterNotNull()
        ?.associate { provider ->
            val signature = listOf(
                provider.name.orEmpty(),
                provider.enabled.toString(),
                provider.exported.toString(),
                provider.processName.orEmpty(),
                provider.directBootAware.toString(),
                provider.authority.orEmpty(),
                provider.readPermission.orEmpty(),
                provider.writePermission.orEmpty(),
            ).joinToString("|")
            "provider:${provider.name}" to sha256Hex(signature.toByteArray())
        }
        .orEmpty()

    private fun componentFieldValues(
        type: String,
        components: Array<out ComponentInfo>?,
    ): Map<String, String> = components
        ?.filterNotNull()
        ?.flatMap { component ->
            val base = "$type:${component.name.orEmpty()}"
            val permission = when (component) {
                is android.content.pm.ActivityInfo -> component.permission.orEmpty()
                is android.content.pm.ServiceInfo -> component.permission.orEmpty()
                else -> ""
            }
            listOf(
                "$base#enabled" to component.enabled.toString(),
                "$base#exported" to component.exported.toString(),
                "$base#permission" to permission,
                "$base#processName" to component.processName.orEmpty(),
                "$base#directBootAware" to component.directBootAware.toString(),
            )
        }
        ?.toMap()
        .orEmpty()

    private fun providerFieldValues(
        providers: Array<out android.content.pm.ProviderInfo>?,
    ): Map<String, String> = providers
        ?.filterNotNull()
        ?.flatMap { provider ->
            val base = "provider:${provider.name.orEmpty()}"
            listOf(
                "$base#enabled" to provider.enabled.toString(),
                "$base#exported" to provider.exported.toString(),
                "$base#processName" to provider.processName.orEmpty(),
                "$base#directBootAware" to provider.directBootAware.toString(),
                "$base#grantUriPermissions" to provider.grantUriPermissions.toString(),
                "$base#multiprocess" to provider.multiprocess.toString(),
                "$base#initOrder" to provider.initOrder.toString(),
                "$base#authority" to provider.authority.orEmpty(),
                "$base#readPermission" to provider.readPermission.orEmpty(),
                "$base#writePermission" to provider.writePermission.orEmpty(),
            )
        }
        ?.toMap()
        .orEmpty()

    private fun collectProviderUriPermissionPatternFingerprints(info: PackageInfo?): Map<String, String> =
        info?.providers
            ?.filterNotNull()
            ?.associate { provider ->
                "provider:${provider.name}" to sha256Hex(
                    provider.uriPermissionPatterns
                        ?.filterNotNull()
                        ?.map {
                            listOf(
                                it.type.toString(),
                                it.path.orEmpty(),
                            ).joinToString("|")
                        }
                        ?.sorted()
                        ?.joinToString(separator = "\n")
                        ?.toByteArray()
                        ?: ByteArray(0),
                )
            }
            .orEmpty()

    private fun collectProviderPathPermissionFingerprints(info: PackageInfo?): Map<String, String> =
        info?.providers
            ?.filterNotNull()
            ?.associate { provider ->
                "provider:${provider.name}" to sha256Hex(
                    provider.pathPermissions
                        ?.filterNotNull()
                        ?.map {
                            listOf(
                                it.type.toString(),
                                it.path.orEmpty(),
                                it.readPermission.orEmpty(),
                                it.writePermission.orEmpty(),
                            ).joinToString("|")
                        }
                        ?.sorted()
                        ?.joinToString(separator = "\n")
                        ?.toByteArray()
                        ?: ByteArray(0),
                )
            }
            .orEmpty()

    private fun collectProviderAuthoritySetFingerprints(info: PackageInfo?): Map<String, String> =
        info?.providers
            ?.filterNotNull()
            ?.associate { provider ->
                "provider:${provider.name}" to sha256Hex(
                    provider.authority
                        .orEmpty()
                        .split(';')
                        .map { it.trim() }
                        .filter { it.isNotBlank() }
                        .sorted()
                        .joinToString(separator = "\n")
                        .toByteArray(),
                )
            }
            .orEmpty()

    private fun collectProviderSemanticsFingerprints(info: PackageInfo?): Map<String, String> =
        info?.providers
            ?.filterNotNull()
            ?.associate { provider ->
                val authoritySet = provider.authority
                    .orEmpty()
                    .split(';')
                    .map { it.trim() }
                    .filter { it.isNotBlank() }
                    .sorted()
                val uriPermissionPatterns = provider.uriPermissionPatterns
                    ?.filterNotNull()
                    ?.map {
                        listOf(
                            it.type.toString(),
                            it.path.orEmpty(),
                        ).joinToString("|")
                    }
                    ?.sorted()
                    .orEmpty()
                val pathPermissions = provider.pathPermissions
                    ?.filterNotNull()
                    ?.map {
                        listOf(
                            it.type.toString(),
                            it.path.orEmpty(),
                            it.readPermission.orEmpty(),
                            it.writePermission.orEmpty(),
                        ).joinToString("|")
                    }
                    ?.sorted()
                    .orEmpty()
                val lines = buildList {
                    add("name=${provider.name.orEmpty()}")
                    add("enabled=${provider.enabled}")
                    add("exported=${provider.exported}")
                    add("processName=${provider.processName.orEmpty()}")
                    add("directBootAware=${provider.directBootAware}")
                    add("grantUriPermissions=${provider.grantUriPermissions}")
                    add("multiprocess=${provider.multiprocess}")
                    add("initOrder=${provider.initOrder}")
                    add("readPermission=${provider.readPermission.orEmpty()}")
                    add("writePermission=${provider.writePermission.orEmpty()}")
                    addAll(authoritySet.map { "authority=$it" })
                    addAll(uriPermissionPatterns.map { "uriPermissionPattern=$it" })
                    addAll(pathPermissions.map { "pathPermission=$it" })
                }
                "provider:${provider.name}" to sha256Hex(
                    lines.joinToString(separator = "\n").toByteArray(),
                )
            }
            .orEmpty()

    private fun normalizeManifestClassName(packageName: String, rawName: String): String =
        when {
            rawName.startsWith(".") -> packageName + rawName
            '.' in rawName -> rawName
            packageName.isNotBlank() -> "$packageName.$rawName"
            else -> rawName
        }

    private fun canonicalizeManifestNode(name: String, attrs: Map<String, String>): String {
        if (attrs.isEmpty()) return name
        return buildString {
            append(name)
            attrs.toSortedMap().forEach { (key, value) ->
                append('|')
                append(key)
                append('=')
                append(value)
            }
        }
    }

    private fun walkBinaryXml(
        xmlBytes: ByteArray,
        onStartTag: (String, Map<String, String>) -> Unit,
        onEndTag: (String) -> Unit,
    ): Boolean {
        if (xmlBytes.size < 8) return false
        val strings = mutableListOf<String>()
        val headerSize = u16(xmlBytes, 2)
        val totalSize = u32(xmlBytes, 4)
        if (headerSize <= 0 || totalSize <= 0 || totalSize > xmlBytes.size) return false

        var offset = headerSize
        while (offset + 8 <= totalSize) {
            val chunkType = u16(xmlBytes, offset)
            val chunkHeaderSize = u16(xmlBytes, offset + 2)
            val chunkSize = u32(xmlBytes, offset + 4)
            if (chunkHeaderSize <= 0 || chunkSize < chunkHeaderSize || offset + chunkSize > totalSize) {
                return false
            }
            when (chunkType) {
                RES_STRING_POOL_TYPE -> {
                    strings.clear()
                    strings += parseStringPool(xmlBytes, offset, chunkSize)
                }
                RES_XML_START_ELEMENT_TYPE -> {
                    val start = parseXmlStartElement(xmlBytes, offset, strings)
                    if (start != null) onStartTag(start.name, start.attributes)
                }
                RES_XML_END_ELEMENT_TYPE -> {
                    val end = parseXmlEndElement(xmlBytes, offset, strings)
                    if (end != null) onEndTag(end)
                }
            }
            offset += chunkSize
        }
        return true
    }

    private fun parseStringPool(bytes: ByteArray, offset: Int, chunkSize: Int): List<String> {
        if (offset + 28 > bytes.size) return emptyList()
        val stringCount = u32(bytes, offset + 8)
        val flags = u32(bytes, offset + 16)
        val stringsStart = u32(bytes, offset + 20)
        if (stringCount < 0 || stringsStart < 0 || offset + stringsStart > bytes.size) return emptyList()
        val isUtf8 = (flags and UTF8_FLAG) != 0
        val offsetsBase = offset + 28
        val stringsBase = offset + stringsStart
        return buildList {
            for (index in 0 until stringCount) {
                val stringOffset = u32(bytes, offsetsBase + index * 4)
                if (stringOffset < 0 || stringsBase + stringOffset >= offset + chunkSize) {
                    add("")
                    continue
                }
                add(
                    if (isUtf8) {
                        decodeUtf8String(bytes, stringsBase + stringOffset)
                    } else {
                        decodeUtf16String(bytes, stringsBase + stringOffset)
                    },
                )
            }
        }
    }

    private fun parseXmlStartElement(
        bytes: ByteArray,
        offset: Int,
        strings: List<String>,
    ): XmlStartElement? {
        if (offset + 36 > bytes.size) return null
        val name = strings.getOrElse(u32(bytes, offset + 20)) { "" }
        if (name.isBlank()) return null
        val attrStart = u16(bytes, offset + 24)
        val attrSize = u16(bytes, offset + 26)
        val attrCount = u16(bytes, offset + 28)
        val attrsBase = offset + 16 + attrStart
        if (attrSize <= 0 || attrsBase < 0 || attrsBase > bytes.size) return XmlStartElement(name, emptyMap())
        val attributes = linkedMapOf<String, String>()
        for (index in 0 until attrCount) {
            val attrOffset = attrsBase + index * attrSize
            if (attrOffset + 20 > bytes.size) break
            val attrName = strings.getOrElse(u32(bytes, attrOffset + 4)) { "" }
            if (attrName.isBlank()) continue
            val rawValueIndex = u32(bytes, attrOffset + 8)
            val dataType = bytes[attrOffset + 15].toInt() and 0xFF
            val data = u32(bytes, attrOffset + 16)
            val value = when {
                rawValueIndex >= 0 -> strings.getOrElse(rawValueIndex) { "" }
                else -> decodeTypedXmlValue(dataType, data, strings)
            }
            attributes[attrName] = value
        }
        return XmlStartElement(name, attributes)
    }

    private fun parseXmlEndElement(bytes: ByteArray, offset: Int, strings: List<String>): String? {
        if (offset + 24 > bytes.size) return null
        return strings.getOrElse(u32(bytes, offset + 20)) { "" }.ifBlank { null }
    }

    private fun decodeTypedXmlValue(dataType: Int, data: Int, strings: List<String>): String = when (dataType) {
        TYPE_STRING -> strings.getOrElse(data) { "" }
        TYPE_INT_DEC -> data.toString()
        TYPE_INT_HEX -> "0x${data.toString(16)}"
        TYPE_INT_BOOLEAN -> if (data != 0) "true" else "false"
        TYPE_REFERENCE -> "@0x${data.toString(16)}"
        else -> data.toString()
    }

    private fun decodeUtf8String(bytes: ByteArray, offset: Int): String {
        val firstLen = readLength8(bytes, offset) ?: return ""
        val secondLen = readLength8(bytes, firstLen.nextOffset) ?: return ""
        val start = secondLen.nextOffset
        val end = (start + secondLen.value).coerceAtMost(bytes.size)
        return bytes.copyOfRange(start, end).decodeToString()
    }

    private fun decodeUtf16String(bytes: ByteArray, offset: Int): String {
        val len = readLength16(bytes, offset) ?: return ""
        val start = len.nextOffset
        val end = (start + len.value * 2).coerceAtMost(bytes.size)
        return bytes.copyOfRange(start, end).toString(Charsets.UTF_16LE)
    }

    private fun readLength8(bytes: ByteArray, offset: Int): LengthValue? {
        if (offset !in bytes.indices) return null
        val first = bytes[offset].toInt() and 0xFF
        return if ((first and 0x80) == 0) {
            LengthValue(first, offset + 1)
        } else {
            if (offset + 1 >= bytes.size) null else LengthValue(
                ((first and 0x7F) shl 8) or (bytes[offset + 1].toInt() and 0xFF),
                offset + 2,
            )
        }
    }

    private fun readLength16(bytes: ByteArray, offset: Int): LengthValue? {
        if (offset + 1 >= bytes.size) return null
        val first = u16(bytes, offset)
        return if ((first and 0x8000) == 0) {
            LengthValue(first, offset + 2)
        } else {
            if (offset + 3 >= bytes.size) null else LengthValue(
                ((first and 0x7FFF) shl 16) or u16(bytes, offset + 2),
                offset + 4,
            )
        }
    }

    private fun u16(bytes: ByteArray, offset: Int): Int {
        if (offset + 2 > bytes.size) return -1
        return (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
    }

    private fun u32(bytes: ByteArray, offset: Int): Int {
        if (offset + 4 > bytes.size) return -1
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private data class ManifestSubtreeFingerprints(
        val intentFilterHashes: Map<String, String>,
        val intentFilterActionHashes: Map<String, String>,
        val intentFilterCategoryHashes: Map<String, String>,
        val intentFilterDataHashes: Map<String, String>,
        val intentFilterDataSchemeHashes: Map<String, String>,
        val intentFilterDataAuthorityHashes: Map<String, String>,
        val intentFilterDataPathHashes: Map<String, String>,
        val intentFilterDataMimeTypeHashes: Map<String, String>,
        val grantUriPermissionHashes: Map<String, String>,
    ) {
        companion object {
            val EMPTY = ManifestSubtreeFingerprints(
                emptyMap(),
                emptyMap(),
                emptyMap(),
                emptyMap(),
                emptyMap(),
                emptyMap(),
                emptyMap(),
                emptyMap(),
                emptyMap(),
            )
        }
    }

    private data class ManifestGlobalFingerprints(
        val usesFeatureSha256: String? = null,
        val usesFeatureNameSha256: String? = null,
        val usesFeatureRequiredSha256: String? = null,
        val usesFeatureGlEsVersionSha256: String? = null,
        val usesSdkSha256: String? = null,
        val usesSdkMinVersionSha256: String? = null,
        val usesSdkTargetVersionSha256: String? = null,
        val usesSdkMaxVersionSha256: String? = null,
        val supportsScreensSha256: String? = null,
        val supportsScreensSmallScreensSha256: String? = null,
        val supportsScreensNormalScreensSha256: String? = null,
        val supportsScreensLargeScreensSha256: String? = null,
        val supportsScreensXlargeScreensSha256: String? = null,
        val supportsScreensResizeableSha256: String? = null,
        val supportsScreensAnyDensitySha256: String? = null,
        val supportsScreensRequiresSmallestWidthDpSha256: String? = null,
        val supportsScreensCompatibleWidthLimitDpSha256: String? = null,
        val supportsScreensLargestWidthLimitDpSha256: String? = null,
        val compatibleScreensSha256: String? = null,
        val compatibleScreensScreenSizeSha256: String? = null,
        val compatibleScreensScreenDensitySha256: String? = null,
        val usesLibrarySha256: String? = null,
        val usesLibraryNameSha256: String? = null,
        val usesLibraryRequiredSha256: String? = null,
        val usesLibraryOnlySha256: String? = null,
        val usesLibraryOnlyNameSha256: String? = null,
        val usesLibraryOnlyRequiredSha256: String? = null,
        val usesNativeLibrarySha256: String? = null,
        val usesNativeLibraryNameSha256: String? = null,
        val usesNativeLibraryRequiredSha256: String? = null,
        val queriesPackageSha256: String? = null,
        val queriesPackageNameSha256: String? = null,
        val queriesProviderSha256: String? = null,
        val queriesProviderAuthoritySha256: String? = null,
        val queriesIntentSha256: String? = null,
        val queriesIntentActionSha256: String? = null,
        val queriesIntentCategorySha256: String? = null,
        val queriesIntentDataSha256: String? = null,
        val queriesIntentDataSchemeSha256: String? = null,
        val queriesIntentDataAuthoritySha256: String? = null,
        val queriesIntentDataPathSha256: String? = null,
        val queriesIntentDataMimeTypeSha256: String? = null,
        val queriesSha256: String? = null,
        val applicationSemanticsSha256: String? = null,
        val applicationFieldValues: Map<String, String> = emptyMap(),
    ) {
        companion object {
            val EMPTY = ManifestGlobalFingerprints()
        }
    }

    private data class ManifestComponent(
        val type: String,
        val name: String,
    )

    private data class XmlStartElement(
        val name: String,
        val attributes: Map<String, String>,
    )

    private data class LengthValue(
        val value: Int,
        val nextOffset: Int,
    )

    private fun PackageManager.safeInstaller(packageName: String): String? = try {
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> {
                getInstallSourceInfo(packageName).installingPackageName
            }
            else -> @Suppress("DEPRECATION") getInstallerPackageName(packageName)
        }
    } catch (_: Throwable) {
        null
    }

    @Suppress("DEPRECATION")
    private fun PackageManager.safePackageInfo(packageName: String): PackageInfo? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
        } else {
            getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
        }
    } catch (_: Throwable) {
        null
    }

    @Suppress("DEPRECATION")
    private fun PackageManager.safeManifestPackageInfo(packageName: String): PackageInfo? = try {
        val flags =
            PackageManager.GET_PERMISSIONS.toLong() or
                PackageManager.GET_ACTIVITIES.toLong() or
                PackageManager.GET_SERVICES.toLong() or
                PackageManager.GET_RECEIVERS.toLong() or
                PackageManager.GET_PROVIDERS.toLong() or
                PackageManager.GET_URI_PERMISSION_PATTERNS.toLong() or
                PackageManager.GET_META_DATA.toLong()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags))
        } else {
            getPackageInfo(packageName, flags.toInt())
        }
    } catch (_: Throwable) {
        null
    }

    @Suppress("DEPRECATION")
    private fun PackageManager.safeMetaData(packageName: String) =
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                getApplicationInfo(
                    packageName,
                    PackageManager.ApplicationInfoFlags.of(PackageManager.GET_META_DATA.toLong()),
                ).metaData
            } else {
                getApplicationInfo(packageName, PackageManager.GET_META_DATA).metaData
            }
        } catch (_: Throwable) {
            null
        }

    private fun PackageInfo.safeLongVersionCode(): Long =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            longVersionCode
        } else {
            @Suppress("DEPRECATION")
            versionCode.toLong()
        }

    @Suppress("DEPRECATION")
    private fun PackageInfo?.signingDigestsSha256(): List<String> {
        if (this == null) return emptyList()
        val rawSignatures = when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
                val info = signingInfo ?: return emptyList()
                val signatures = if (info.hasMultipleSigners()) {
                    info.apkContentsSigners
                } else {
                    info.signingCertificateHistory
                }
                signatures?.map { it.toByteArray() }.orEmpty()
            }
            else -> signatures?.map { it.toByteArray() }.orEmpty()
        }

        return rawSignatures
            .filter { it.isNotEmpty() }
            .map { bytes -> sha256Hex(bytes) }
            .distinct()
            .sorted()
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .toHex()

    private fun ByteArray.toHex(): String =
        joinToString(separator = "") { "%02x".format(it) }

    private const val RES_STRING_POOL_TYPE = 0x0001
    private const val RES_XML_START_ELEMENT_TYPE = 0x0102
    private const val RES_XML_END_ELEMENT_TYPE = 0x0103
    private const val UTF8_FLAG = 0x00000100

    private const val TYPE_REFERENCE = 0x01
    private const val TYPE_STRING = 0x03
    private const val TYPE_INT_DEC = 0x10
    private const val TYPE_INT_HEX = 0x11
    private const val TYPE_INT_BOOLEAN = 0x12

    private val KNOWN_CONFIG_SPLIT_ABI_AXES = setOf(
        "armeabi",
        "armeabi_v7a",
        "arm64_v8a",
        "x86",
        "x86_64",
        "mips",
        "mips64",
        "riscv64",
    )

    private val CONFIG_SPLIT_DENSITY_REGEX = Regex(
        "^(?:ldpi|mdpi|tvdpi|hdpi|xhdpi|xxhdpi|xxxhdpi|nodpi|anydpi|[0-9]{3,4}dpi)$",
    )
    private val CONFIG_SPLIT_LOCALE_REGEX = Regex("^[a-z]{2,3}(?:-r[A-Z]{2})?$")
    private val CONFIG_SPLIT_BCP47_LOCALE_REGEX = Regex("^b\\+[A-Za-z0-9_+]+$")
}
