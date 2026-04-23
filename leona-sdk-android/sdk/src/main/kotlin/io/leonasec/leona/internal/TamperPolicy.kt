/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import io.leonasec.leona.config.LeonaConfig

internal data class TamperPolicy(
    val expectedPackageName: String? = null,
    val allowedInstallerPackages: Set<String> = emptySet(),
    val allowedSigningCertSha256: Set<String> = emptySet(),
    val expectedApkSha256: String? = null,
    val expectedNativeLibSha256: Map<String, String> = emptyMap(),
    val expectedManifestEntrySha256: String? = null,
    val expectedDexSha256: Map<String, String> = emptyMap(),
    val expectedDexSectionSha256: Map<String, String> = emptyMap(),
    val expectedDexMethodSha256: Map<String, String> = emptyMap(),
    val expectedSplitApkSha256: Map<String, String> = emptyMap(),
    val expectedSplitInventorySha256: String? = null,
    val expectedDynamicFeatureSplitSha256: String? = null,
    val expectedDynamicFeatureSplitNameSha256: String? = null,
    val expectedConfigSplitAxisSha256: String? = null,
    val expectedConfigSplitNameSha256: String? = null,
    val expectedConfigSplitAbiSha256: String? = null,
    val expectedConfigSplitLocaleSha256: String? = null,
    val expectedConfigSplitDensitySha256: String? = null,
    val expectedElfSectionSha256: Map<String, String> = emptyMap(),
    val expectedElfExportSymbolSha256: Map<String, String> = emptyMap(),
    val expectedElfExportGraphSha256: Map<String, String> = emptyMap(),
    val expectedRequestedPermissionsSha256: String? = null,
    val expectedRequestedPermissionSemanticsSha256: String? = null,
    val expectedDeclaredPermissionSemanticsSha256: String? = null,
    val expectedDeclaredPermissionFieldValues: Map<String, String> = emptyMap(),
    val expectedComponentSignatureSha256: Map<String, String> = emptyMap(),
    val expectedComponentFieldValues: Map<String, String> = emptyMap(),
    val expectedProviderUriPermissionPatternsSha256: Map<String, String> = emptyMap(),
    val expectedProviderPathPermissionsSha256: Map<String, String> = emptyMap(),
    val expectedProviderAuthoritySetSha256: Map<String, String> = emptyMap(),
    val expectedProviderSemanticsSha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterSha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterActionSha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterCategorySha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterDataSha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterDataSchemeSha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterDataAuthoritySha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterDataPathSha256: Map<String, String> = emptyMap(),
    val expectedIntentFilterDataMimeTypeSha256: Map<String, String> = emptyMap(),
    val expectedGrantUriPermissionSha256: Map<String, String> = emptyMap(),
    val expectedUsesFeatureSha256: String? = null,
    val expectedUsesFeatureNameSha256: String? = null,
    val expectedUsesFeatureRequiredSha256: String? = null,
    val expectedUsesFeatureGlEsVersionSha256: String? = null,
    val expectedUsesSdkSha256: String? = null,
    val expectedUsesSdkMinSha256: String? = null,
    val expectedUsesSdkTargetSha256: String? = null,
    val expectedUsesSdkMaxSha256: String? = null,
    val expectedSupportsScreensSha256: String? = null,
    val expectedCompatibleScreensSha256: String? = null,
    val expectedUsesLibrarySha256: String? = null,
    val expectedUsesLibraryOnlySha256: String? = null,
    val expectedUsesNativeLibrarySha256: String? = null,
    val expectedQueriesSha256: String? = null,
    val expectedQueriesPackageSha256: String? = null,
    val expectedQueriesPackageNameSha256: String? = null,
    val expectedQueriesProviderSha256: String? = null,
    val expectedQueriesProviderAuthoritySha256: String? = null,
    val expectedQueriesIntentSha256: String? = null,
    val expectedQueriesIntentActionSha256: String? = null,
    val expectedQueriesIntentCategorySha256: String? = null,
    val expectedQueriesIntentDataSha256: String? = null,
    val expectedQueriesIntentDataSchemeSha256: String? = null,
    val expectedQueriesIntentDataAuthoritySha256: String? = null,
    val expectedQueriesIntentDataPathSha256: String? = null,
    val expectedQueriesIntentDataMimeTypeSha256: String? = null,
    val expectedApplicationSemanticsSha256: String? = null,
    val expectedApplicationFieldValues: Map<String, String> = emptyMap(),
    val expectedMetaData: Map<String, String> = emptyMap(),
) {
    fun merge(server: TamperPolicy?): TamperPolicy {
        if (server == null) return this
        return TamperPolicy(
            expectedPackageName = server.expectedPackageName ?: expectedPackageName,
            allowedInstallerPackages = if (server.allowedInstallerPackages.isNotEmpty()) {
                server.allowedInstallerPackages
            } else {
                allowedInstallerPackages
            },
            allowedSigningCertSha256 = if (server.allowedSigningCertSha256.isNotEmpty()) {
                server.allowedSigningCertSha256
            } else {
                allowedSigningCertSha256
            },
            expectedApkSha256 = server.expectedApkSha256 ?: expectedApkSha256,
            expectedNativeLibSha256 = expectedNativeLibSha256 + server.expectedNativeLibSha256,
            expectedManifestEntrySha256 = server.expectedManifestEntrySha256 ?: expectedManifestEntrySha256,
            expectedDexSha256 = expectedDexSha256 + server.expectedDexSha256,
            expectedDexSectionSha256 = expectedDexSectionSha256 + server.expectedDexSectionSha256,
            expectedDexMethodSha256 = expectedDexMethodSha256 + server.expectedDexMethodSha256,
            expectedSplitApkSha256 = expectedSplitApkSha256 + server.expectedSplitApkSha256,
            expectedSplitInventorySha256 = server.expectedSplitInventorySha256 ?: expectedSplitInventorySha256,
            expectedDynamicFeatureSplitSha256 =
                server.expectedDynamicFeatureSplitSha256 ?: expectedDynamicFeatureSplitSha256,
            expectedDynamicFeatureSplitNameSha256 =
                server.expectedDynamicFeatureSplitNameSha256 ?: expectedDynamicFeatureSplitNameSha256,
            expectedConfigSplitAxisSha256 =
                server.expectedConfigSplitAxisSha256 ?: expectedConfigSplitAxisSha256,
            expectedConfigSplitNameSha256 =
                server.expectedConfigSplitNameSha256 ?: expectedConfigSplitNameSha256,
            expectedConfigSplitAbiSha256 =
                server.expectedConfigSplitAbiSha256 ?: expectedConfigSplitAbiSha256,
            expectedConfigSplitLocaleSha256 =
                server.expectedConfigSplitLocaleSha256 ?: expectedConfigSplitLocaleSha256,
            expectedConfigSplitDensitySha256 =
                server.expectedConfigSplitDensitySha256 ?: expectedConfigSplitDensitySha256,
            expectedElfSectionSha256 = expectedElfSectionSha256 + server.expectedElfSectionSha256,
            expectedElfExportSymbolSha256 = expectedElfExportSymbolSha256 + server.expectedElfExportSymbolSha256,
            expectedElfExportGraphSha256 = expectedElfExportGraphSha256 + server.expectedElfExportGraphSha256,
            expectedRequestedPermissionsSha256 = server.expectedRequestedPermissionsSha256
                ?: expectedRequestedPermissionsSha256,
            expectedRequestedPermissionSemanticsSha256 = server.expectedRequestedPermissionSemanticsSha256
                ?: expectedRequestedPermissionSemanticsSha256,
            expectedDeclaredPermissionSemanticsSha256 = server.expectedDeclaredPermissionSemanticsSha256
                ?: expectedDeclaredPermissionSemanticsSha256,
            expectedDeclaredPermissionFieldValues = expectedDeclaredPermissionFieldValues
                + server.expectedDeclaredPermissionFieldValues,
            expectedComponentSignatureSha256 = expectedComponentSignatureSha256
                + server.expectedComponentSignatureSha256,
            expectedComponentFieldValues = expectedComponentFieldValues
                + server.expectedComponentFieldValues,
            expectedProviderUriPermissionPatternsSha256 = expectedProviderUriPermissionPatternsSha256
                + server.expectedProviderUriPermissionPatternsSha256,
            expectedProviderPathPermissionsSha256 = expectedProviderPathPermissionsSha256
                + server.expectedProviderPathPermissionsSha256,
            expectedProviderAuthoritySetSha256 = expectedProviderAuthoritySetSha256
                + server.expectedProviderAuthoritySetSha256,
            expectedProviderSemanticsSha256 = expectedProviderSemanticsSha256
                + server.expectedProviderSemanticsSha256,
            expectedIntentFilterSha256 = expectedIntentFilterSha256 + server.expectedIntentFilterSha256,
            expectedIntentFilterActionSha256 =
                expectedIntentFilterActionSha256 + server.expectedIntentFilterActionSha256,
            expectedIntentFilterCategorySha256 =
                expectedIntentFilterCategorySha256 + server.expectedIntentFilterCategorySha256,
            expectedIntentFilterDataSha256 =
                expectedIntentFilterDataSha256 + server.expectedIntentFilterDataSha256,
            expectedIntentFilterDataSchemeSha256 =
                expectedIntentFilterDataSchemeSha256 + server.expectedIntentFilterDataSchemeSha256,
            expectedIntentFilterDataAuthoritySha256 =
                expectedIntentFilterDataAuthoritySha256 + server.expectedIntentFilterDataAuthoritySha256,
            expectedIntentFilterDataPathSha256 =
                expectedIntentFilterDataPathSha256 + server.expectedIntentFilterDataPathSha256,
            expectedIntentFilterDataMimeTypeSha256 =
                expectedIntentFilterDataMimeTypeSha256 + server.expectedIntentFilterDataMimeTypeSha256,
            expectedGrantUriPermissionSha256 =
                expectedGrantUriPermissionSha256 + server.expectedGrantUriPermissionSha256,
            expectedUsesFeatureSha256 = server.expectedUsesFeatureSha256 ?: expectedUsesFeatureSha256,
            expectedUsesFeatureNameSha256 =
                server.expectedUsesFeatureNameSha256 ?: expectedUsesFeatureNameSha256,
            expectedUsesFeatureRequiredSha256 =
                server.expectedUsesFeatureRequiredSha256 ?: expectedUsesFeatureRequiredSha256,
            expectedUsesFeatureGlEsVersionSha256 =
                server.expectedUsesFeatureGlEsVersionSha256 ?: expectedUsesFeatureGlEsVersionSha256,
            expectedUsesSdkSha256 = server.expectedUsesSdkSha256 ?: expectedUsesSdkSha256,
            expectedUsesSdkMinSha256 = server.expectedUsesSdkMinSha256 ?: expectedUsesSdkMinSha256,
            expectedUsesSdkTargetSha256 =
                server.expectedUsesSdkTargetSha256 ?: expectedUsesSdkTargetSha256,
            expectedUsesSdkMaxSha256 = server.expectedUsesSdkMaxSha256 ?: expectedUsesSdkMaxSha256,
            expectedSupportsScreensSha256 = server.expectedSupportsScreensSha256 ?: expectedSupportsScreensSha256,
            expectedCompatibleScreensSha256 =
                server.expectedCompatibleScreensSha256 ?: expectedCompatibleScreensSha256,
            expectedUsesLibrarySha256 = server.expectedUsesLibrarySha256 ?: expectedUsesLibrarySha256,
            expectedUsesLibraryOnlySha256 =
                server.expectedUsesLibraryOnlySha256 ?: expectedUsesLibraryOnlySha256,
            expectedUsesNativeLibrarySha256 =
                server.expectedUsesNativeLibrarySha256 ?: expectedUsesNativeLibrarySha256,
            expectedQueriesSha256 = server.expectedQueriesSha256 ?: expectedQueriesSha256,
            expectedQueriesPackageSha256 = server.expectedQueriesPackageSha256 ?: expectedQueriesPackageSha256,
            expectedQueriesPackageNameSha256 =
                server.expectedQueriesPackageNameSha256 ?: expectedQueriesPackageNameSha256,
            expectedQueriesProviderSha256 = server.expectedQueriesProviderSha256 ?: expectedQueriesProviderSha256,
            expectedQueriesProviderAuthoritySha256 =
                server.expectedQueriesProviderAuthoritySha256 ?: expectedQueriesProviderAuthoritySha256,
            expectedQueriesIntentSha256 = server.expectedQueriesIntentSha256 ?: expectedQueriesIntentSha256,
            expectedQueriesIntentActionSha256 =
                server.expectedQueriesIntentActionSha256 ?: expectedQueriesIntentActionSha256,
            expectedQueriesIntentCategorySha256 =
                server.expectedQueriesIntentCategorySha256 ?: expectedQueriesIntentCategorySha256,
            expectedQueriesIntentDataSha256 =
                server.expectedQueriesIntentDataSha256 ?: expectedQueriesIntentDataSha256,
            expectedQueriesIntentDataSchemeSha256 =
                server.expectedQueriesIntentDataSchemeSha256 ?: expectedQueriesIntentDataSchemeSha256,
            expectedQueriesIntentDataAuthoritySha256 =
                server.expectedQueriesIntentDataAuthoritySha256 ?: expectedQueriesIntentDataAuthoritySha256,
            expectedQueriesIntentDataPathSha256 =
                server.expectedQueriesIntentDataPathSha256 ?: expectedQueriesIntentDataPathSha256,
            expectedQueriesIntentDataMimeTypeSha256 =
                server.expectedQueriesIntentDataMimeTypeSha256 ?: expectedQueriesIntentDataMimeTypeSha256,
            expectedApplicationSemanticsSha256 =
                server.expectedApplicationSemanticsSha256 ?: expectedApplicationSemanticsSha256,
            expectedApplicationFieldValues = expectedApplicationFieldValues + server.expectedApplicationFieldValues,
            expectedMetaData = expectedMetaData + server.expectedMetaData,
        )
    }

    companion object {
        val EMPTY = TamperPolicy()
    }
}

internal fun LeonaConfig.toTamperPolicy(): TamperPolicy =
    TamperPolicy(
        expectedPackageName = expectedPackageName,
        allowedInstallerPackages = allowedInstallerPackages,
        allowedSigningCertSha256 = allowedSigningCertSha256,
        expectedApkSha256 = expectedApkSha256,
        expectedNativeLibSha256 = expectedNativeLibSha256,
        expectedManifestEntrySha256 = expectedManifestEntrySha256,
        expectedDexSha256 = expectedDexSha256,
        expectedDexSectionSha256 = expectedDexSectionSha256,
        expectedDexMethodSha256 = expectedDexMethodSha256,
        expectedSplitApkSha256 = expectedSplitApkSha256,
        expectedSplitInventorySha256 = expectedSplitInventorySha256,
        expectedDynamicFeatureSplitSha256 = expectedDynamicFeatureSplitSha256,
        expectedDynamicFeatureSplitNameSha256 = expectedDynamicFeatureSplitNameSha256,
        expectedConfigSplitAxisSha256 = expectedConfigSplitAxisSha256,
        expectedConfigSplitNameSha256 = expectedConfigSplitNameSha256,
        expectedConfigSplitAbiSha256 = expectedConfigSplitAbiSha256,
        expectedConfigSplitLocaleSha256 = expectedConfigSplitLocaleSha256,
        expectedConfigSplitDensitySha256 = expectedConfigSplitDensitySha256,
        expectedElfSectionSha256 = expectedElfSectionSha256,
        expectedElfExportSymbolSha256 = expectedElfExportSymbolSha256,
        expectedElfExportGraphSha256 = expectedElfExportGraphSha256,
        expectedRequestedPermissionsSha256 = expectedRequestedPermissionsSha256,
        expectedRequestedPermissionSemanticsSha256 = expectedRequestedPermissionSemanticsSha256,
        expectedDeclaredPermissionSemanticsSha256 = expectedDeclaredPermissionSemanticsSha256,
        expectedDeclaredPermissionFieldValues = expectedDeclaredPermissionFieldValues,
        expectedComponentSignatureSha256 = expectedComponentSignatureSha256,
        expectedComponentFieldValues = expectedComponentFieldValues,
        expectedProviderUriPermissionPatternsSha256 = expectedProviderUriPermissionPatternsSha256,
        expectedProviderPathPermissionsSha256 = expectedProviderPathPermissionsSha256,
        expectedProviderAuthoritySetSha256 = expectedProviderAuthoritySetSha256,
        expectedProviderSemanticsSha256 = expectedProviderSemanticsSha256,
        expectedIntentFilterSha256 = expectedIntentFilterSha256,
        expectedIntentFilterActionSha256 = expectedIntentFilterActionSha256,
        expectedIntentFilterCategorySha256 = expectedIntentFilterCategorySha256,
        expectedIntentFilterDataSha256 = expectedIntentFilterDataSha256,
        expectedIntentFilterDataSchemeSha256 = expectedIntentFilterDataSchemeSha256,
        expectedIntentFilterDataAuthoritySha256 = expectedIntentFilterDataAuthoritySha256,
        expectedIntentFilterDataPathSha256 = expectedIntentFilterDataPathSha256,
        expectedIntentFilterDataMimeTypeSha256 = expectedIntentFilterDataMimeTypeSha256,
        expectedGrantUriPermissionSha256 = expectedGrantUriPermissionSha256,
        expectedUsesFeatureSha256 = expectedUsesFeatureSha256,
        expectedUsesFeatureNameSha256 = expectedUsesFeatureNameSha256,
        expectedUsesFeatureRequiredSha256 = expectedUsesFeatureRequiredSha256,
        expectedUsesFeatureGlEsVersionSha256 = expectedUsesFeatureGlEsVersionSha256,
        expectedUsesSdkSha256 = expectedUsesSdkSha256,
        expectedUsesSdkMinSha256 = expectedUsesSdkMinSha256,
        expectedUsesSdkTargetSha256 = expectedUsesSdkTargetSha256,
        expectedUsesSdkMaxSha256 = expectedUsesSdkMaxSha256,
        expectedSupportsScreensSha256 = expectedSupportsScreensSha256,
        expectedCompatibleScreensSha256 = expectedCompatibleScreensSha256,
        expectedUsesLibrarySha256 = expectedUsesLibrarySha256,
        expectedUsesLibraryOnlySha256 = expectedUsesLibraryOnlySha256,
        expectedUsesNativeLibrarySha256 = expectedUsesNativeLibrarySha256,
        expectedQueriesSha256 = expectedQueriesSha256,
        expectedQueriesPackageSha256 = expectedQueriesPackageSha256,
        expectedQueriesPackageNameSha256 = expectedQueriesPackageNameSha256,
        expectedQueriesProviderSha256 = expectedQueriesProviderSha256,
        expectedQueriesProviderAuthoritySha256 = expectedQueriesProviderAuthoritySha256,
        expectedQueriesIntentSha256 = expectedQueriesIntentSha256,
        expectedQueriesIntentActionSha256 = expectedQueriesIntentActionSha256,
        expectedQueriesIntentCategorySha256 = expectedQueriesIntentCategorySha256,
        expectedQueriesIntentDataSha256 = expectedQueriesIntentDataSha256,
        expectedQueriesIntentDataSchemeSha256 = expectedQueriesIntentDataSchemeSha256,
        expectedQueriesIntentDataAuthoritySha256 = expectedQueriesIntentDataAuthoritySha256,
        expectedQueriesIntentDataPathSha256 = expectedQueriesIntentDataPathSha256,
        expectedQueriesIntentDataMimeTypeSha256 = expectedQueriesIntentDataMimeTypeSha256,
        expectedApplicationSemanticsSha256 = expectedApplicationSemanticsSha256,
        expectedApplicationFieldValues = expectedApplicationFieldValues,
        expectedMetaData = expectedMetaData,
    )
