/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TamperPolicyTest {

    @Test
    fun `server policy overrides scalar baselines and augments maps`() {
        val local = TamperPolicy(
            expectedPackageName = "com.local.app",
            allowedInstallerPackages = setOf("com.android.vending"),
            expectedSigningCertificateLineageSha256 = "local-signing-lineage",
            expectedApkSigningBlockSha256 = "local-signing-block",
            expectedApkSigningBlockIdSha256 = mapOf("0x7109871a" to "local-v2-block"),
            expectedNativeLibSha256 = mapOf("libleona.so" to "local-lib"),
            expectedResourcesArscSha256 = "local-resources-arsc",
            expectedResourceInventorySha256 = "local-resource-inventory",
            expectedResourceEntrySha256 = mapOf("res/raw/local.bin" to "local-resource"),
            expectedDexSha256 = mapOf("classes.dex" to "local-dex"),
            expectedDexSectionSha256 = mapOf("classes.dex#code_item" to "local-dex-section"),
            expectedDexMethodSha256 = mapOf(
                "classes.dex#Lcom/local/MainActivity;->isTampered()Z" to "local-dex-method",
            ),
            expectedElfSectionSha256 = mapOf("libleona.so#.text" to "local-elf"),
            expectedSplitInventorySha256 = "local-split-inventory",
            expectedDynamicFeatureSplitSha256 = "local-dynamic-features",
            expectedDynamicFeatureSplitNameSha256 = "local-dynamic-feature-names",
            expectedConfigSplitAxisSha256 = "local-config-axes",
            expectedConfigSplitNameSha256 = "local-config-names",
            expectedConfigSplitAbiSha256 = "local-config-abis",
            expectedConfigSplitLocaleSha256 = "local-config-locales",
            expectedConfigSplitDensitySha256 = "local-config-densities",
            expectedElfExportSymbolSha256 = mapOf("libleona.so#JNI_OnLoad" to "local-symbol"),
            expectedElfExportGraphSha256 = mapOf("libleona.so" to "local-graph"),
            expectedRequestedPermissionsSha256 = "local-permissions",
            expectedRequestedPermissionSemanticsSha256 = "local-permission-semantics",
            expectedDeclaredPermissionSemanticsSha256 = "local-declared-permission-semantics",
            expectedDeclaredPermissionFieldValues = mapOf(
                "permission:com.local.permission.GUARD#protectionLevel" to "18",
            ),
            expectedComponentSignatureSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-component",
            ),
            expectedComponentAccessSemanticsSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-component-access-semantics",
            ),
            expectedComponentOperationalSemanticsSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-component-operational-semantics",
            ),
            expectedComponentFieldValues = mapOf(
                "activity:com.local.MainActivity#exported" to "false",
            ),
            expectedProviderUriPermissionPatternsSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-uri-patterns",
            ),
            expectedProviderPathPermissionsSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-path-permissions",
            ),
            expectedProviderAuthoritySetSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-authority-set",
            ),
            expectedProviderSemanticsSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-provider-semantics",
            ),
            expectedProviderAccessSemanticsSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-provider-access-semantics",
            ),
            expectedProviderOperationalSemanticsSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-provider-operational-semantics",
            ),
            expectedIntentFilterSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-filters",
            ),
            expectedIntentFilterActionSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-actions",
            ),
            expectedIntentFilterCategorySha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-categories",
            ),
            expectedIntentFilterDataSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-data",
            ),
            expectedIntentFilterDataSchemeSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-scheme",
            ),
            expectedIntentFilterDataAuthoritySha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-authority",
            ),
            expectedIntentFilterDataPathSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-path",
            ),
            expectedIntentFilterDataMimeTypeSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-mime",
            ),
            expectedIntentFilterSemanticsSha256 = mapOf(
                "activity:com.local.MainActivity" to "local-intent-semantics",
            ),
            expectedGrantUriPermissionSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-grant-uri",
            ),
            expectedGrantUriPermissionSemanticsSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-grant-uri-semantics",
            ),
            expectedUsesFeatureSha256 = "local-uses-feature",
            expectedUsesFeatureNameSha256 = "local-uses-feature-name",
            expectedUsesFeatureRequiredSha256 = "local-uses-feature-required",
            expectedUsesFeatureGlEsVersionSha256 = "local-uses-feature-gles",
            expectedUsesFeatureFieldValues = mapOf(
                "uses-feature:android.hardware.camera#required" to "true",
            ),
            expectedUsesSdkSha256 = "local-uses-sdk",
            expectedUsesSdkMinSha256 = "local-uses-sdk-min",
            expectedUsesSdkTargetSha256 = "local-uses-sdk-target",
            expectedUsesSdkMaxSha256 = "local-uses-sdk-max",
            expectedUsesSdkFieldValues = mapOf(
                "uses-sdk#targetSdkVersion" to "33",
            ),
            expectedSupportsScreensSha256 = "local-supports-screens",
            expectedSupportsScreensSmallScreensSha256 = "local-supports-screens-small",
            expectedSupportsScreensNormalScreensSha256 = "local-supports-screens-normal",
            expectedSupportsScreensLargeScreensSha256 = "local-supports-screens-large",
            expectedSupportsScreensXlargeScreensSha256 = "local-supports-screens-xlarge",
            expectedSupportsScreensResizeableSha256 = "local-supports-screens-resizeable",
            expectedSupportsScreensAnyDensitySha256 = "local-supports-screens-any-density",
            expectedSupportsScreensRequiresSmallestWidthDpSha256 =
                "local-supports-screens-requires-smallest-width",
            expectedSupportsScreensCompatibleWidthLimitDpSha256 =
                "local-supports-screens-compatible-width-limit",
            expectedSupportsScreensLargestWidthLimitDpSha256 =
                "local-supports-screens-largest-width-limit",
            expectedCompatibleScreensSha256 = "local-compatible-screens",
            expectedCompatibleScreensScreenSizeSha256 = "local-compatible-screens-size",
            expectedCompatibleScreensScreenDensitySha256 = "local-compatible-screens-density",
            expectedUsesLibrarySha256 = "local-uses-library",
            expectedUsesLibraryNameSha256 = "local-uses-library-name",
            expectedUsesLibraryRequiredSha256 = "local-uses-library-required",
            expectedUsesLibraryFieldValues = mapOf(
                "uses-library:org.apache.http.legacy#required" to "false",
            ),
            expectedUsesLibraryOnlySha256 = "local-uses-library-only",
            expectedUsesLibraryOnlyNameSha256 = "local-uses-library-only-name",
            expectedUsesLibraryOnlyRequiredSha256 = "local-uses-library-only-required",
            expectedUsesNativeLibrarySha256 = "local-uses-native-library",
            expectedUsesNativeLibraryNameSha256 = "local-uses-native-library-name",
            expectedUsesNativeLibraryRequiredSha256 = "local-uses-native-library-required",
            expectedUsesNativeLibraryFieldValues = mapOf(
                "uses-native-library:com.local.sec#required" to "true",
            ),
            expectedQueriesSha256 = "local-queries",
            expectedQueriesPackageSha256 = "local-queries-package",
            expectedQueriesPackageNameSha256 = "local-queries-package-name",
            expectedQueriesPackageSemanticsSha256 = "local-queries-package-semantics",
            expectedQueriesProviderSha256 = "local-queries-provider",
            expectedQueriesProviderAuthoritySha256 = "local-queries-provider-authority",
            expectedQueriesProviderSemanticsSha256 = "local-queries-provider-semantics",
            expectedQueriesIntentSha256 = "local-queries-intent",
            expectedQueriesIntentActionSha256 = "local-queries-intent-action",
            expectedQueriesIntentCategorySha256 = "local-queries-intent-category",
            expectedQueriesIntentDataSha256 = "local-queries-intent-data",
            expectedQueriesIntentDataSchemeSha256 = "local-queries-intent-data-scheme",
            expectedQueriesIntentDataAuthoritySha256 = "local-queries-intent-data-authority",
            expectedQueriesIntentDataPathSha256 = "local-queries-intent-data-path",
            expectedQueriesIntentDataMimeTypeSha256 = "local-queries-intent-data-mime",
            expectedQueriesIntentSemanticsSha256 = "local-queries-intent-semantics",
            expectedApplicationSemanticsSha256 = "local-application-semantics",
            expectedApplicationSecuritySemanticsSha256 = "local-application-security-semantics",
            expectedApplicationRuntimeSemanticsSha256 = "local-application-runtime-semantics",
            expectedApplicationFieldValues = mapOf(
                "application#usesCleartextTraffic" to "false",
            ),
            expectedMetaDataType = mapOf("channel" to "string"),
            expectedMetaDataValueSha256 = mapOf("channel" to "local-meta-hash"),
            expectedManifestMetaDataEntrySha256 = mapOf("channel" to "local-manifest-meta-entry"),
            expectedManifestMetaDataSemanticsSha256 = mapOf("channel" to "local-manifest-meta-semantics"),
            expectedMetaData = mapOf("channel" to "local"),
        )
        val server = TamperPolicy(
            expectedPackageName = "com.server.app",
            allowedInstallerPackages = setOf("com.server.store"),
            expectedSigningCertificateLineageSha256 = "server-signing-lineage",
            expectedApkSigningBlockSha256 = "server-signing-block",
            expectedApkSigningBlockIdSha256 = mapOf("0xf05368c0" to "server-v3-block"),
            expectedNativeLibSha256 = mapOf("libextra.so" to "server-lib"),
            expectedResourcesArscSha256 = "server-resources-arsc",
            expectedResourceInventorySha256 = "server-resource-inventory",
            expectedResourceEntrySha256 = mapOf("assets/server.dat" to "server-resource"),
            expectedDexSha256 = mapOf("classes2.dex" to "server-dex"),
            expectedDexSectionSha256 = mapOf("classes.dex#class_defs" to "server-dex-section"),
            expectedDexMethodSha256 = mapOf(
                "classes2.dex#Lcom/server/Guard;->verify()V" to "server-dex-method",
            ),
            expectedElfSectionSha256 = mapOf("libextra.so#.rodata" to "server-elf"),
            expectedSplitInventorySha256 = "server-split-inventory",
            expectedDynamicFeatureSplitSha256 = "server-dynamic-features",
            expectedDynamicFeatureSplitNameSha256 = "server-dynamic-feature-names",
            expectedConfigSplitAxisSha256 = "server-config-axes",
            expectedConfigSplitNameSha256 = "server-config-names",
            expectedConfigSplitAbiSha256 = "server-config-abis",
            expectedConfigSplitLocaleSha256 = "server-config-locales",
            expectedConfigSplitDensitySha256 = "server-config-densities",
            expectedElfExportSymbolSha256 = mapOf("libextra.so#Java_com_x" to "server-symbol"),
            expectedElfExportGraphSha256 = mapOf("libextra.so" to "server-graph"),
            expectedRequestedPermissionsSha256 = "server-permissions",
            expectedRequestedPermissionSemanticsSha256 = "server-permission-semantics",
            expectedDeclaredPermissionSemanticsSha256 = "server-declared-permission-semantics",
            expectedDeclaredPermissionFieldValues = mapOf(
                "permission:com.server.permission.SYNC#flags" to "1",
            ),
            expectedComponentSignatureSha256 = mapOf(
                "service:com.server.SyncService" to "server-component",
            ),
            expectedComponentAccessSemanticsSha256 = mapOf(
                "service:com.server.SyncService" to "server-component-access-semantics",
            ),
            expectedComponentOperationalSemanticsSha256 = mapOf(
                "service:com.server.SyncService" to "server-component-operational-semantics",
            ),
            expectedComponentFieldValues = mapOf(
                "service:com.server.SyncService#processName" to ":sync",
            ),
            expectedProviderUriPermissionPatternsSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-uri-patterns",
            ),
            expectedProviderPathPermissionsSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-path-permissions",
            ),
            expectedProviderAuthoritySetSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-authority-set",
            ),
            expectedProviderSemanticsSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-provider-semantics",
            ),
            expectedProviderAccessSemanticsSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-provider-access-semantics",
            ),
            expectedProviderOperationalSemanticsSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-provider-operational-semantics",
            ),
            expectedIntentFilterSha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-filters",
            ),
            expectedIntentFilterActionSha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-actions",
            ),
            expectedIntentFilterCategorySha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-categories",
            ),
            expectedIntentFilterDataSha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-data",
            ),
            expectedIntentFilterDataSchemeSha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-data-scheme",
            ),
            expectedIntentFilterDataAuthoritySha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-data-authority",
            ),
            expectedIntentFilterDataPathSha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-data-path",
            ),
            expectedIntentFilterDataMimeTypeSha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-data-mime",
            ),
            expectedIntentFilterSemanticsSha256 = mapOf(
                "service:com.server.SyncService" to "server-intent-semantics",
            ),
            expectedGrantUriPermissionSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-grant-uri",
            ),
            expectedGrantUriPermissionSemanticsSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-grant-uri-semantics",
            ),
            expectedUsesFeatureSha256 = "server-uses-feature",
            expectedUsesFeatureNameSha256 = "server-uses-feature-name",
            expectedUsesFeatureRequiredSha256 = "server-uses-feature-required",
            expectedUsesFeatureGlEsVersionSha256 = "server-uses-feature-gles",
            expectedUsesFeatureFieldValues = mapOf(
                "uses-feature:android.hardware.camera.autofocus#required" to "false",
            ),
            expectedUsesSdkSha256 = "server-uses-sdk",
            expectedUsesSdkMinSha256 = "server-uses-sdk-min",
            expectedUsesSdkTargetSha256 = "server-uses-sdk-target",
            expectedUsesSdkMaxSha256 = "server-uses-sdk-max",
            expectedUsesSdkFieldValues = mapOf(
                "uses-sdk#minSdkVersion" to "24",
            ),
            expectedSupportsScreensSha256 = "server-supports-screens",
            expectedSupportsScreensSmallScreensSha256 = "server-supports-screens-small",
            expectedSupportsScreensNormalScreensSha256 = "server-supports-screens-normal",
            expectedSupportsScreensLargeScreensSha256 = "server-supports-screens-large",
            expectedSupportsScreensXlargeScreensSha256 = "server-supports-screens-xlarge",
            expectedSupportsScreensResizeableSha256 = "server-supports-screens-resizeable",
            expectedSupportsScreensAnyDensitySha256 = "server-supports-screens-any-density",
            expectedSupportsScreensRequiresSmallestWidthDpSha256 =
                "server-supports-screens-requires-smallest-width",
            expectedSupportsScreensCompatibleWidthLimitDpSha256 =
                "server-supports-screens-compatible-width-limit",
            expectedSupportsScreensLargestWidthLimitDpSha256 =
                "server-supports-screens-largest-width-limit",
            expectedCompatibleScreensSha256 = "server-compatible-screens",
            expectedCompatibleScreensScreenSizeSha256 = "server-compatible-screens-size",
            expectedCompatibleScreensScreenDensitySha256 = "server-compatible-screens-density",
            expectedUsesLibrarySha256 = "server-uses-library",
            expectedUsesLibraryNameSha256 = "server-uses-library-name",
            expectedUsesLibraryRequiredSha256 = "server-uses-library-required",
            expectedUsesLibraryFieldValues = mapOf(
                "uses-library:android.test.runner#required" to "true",
            ),
            expectedUsesLibraryOnlySha256 = "server-uses-library-only",
            expectedUsesLibraryOnlyNameSha256 = "server-uses-library-only-name",
            expectedUsesLibraryOnlyRequiredSha256 = "server-uses-library-only-required",
            expectedUsesNativeLibrarySha256 = "server-uses-native-library",
            expectedUsesNativeLibraryNameSha256 = "server-uses-native-library-name",
            expectedUsesNativeLibraryRequiredSha256 = "server-uses-native-library-required",
            expectedUsesNativeLibraryFieldValues = mapOf(
                "uses-native-library:com.server.sec#required" to "false",
            ),
            expectedQueriesSha256 = "server-queries",
            expectedQueriesPackageSha256 = "server-queries-package",
            expectedQueriesPackageNameSha256 = "server-queries-package-name",
            expectedQueriesPackageSemanticsSha256 = "server-queries-package-semantics",
            expectedQueriesProviderSha256 = "server-queries-provider",
            expectedQueriesProviderAuthoritySha256 = "server-queries-provider-authority",
            expectedQueriesProviderSemanticsSha256 = "server-queries-provider-semantics",
            expectedQueriesIntentSha256 = "server-queries-intent",
            expectedQueriesIntentActionSha256 = "server-queries-intent-action",
            expectedQueriesIntentCategorySha256 = "server-queries-intent-category",
            expectedQueriesIntentDataSha256 = "server-queries-intent-data",
            expectedQueriesIntentDataSchemeSha256 = "server-queries-intent-data-scheme",
            expectedQueriesIntentDataAuthoritySha256 = "server-queries-intent-data-authority",
            expectedQueriesIntentDataPathSha256 = "server-queries-intent-data-path",
            expectedQueriesIntentDataMimeTypeSha256 = "server-queries-intent-data-mime",
            expectedQueriesIntentSemanticsSha256 = "server-queries-intent-semantics",
            expectedApplicationSemanticsSha256 = "server-application-semantics",
            expectedApplicationSecuritySemanticsSha256 = "server-application-security-semantics",
            expectedApplicationRuntimeSemanticsSha256 = "server-application-runtime-semantics",
            expectedApplicationFieldValues = mapOf(
                "application#networkSecurityConfig" to "@xml/network_security_config",
            ),
            expectedMetaDataType = mapOf("build" to "string"),
            expectedMetaDataValueSha256 = mapOf("build" to "server-meta-hash"),
            expectedManifestMetaDataEntrySha256 = mapOf("build" to "server-manifest-meta-entry"),
            expectedManifestMetaDataSemanticsSha256 = mapOf("build" to "server-manifest-meta-semantics"),
            expectedMetaData = mapOf("build" to "prod"),
        )

        val merged = local.merge(server)

        assertEquals("com.server.app", merged.expectedPackageName)
        assertEquals(setOf("com.server.store"), merged.allowedInstallerPackages)
        assertEquals("server-signing-lineage", merged.expectedSigningCertificateLineageSha256)
        assertEquals("server-signing-block", merged.expectedApkSigningBlockSha256)
        assertEquals(
            mapOf(
                "0x7109871a" to "local-v2-block",
                "0xf05368c0" to "server-v3-block",
            ),
            merged.expectedApkSigningBlockIdSha256,
        )
        assertEquals(
            mapOf(
                "libleona.so" to "local-lib",
                "libextra.so" to "server-lib",
            ),
            merged.expectedNativeLibSha256,
        )
        assertEquals("server-resources-arsc", merged.expectedResourcesArscSha256)
        assertEquals("server-resource-inventory", merged.expectedResourceInventorySha256)
        assertEquals(
            mapOf(
                "res/raw/local.bin" to "local-resource",
                "assets/server.dat" to "server-resource",
            ),
            merged.expectedResourceEntrySha256,
        )
        assertEquals(
            mapOf(
                "classes.dex" to "local-dex",
                "classes2.dex" to "server-dex",
            ),
            merged.expectedDexSha256,
        )
        assertEquals(
            mapOf(
                "classes.dex#code_item" to "local-dex-section",
                "classes.dex#class_defs" to "server-dex-section",
            ),
            merged.expectedDexSectionSha256,
        )
        assertEquals(
            mapOf(
                "classes.dex#Lcom/local/MainActivity;->isTampered()Z" to "local-dex-method",
                "classes2.dex#Lcom/server/Guard;->verify()V" to "server-dex-method",
            ),
            merged.expectedDexMethodSha256,
        )
        assertEquals(
            mapOf(
                "libleona.so#.text" to "local-elf",
                "libextra.so#.rodata" to "server-elf",
            ),
            merged.expectedElfSectionSha256,
        )
        assertEquals("server-split-inventory", merged.expectedSplitInventorySha256)
        assertEquals("server-dynamic-features", merged.expectedDynamicFeatureSplitSha256)
        assertEquals("server-dynamic-feature-names", merged.expectedDynamicFeatureSplitNameSha256)
        assertEquals("server-config-axes", merged.expectedConfigSplitAxisSha256)
        assertEquals("server-config-names", merged.expectedConfigSplitNameSha256)
        assertEquals("server-config-abis", merged.expectedConfigSplitAbiSha256)
        assertEquals("server-config-locales", merged.expectedConfigSplitLocaleSha256)
        assertEquals("server-config-densities", merged.expectedConfigSplitDensitySha256)
        assertEquals(
            mapOf(
                "libleona.so#JNI_OnLoad" to "local-symbol",
                "libextra.so#Java_com_x" to "server-symbol",
            ),
            merged.expectedElfExportSymbolSha256,
        )
        assertEquals(
            mapOf(
                "libleona.so" to "local-graph",
                "libextra.so" to "server-graph",
            ),
            merged.expectedElfExportGraphSha256,
        )
        assertEquals("server-permissions", merged.expectedRequestedPermissionsSha256)
        assertEquals("server-permission-semantics", merged.expectedRequestedPermissionSemanticsSha256)
        assertEquals("server-declared-permission-semantics", merged.expectedDeclaredPermissionSemanticsSha256)
        assertEquals(
            mapOf(
                "permission:com.local.permission.GUARD#protectionLevel" to "18",
                "permission:com.server.permission.SYNC#flags" to "1",
            ),
            merged.expectedDeclaredPermissionFieldValues,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-component",
                "service:com.server.SyncService" to "server-component",
            ),
            merged.expectedComponentSignatureSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-component-access-semantics",
                "service:com.server.SyncService" to "server-component-access-semantics",
            ),
            merged.expectedComponentAccessSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-component-operational-semantics",
                "service:com.server.SyncService" to "server-component-operational-semantics",
            ),
            merged.expectedComponentOperationalSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity#exported" to "false",
                "service:com.server.SyncService#processName" to ":sync",
            ),
            merged.expectedComponentFieldValues,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-uri-patterns",
                "provider:com.server.SyncProvider" to "server-uri-patterns",
            ),
            merged.expectedProviderUriPermissionPatternsSha256,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-path-permissions",
                "provider:com.server.SyncProvider" to "server-path-permissions",
            ),
            merged.expectedProviderPathPermissionsSha256,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-authority-set",
                "provider:com.server.SyncProvider" to "server-authority-set",
            ),
            merged.expectedProviderAuthoritySetSha256,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-provider-semantics",
                "provider:com.server.SyncProvider" to "server-provider-semantics",
            ),
            merged.expectedProviderSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-provider-access-semantics",
                "provider:com.server.SyncProvider" to "server-provider-access-semantics",
            ),
            merged.expectedProviderAccessSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-provider-operational-semantics",
                "provider:com.server.SyncProvider" to "server-provider-operational-semantics",
            ),
            merged.expectedProviderOperationalSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-filters",
                "service:com.server.SyncService" to "server-intent-filters",
            ),
            merged.expectedIntentFilterSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-actions",
                "service:com.server.SyncService" to "server-intent-actions",
            ),
            merged.expectedIntentFilterActionSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-categories",
                "service:com.server.SyncService" to "server-intent-categories",
            ),
            merged.expectedIntentFilterCategorySha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-data",
                "service:com.server.SyncService" to "server-intent-data",
            ),
            merged.expectedIntentFilterDataSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-scheme",
                "service:com.server.SyncService" to "server-intent-data-scheme",
            ),
            merged.expectedIntentFilterDataSchemeSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-authority",
                "service:com.server.SyncService" to "server-intent-data-authority",
            ),
            merged.expectedIntentFilterDataAuthoritySha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-path",
                "service:com.server.SyncService" to "server-intent-data-path",
            ),
            merged.expectedIntentFilterDataPathSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-data-mime",
                "service:com.server.SyncService" to "server-intent-data-mime",
            ),
            merged.expectedIntentFilterDataMimeTypeSha256,
        )
        assertEquals(
            mapOf(
                "activity:com.local.MainActivity" to "local-intent-semantics",
                "service:com.server.SyncService" to "server-intent-semantics",
            ),
            merged.expectedIntentFilterSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-grant-uri",
                "provider:com.server.SyncProvider" to "server-grant-uri",
            ),
            merged.expectedGrantUriPermissionSha256,
        )
        assertEquals(
            mapOf(
                "provider:com.local.DataProvider" to "local-grant-uri-semantics",
                "provider:com.server.SyncProvider" to "server-grant-uri-semantics",
            ),
            merged.expectedGrantUriPermissionSemanticsSha256,
        )
        assertEquals("server-uses-feature", merged.expectedUsesFeatureSha256)
        assertEquals("server-uses-feature-name", merged.expectedUsesFeatureNameSha256)
        assertEquals("server-uses-feature-required", merged.expectedUsesFeatureRequiredSha256)
        assertEquals("server-uses-feature-gles", merged.expectedUsesFeatureGlEsVersionSha256)
        assertEquals(
            mapOf(
                "uses-feature:android.hardware.camera#required" to "true",
                "uses-feature:android.hardware.camera.autofocus#required" to "false",
            ),
            merged.expectedUsesFeatureFieldValues,
        )
        assertEquals("server-uses-sdk", merged.expectedUsesSdkSha256)
        assertEquals("server-uses-sdk-min", merged.expectedUsesSdkMinSha256)
        assertEquals("server-uses-sdk-target", merged.expectedUsesSdkTargetSha256)
        assertEquals("server-uses-sdk-max", merged.expectedUsesSdkMaxSha256)
        assertEquals(
            mapOf(
                "uses-sdk#targetSdkVersion" to "33",
                "uses-sdk#minSdkVersion" to "24",
            ),
            merged.expectedUsesSdkFieldValues,
        )
        assertEquals("server-supports-screens", merged.expectedSupportsScreensSha256)
        assertEquals(
            "server-supports-screens-small",
            merged.expectedSupportsScreensSmallScreensSha256,
        )
        assertEquals(
            "server-supports-screens-normal",
            merged.expectedSupportsScreensNormalScreensSha256,
        )
        assertEquals(
            "server-supports-screens-large",
            merged.expectedSupportsScreensLargeScreensSha256,
        )
        assertEquals(
            "server-supports-screens-xlarge",
            merged.expectedSupportsScreensXlargeScreensSha256,
        )
        assertEquals(
            "server-supports-screens-resizeable",
            merged.expectedSupportsScreensResizeableSha256,
        )
        assertEquals(
            "server-supports-screens-any-density",
            merged.expectedSupportsScreensAnyDensitySha256,
        )
        assertEquals(
            "server-supports-screens-requires-smallest-width",
            merged.expectedSupportsScreensRequiresSmallestWidthDpSha256,
        )
        assertEquals(
            "server-supports-screens-compatible-width-limit",
            merged.expectedSupportsScreensCompatibleWidthLimitDpSha256,
        )
        assertEquals(
            "server-supports-screens-largest-width-limit",
            merged.expectedSupportsScreensLargestWidthLimitDpSha256,
        )
        assertEquals("server-compatible-screens", merged.expectedCompatibleScreensSha256)
        assertEquals(
            "server-compatible-screens-size",
            merged.expectedCompatibleScreensScreenSizeSha256,
        )
        assertEquals(
            "server-compatible-screens-density",
            merged.expectedCompatibleScreensScreenDensitySha256,
        )
        assertEquals("server-uses-library", merged.expectedUsesLibrarySha256)
        assertEquals("server-uses-library-name", merged.expectedUsesLibraryNameSha256)
        assertEquals("server-uses-library-required", merged.expectedUsesLibraryRequiredSha256)
        assertEquals(
            mapOf(
                "uses-library:org.apache.http.legacy#required" to "false",
                "uses-library:android.test.runner#required" to "true",
            ),
            merged.expectedUsesLibraryFieldValues,
        )
        assertEquals("server-uses-library-only", merged.expectedUsesLibraryOnlySha256)
        assertEquals("server-uses-library-only-name", merged.expectedUsesLibraryOnlyNameSha256)
        assertEquals("server-uses-library-only-required", merged.expectedUsesLibraryOnlyRequiredSha256)
        assertEquals("server-uses-native-library", merged.expectedUsesNativeLibrarySha256)
        assertEquals("server-uses-native-library-name", merged.expectedUsesNativeLibraryNameSha256)
        assertEquals(
            "server-uses-native-library-required",
            merged.expectedUsesNativeLibraryRequiredSha256,
        )
        assertEquals(
            mapOf(
                "uses-native-library:com.local.sec#required" to "true",
                "uses-native-library:com.server.sec#required" to "false",
            ),
            merged.expectedUsesNativeLibraryFieldValues,
        )
        assertEquals("server-queries", merged.expectedQueriesSha256)
        assertEquals("server-queries-package", merged.expectedQueriesPackageSha256)
        assertEquals("server-queries-package-name", merged.expectedQueriesPackageNameSha256)
        assertEquals("server-queries-package-semantics", merged.expectedQueriesPackageSemanticsSha256)
        assertEquals("server-queries-provider", merged.expectedQueriesProviderSha256)
        assertEquals("server-queries-provider-authority", merged.expectedQueriesProviderAuthoritySha256)
        assertEquals("server-queries-provider-semantics", merged.expectedQueriesProviderSemanticsSha256)
        assertEquals("server-queries-intent", merged.expectedQueriesIntentSha256)
        assertEquals("server-queries-intent-action", merged.expectedQueriesIntentActionSha256)
        assertEquals("server-queries-intent-category", merged.expectedQueriesIntentCategorySha256)
        assertEquals("server-queries-intent-data", merged.expectedQueriesIntentDataSha256)
        assertEquals("server-queries-intent-data-scheme", merged.expectedQueriesIntentDataSchemeSha256)
        assertEquals("server-queries-intent-data-authority", merged.expectedQueriesIntentDataAuthoritySha256)
        assertEquals("server-queries-intent-data-path", merged.expectedQueriesIntentDataPathSha256)
        assertEquals("server-queries-intent-data-mime", merged.expectedQueriesIntentDataMimeTypeSha256)
        assertEquals("server-queries-intent-semantics", merged.expectedQueriesIntentSemanticsSha256)
        assertEquals("server-application-semantics", merged.expectedApplicationSemanticsSha256)
        assertEquals(
            "server-application-security-semantics",
            merged.expectedApplicationSecuritySemanticsSha256,
        )
        assertEquals(
            "server-application-runtime-semantics",
            merged.expectedApplicationRuntimeSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "application#usesCleartextTraffic" to "false",
                "application#networkSecurityConfig" to "@xml/network_security_config",
            ),
            merged.expectedApplicationFieldValues,
        )
        assertEquals(
            mapOf(
                "channel" to "string",
                "build" to "string",
            ),
            merged.expectedMetaDataType,
        )
        assertEquals(
            mapOf(
                "channel" to "local-meta-hash",
                "build" to "server-meta-hash",
            ),
            merged.expectedMetaDataValueSha256,
        )
        assertEquals(
            mapOf(
                "channel" to "local-manifest-meta-entry",
                "build" to "server-manifest-meta-entry",
            ),
            merged.expectedManifestMetaDataEntrySha256,
        )
        assertEquals(
            mapOf(
                "channel" to "local-manifest-meta-semantics",
                "build" to "server-manifest-meta-semantics",
            ),
            merged.expectedManifestMetaDataSemanticsSha256,
        )
        assertEquals(
            mapOf(
                "channel" to "local",
                "build" to "prod",
            ),
            merged.expectedMetaData,
        )
    }

    @Test
    fun `capturePolicy serializes extended baseline keys`() {
        val policy = TamperPolicy(
            expectedSigningCertificateLineageSha256 = "signing-lineage",
            expectedApkSigningBlockSha256 = "signing-block",
            expectedApkSigningBlockIdSha256 = mapOf("0x7109871a" to "v2-block"),
            expectedResourcesArscSha256 = "resources-arsc",
            expectedResourceInventorySha256 = "resource-inventory",
            expectedResourceEntrySha256 = mapOf("res/raw/leona.bin" to "resource-entry"),
            expectedDynamicFeatureSplitSha256 = "dynamic-features",
            expectedDynamicFeatureSplitNameSha256 = "dynamic-feature-names",
            expectedConfigSplitAxisSha256 = "config-axes",
            expectedConfigSplitNameSha256 = "config-names",
            expectedConfigSplitAbiSha256 = "config-abis",
            expectedConfigSplitLocaleSha256 = "config-locales",
            expectedConfigSplitDensitySha256 = "config-densities",
            expectedComponentAccessSemanticsSha256 = mapOf(
                "activity:com.leonasec.MainActivity" to "component-access-semantics",
            ),
            expectedComponentOperationalSemanticsSha256 = mapOf(
                "activity:com.leonasec.MainActivity" to "component-operational-semantics",
            ),
            expectedProviderSemanticsSha256 = mapOf(
                "provider:com.leonasec.DataProvider" to "provider-semantics",
            ),
            expectedProviderAccessSemanticsSha256 = mapOf(
                "provider:com.leonasec.DataProvider" to "provider-access-semantics",
            ),
            expectedProviderOperationalSemanticsSha256 = mapOf(
                "provider:com.leonasec.DataProvider" to "provider-operational-semantics",
            ),
            expectedIntentFilterSemanticsSha256 = mapOf(
                "activity:com.leonasec.MainActivity" to "intent-filter-semantics",
            ),
            expectedGrantUriPermissionSemanticsSha256 = mapOf(
                "provider:com.leonasec.DataProvider" to "grant-uri-semantics",
            ),
            expectedMetaDataType = mapOf("channel" to "string"),
            expectedMetaDataValueSha256 = mapOf("channel" to "meta-hash"),
            expectedManifestMetaDataEntrySha256 = mapOf("channel" to "manifest-meta-entry"),
            expectedManifestMetaDataSemanticsSha256 = mapOf("channel" to "manifest-meta-semantics"),
            expectedUsesFeatureFieldValues = mapOf(
                "uses-feature:android.hardware.camera#required" to "true",
            ),
            expectedUsesSdkSha256 = "uses-sdk",
            expectedUsesSdkFieldValues = mapOf(
                "uses-sdk#targetSdkVersion" to "34",
            ),
            expectedSupportsScreensSha256 = "supports-screens",
            expectedSupportsScreensSmallScreensSha256 = "supports-screens-small",
            expectedSupportsScreensNormalScreensSha256 = "supports-screens-normal",
            expectedSupportsScreensLargeScreensSha256 = "supports-screens-large",
            expectedSupportsScreensXlargeScreensSha256 = "supports-screens-xlarge",
            expectedSupportsScreensResizeableSha256 = "supports-screens-resizeable",
            expectedSupportsScreensAnyDensitySha256 = "supports-screens-any-density",
            expectedSupportsScreensRequiresSmallestWidthDpSha256 =
                "supports-screens-requires-smallest-width",
            expectedSupportsScreensCompatibleWidthLimitDpSha256 =
                "supports-screens-compatible-width-limit",
            expectedSupportsScreensLargestWidthLimitDpSha256 =
                "supports-screens-largest-width-limit",
            expectedCompatibleScreensSha256 = "compatible-screens",
            expectedCompatibleScreensScreenSizeSha256 = "compatible-screens-size",
            expectedCompatibleScreensScreenDensitySha256 = "compatible-screens-density",
            expectedQueriesPackageNameSha256 = "queries-package-names",
            expectedQueriesPackageSemanticsSha256 = "queries-package-semantics",
            expectedQueriesProviderAuthoritySha256 = "queries-provider-authorities",
            expectedQueriesProviderSemanticsSha256 = "queries-provider-semantics",
            expectedUsesLibraryNameSha256 = "uses-library-names",
            expectedUsesLibraryRequiredSha256 = "uses-library-required",
            expectedUsesLibraryFieldValues = mapOf(
                "uses-library:org.apache.http.legacy#required" to "false",
            ),
            expectedUsesLibraryOnlyNameSha256 = "uses-library-only-names",
            expectedUsesLibraryOnlyRequiredSha256 = "uses-library-only-required",
            expectedUsesNativeLibraryNameSha256 = "uses-native-library-names",
            expectedUsesNativeLibraryRequiredSha256 = "uses-native-library-required",
            expectedUsesNativeLibraryFieldValues = mapOf(
                "uses-native-library:com.example.sec#required" to "true",
            ),
            expectedQueriesIntentActionSha256 = "queries-intent-actions",
            expectedQueriesIntentCategorySha256 = "queries-intent-categories",
            expectedQueriesIntentDataSha256 = "queries-intent-data",
            expectedQueriesIntentDataSchemeSha256 = "queries-intent-data-scheme",
            expectedQueriesIntentDataAuthoritySha256 = "queries-intent-data-authority",
            expectedQueriesIntentDataPathSha256 = "queries-intent-data-path",
            expectedQueriesIntentDataMimeTypeSha256 = "queries-intent-data-mime",
            expectedQueriesIntentSemanticsSha256 = "queries-intent-semantics",
            expectedApplicationSemanticsSha256 = "application-semantics",
            expectedApplicationSecuritySemanticsSha256 = "application-security-semantics",
            expectedApplicationRuntimeSemanticsSha256 = "application-runtime-semantics",
        )

        val snapshot = AppIntegrity.capturePolicy(policy)

        assertTrue(snapshot.contains("expectedSigningCertificateLineageSha256=signing-lineage"))
        assertTrue(snapshot.contains("expectedApkSigningBlockSha256=signing-block"))
        assertTrue(snapshot.contains("expectedApkSigningBlockIdSha256.0x7109871a=v2-block"))
        assertTrue(snapshot.contains("expectedResourcesArscSha256=resources-arsc"))
        assertTrue(snapshot.contains("expectedResourceInventorySha256=resource-inventory"))
        assertTrue(snapshot.contains("expectedResourceEntrySha256.res/raw/leona.bin=resource-entry"))
        assertTrue(snapshot.contains("expectedDynamicFeatureSplitSha256=dynamic-features"))
        assertTrue(snapshot.contains("expectedDynamicFeatureSplitNameSha256=dynamic-feature-names"))
        assertTrue(snapshot.contains("expectedConfigSplitAxisSha256=config-axes"))
        assertTrue(snapshot.contains("expectedConfigSplitNameSha256=config-names"))
        assertTrue(snapshot.contains("expectedConfigSplitAbiSha256=config-abis"))
        assertTrue(snapshot.contains("expectedConfigSplitLocaleSha256=config-locales"))
        assertTrue(snapshot.contains("expectedConfigSplitDensitySha256=config-densities"))
        assertTrue(
            snapshot.contains(
                "expectedComponentAccessSemanticsSha256.activity:com.leonasec.MainActivity=component-access-semantics",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedComponentOperationalSemanticsSha256.activity:com.leonasec.MainActivity=component-operational-semantics",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedProviderSemanticsSha256.provider:com.leonasec.DataProvider=provider-semantics",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedProviderAccessSemanticsSha256.provider:com.leonasec.DataProvider=provider-access-semantics",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedProviderOperationalSemanticsSha256.provider:com.leonasec.DataProvider=provider-operational-semantics",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedIntentFilterSemanticsSha256.activity:com.leonasec.MainActivity=intent-filter-semantics",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedGrantUriPermissionSemanticsSha256.provider:com.leonasec.DataProvider=grant-uri-semantics",
            ),
        )
        assertTrue(snapshot.contains("expectedMetaDataType.channel=string"))
        assertTrue(snapshot.contains("expectedMetaDataValueSha256.channel=meta-hash"))
        assertTrue(snapshot.contains("expectedManifestMetaDataEntrySha256.channel=manifest-meta-entry"))
        assertTrue(snapshot.contains("expectedManifestMetaDataSemanticsSha256.channel=manifest-meta-semantics"))
        assertTrue(
            snapshot.contains(
                "expectedUsesFeatureField.uses-feature:android.hardware.camera#required=true",
            ),
        )
        assertTrue(snapshot.contains("expectedUsesSdkSha256=uses-sdk"))
        assertTrue(snapshot.contains("expectedUsesSdkField.uses-sdk#targetSdkVersion=34"))
        assertTrue(snapshot.contains("expectedSupportsScreensSha256=supports-screens"))
        assertTrue(snapshot.contains("expectedSupportsScreensSmallScreensSha256=supports-screens-small"))
        assertTrue(snapshot.contains("expectedSupportsScreensNormalScreensSha256=supports-screens-normal"))
        assertTrue(snapshot.contains("expectedSupportsScreensLargeScreensSha256=supports-screens-large"))
        assertTrue(snapshot.contains("expectedSupportsScreensXlargeScreensSha256=supports-screens-xlarge"))
        assertTrue(snapshot.contains("expectedSupportsScreensResizeableSha256=supports-screens-resizeable"))
        assertTrue(snapshot.contains("expectedSupportsScreensAnyDensitySha256=supports-screens-any-density"))
        assertTrue(
            snapshot.contains(
                "expectedSupportsScreensRequiresSmallestWidthDpSha256=supports-screens-requires-smallest-width",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedSupportsScreensCompatibleWidthLimitDpSha256=supports-screens-compatible-width-limit",
            ),
        )
        assertTrue(
            snapshot.contains(
                "expectedSupportsScreensLargestWidthLimitDpSha256=supports-screens-largest-width-limit",
            ),
        )
        assertTrue(snapshot.contains("expectedCompatibleScreensSha256=compatible-screens"))
        assertTrue(snapshot.contains("expectedCompatibleScreensScreenSizeSha256=compatible-screens-size"))
        assertTrue(snapshot.contains("expectedCompatibleScreensScreenDensitySha256=compatible-screens-density"))
        assertTrue(snapshot.contains("expectedUsesLibraryNameSha256=uses-library-names"))
        assertTrue(snapshot.contains("expectedUsesLibraryRequiredSha256=uses-library-required"))
        assertTrue(
            snapshot.contains(
                "expectedUsesLibraryField.uses-library:org.apache.http.legacy#required=false",
            ),
        )
        assertTrue(snapshot.contains("expectedUsesLibraryOnlyNameSha256=uses-library-only-names"))
        assertTrue(snapshot.contains("expectedUsesLibraryOnlyRequiredSha256=uses-library-only-required"))
        assertTrue(snapshot.contains("expectedUsesNativeLibraryNameSha256=uses-native-library-names"))
        assertTrue(snapshot.contains("expectedUsesNativeLibraryRequiredSha256=uses-native-library-required"))
        assertTrue(
            snapshot.contains(
                "expectedUsesNativeLibraryField.uses-native-library:com.example.sec#required=true",
            ),
        )
        assertTrue(snapshot.contains("expectedQueriesPackageNameSha256=queries-package-names"))
        assertTrue(snapshot.contains("expectedQueriesPackageSemanticsSha256=queries-package-semantics"))
        assertTrue(snapshot.contains("expectedQueriesProviderAuthoritySha256=queries-provider-authorities"))
        assertTrue(snapshot.contains("expectedQueriesProviderSemanticsSha256=queries-provider-semantics"))
        assertTrue(snapshot.contains("expectedQueriesIntentActionSha256=queries-intent-actions"))
        assertTrue(snapshot.contains("expectedQueriesIntentCategorySha256=queries-intent-categories"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataSha256=queries-intent-data"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataSchemeSha256=queries-intent-data-scheme"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataAuthoritySha256=queries-intent-data-authority"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataPathSha256=queries-intent-data-path"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataMimeTypeSha256=queries-intent-data-mime"))
        assertTrue(snapshot.contains("expectedQueriesIntentSemanticsSha256=queries-intent-semantics"))
        assertTrue(snapshot.contains("expectedApplicationSemanticsSha256=application-semantics"))
        assertTrue(snapshot.contains("expectedApplicationSecuritySemanticsSha256=application-security-semantics"))
        assertTrue(snapshot.contains("expectedApplicationRuntimeSemanticsSha256=application-runtime-semantics"))
    }
}
