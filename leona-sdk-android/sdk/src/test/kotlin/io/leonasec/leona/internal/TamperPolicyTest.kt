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
            expectedNativeLibSha256 = mapOf("libleona.so" to "local-lib"),
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
            expectedGrantUriPermissionSha256 = mapOf(
                "provider:com.local.DataProvider" to "local-grant-uri",
            ),
            expectedUsesFeatureSha256 = "local-uses-feature",
            expectedUsesFeatureNameSha256 = "local-uses-feature-name",
            expectedUsesFeatureRequiredSha256 = "local-uses-feature-required",
            expectedUsesFeatureGlEsVersionSha256 = "local-uses-feature-gles",
            expectedUsesSdkSha256 = "local-uses-sdk",
            expectedUsesSdkMinSha256 = "local-uses-sdk-min",
            expectedUsesSdkTargetSha256 = "local-uses-sdk-target",
            expectedUsesSdkMaxSha256 = "local-uses-sdk-max",
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
            expectedUsesLibraryOnlySha256 = "local-uses-library-only",
            expectedUsesLibraryOnlyNameSha256 = "local-uses-library-only-name",
            expectedUsesLibraryOnlyRequiredSha256 = "local-uses-library-only-required",
            expectedUsesNativeLibrarySha256 = "local-uses-native-library",
            expectedUsesNativeLibraryNameSha256 = "local-uses-native-library-name",
            expectedUsesNativeLibraryRequiredSha256 = "local-uses-native-library-required",
            expectedQueriesSha256 = "local-queries",
            expectedQueriesPackageSha256 = "local-queries-package",
            expectedQueriesPackageNameSha256 = "local-queries-package-name",
            expectedQueriesProviderSha256 = "local-queries-provider",
            expectedQueriesProviderAuthoritySha256 = "local-queries-provider-authority",
            expectedQueriesIntentSha256 = "local-queries-intent",
            expectedQueriesIntentActionSha256 = "local-queries-intent-action",
            expectedQueriesIntentCategorySha256 = "local-queries-intent-category",
            expectedQueriesIntentDataSha256 = "local-queries-intent-data",
            expectedQueriesIntentDataSchemeSha256 = "local-queries-intent-data-scheme",
            expectedQueriesIntentDataAuthoritySha256 = "local-queries-intent-data-authority",
            expectedQueriesIntentDataPathSha256 = "local-queries-intent-data-path",
            expectedQueriesIntentDataMimeTypeSha256 = "local-queries-intent-data-mime",
            expectedApplicationSemanticsSha256 = "local-application-semantics",
            expectedApplicationSecuritySemanticsSha256 = "local-application-security-semantics",
            expectedApplicationRuntimeSemanticsSha256 = "local-application-runtime-semantics",
            expectedApplicationFieldValues = mapOf(
                "application#usesCleartextTraffic" to "false",
            ),
            expectedMetaData = mapOf("channel" to "local"),
        )
        val server = TamperPolicy(
            expectedPackageName = "com.server.app",
            allowedInstallerPackages = setOf("com.server.store"),
            expectedNativeLibSha256 = mapOf("libextra.so" to "server-lib"),
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
            expectedGrantUriPermissionSha256 = mapOf(
                "provider:com.server.SyncProvider" to "server-grant-uri",
            ),
            expectedUsesFeatureSha256 = "server-uses-feature",
            expectedUsesFeatureNameSha256 = "server-uses-feature-name",
            expectedUsesFeatureRequiredSha256 = "server-uses-feature-required",
            expectedUsesFeatureGlEsVersionSha256 = "server-uses-feature-gles",
            expectedUsesSdkSha256 = "server-uses-sdk",
            expectedUsesSdkMinSha256 = "server-uses-sdk-min",
            expectedUsesSdkTargetSha256 = "server-uses-sdk-target",
            expectedUsesSdkMaxSha256 = "server-uses-sdk-max",
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
            expectedUsesLibraryOnlySha256 = "server-uses-library-only",
            expectedUsesLibraryOnlyNameSha256 = "server-uses-library-only-name",
            expectedUsesLibraryOnlyRequiredSha256 = "server-uses-library-only-required",
            expectedUsesNativeLibrarySha256 = "server-uses-native-library",
            expectedUsesNativeLibraryNameSha256 = "server-uses-native-library-name",
            expectedUsesNativeLibraryRequiredSha256 = "server-uses-native-library-required",
            expectedQueriesSha256 = "server-queries",
            expectedQueriesPackageSha256 = "server-queries-package",
            expectedQueriesPackageNameSha256 = "server-queries-package-name",
            expectedQueriesProviderSha256 = "server-queries-provider",
            expectedQueriesProviderAuthoritySha256 = "server-queries-provider-authority",
            expectedQueriesIntentSha256 = "server-queries-intent",
            expectedQueriesIntentActionSha256 = "server-queries-intent-action",
            expectedQueriesIntentCategorySha256 = "server-queries-intent-category",
            expectedQueriesIntentDataSha256 = "server-queries-intent-data",
            expectedQueriesIntentDataSchemeSha256 = "server-queries-intent-data-scheme",
            expectedQueriesIntentDataAuthoritySha256 = "server-queries-intent-data-authority",
            expectedQueriesIntentDataPathSha256 = "server-queries-intent-data-path",
            expectedQueriesIntentDataMimeTypeSha256 = "server-queries-intent-data-mime",
            expectedApplicationSemanticsSha256 = "server-application-semantics",
            expectedApplicationSecuritySemanticsSha256 = "server-application-security-semantics",
            expectedApplicationRuntimeSemanticsSha256 = "server-application-runtime-semantics",
            expectedApplicationFieldValues = mapOf(
                "application#networkSecurityConfig" to "@xml/network_security_config",
            ),
            expectedMetaData = mapOf("build" to "prod"),
        )

        val merged = local.merge(server)

        assertEquals("com.server.app", merged.expectedPackageName)
        assertEquals(setOf("com.server.store"), merged.allowedInstallerPackages)
        assertEquals(
            mapOf(
                "libleona.so" to "local-lib",
                "libextra.so" to "server-lib",
            ),
            merged.expectedNativeLibSha256,
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
                "provider:com.local.DataProvider" to "local-grant-uri",
                "provider:com.server.SyncProvider" to "server-grant-uri",
            ),
            merged.expectedGrantUriPermissionSha256,
        )
        assertEquals("server-uses-feature", merged.expectedUsesFeatureSha256)
        assertEquals("server-uses-feature-name", merged.expectedUsesFeatureNameSha256)
        assertEquals("server-uses-feature-required", merged.expectedUsesFeatureRequiredSha256)
        assertEquals("server-uses-feature-gles", merged.expectedUsesFeatureGlEsVersionSha256)
        assertEquals("server-uses-sdk", merged.expectedUsesSdkSha256)
        assertEquals("server-uses-sdk-min", merged.expectedUsesSdkMinSha256)
        assertEquals("server-uses-sdk-target", merged.expectedUsesSdkTargetSha256)
        assertEquals("server-uses-sdk-max", merged.expectedUsesSdkMaxSha256)
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
        assertEquals("server-uses-library-only", merged.expectedUsesLibraryOnlySha256)
        assertEquals("server-uses-library-only-name", merged.expectedUsesLibraryOnlyNameSha256)
        assertEquals("server-uses-library-only-required", merged.expectedUsesLibraryOnlyRequiredSha256)
        assertEquals("server-uses-native-library", merged.expectedUsesNativeLibrarySha256)
        assertEquals("server-uses-native-library-name", merged.expectedUsesNativeLibraryNameSha256)
        assertEquals(
            "server-uses-native-library-required",
            merged.expectedUsesNativeLibraryRequiredSha256,
        )
        assertEquals("server-queries", merged.expectedQueriesSha256)
        assertEquals("server-queries-package", merged.expectedQueriesPackageSha256)
        assertEquals("server-queries-package-name", merged.expectedQueriesPackageNameSha256)
        assertEquals("server-queries-provider", merged.expectedQueriesProviderSha256)
        assertEquals("server-queries-provider-authority", merged.expectedQueriesProviderAuthoritySha256)
        assertEquals("server-queries-intent", merged.expectedQueriesIntentSha256)
        assertEquals("server-queries-intent-action", merged.expectedQueriesIntentActionSha256)
        assertEquals("server-queries-intent-category", merged.expectedQueriesIntentCategorySha256)
        assertEquals("server-queries-intent-data", merged.expectedQueriesIntentDataSha256)
        assertEquals("server-queries-intent-data-scheme", merged.expectedQueriesIntentDataSchemeSha256)
        assertEquals("server-queries-intent-data-authority", merged.expectedQueriesIntentDataAuthoritySha256)
        assertEquals("server-queries-intent-data-path", merged.expectedQueriesIntentDataPathSha256)
        assertEquals("server-queries-intent-data-mime", merged.expectedQueriesIntentDataMimeTypeSha256)
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
                "channel" to "local",
                "build" to "prod",
            ),
            merged.expectedMetaData,
        )
    }

    @Test
    fun `capturePolicy serializes extended baseline keys`() {
        val policy = TamperPolicy(
            expectedDynamicFeatureSplitSha256 = "dynamic-features",
            expectedDynamicFeatureSplitNameSha256 = "dynamic-feature-names",
            expectedConfigSplitAxisSha256 = "config-axes",
            expectedConfigSplitNameSha256 = "config-names",
            expectedConfigSplitAbiSha256 = "config-abis",
            expectedConfigSplitLocaleSha256 = "config-locales",
            expectedConfigSplitDensitySha256 = "config-densities",
            expectedProviderSemanticsSha256 = mapOf(
                "provider:com.leonasec.DataProvider" to "provider-semantics",
            ),
            expectedProviderAccessSemanticsSha256 = mapOf(
                "provider:com.leonasec.DataProvider" to "provider-access-semantics",
            ),
            expectedProviderOperationalSemanticsSha256 = mapOf(
                "provider:com.leonasec.DataProvider" to "provider-operational-semantics",
            ),
            expectedUsesSdkSha256 = "uses-sdk",
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
            expectedQueriesProviderAuthoritySha256 = "queries-provider-authorities",
            expectedUsesLibraryNameSha256 = "uses-library-names",
            expectedUsesLibraryRequiredSha256 = "uses-library-required",
            expectedUsesLibraryOnlyNameSha256 = "uses-library-only-names",
            expectedUsesLibraryOnlyRequiredSha256 = "uses-library-only-required",
            expectedUsesNativeLibraryNameSha256 = "uses-native-library-names",
            expectedUsesNativeLibraryRequiredSha256 = "uses-native-library-required",
            expectedQueriesIntentActionSha256 = "queries-intent-actions",
            expectedQueriesIntentCategorySha256 = "queries-intent-categories",
            expectedQueriesIntentDataSha256 = "queries-intent-data",
            expectedQueriesIntentDataSchemeSha256 = "queries-intent-data-scheme",
            expectedQueriesIntentDataAuthoritySha256 = "queries-intent-data-authority",
            expectedQueriesIntentDataPathSha256 = "queries-intent-data-path",
            expectedQueriesIntentDataMimeTypeSha256 = "queries-intent-data-mime",
            expectedApplicationSemanticsSha256 = "application-semantics",
            expectedApplicationSecuritySemanticsSha256 = "application-security-semantics",
            expectedApplicationRuntimeSemanticsSha256 = "application-runtime-semantics",
        )

        val snapshot = AppIntegrity.capturePolicy(policy)

        assertTrue(snapshot.contains("expectedDynamicFeatureSplitSha256=dynamic-features"))
        assertTrue(snapshot.contains("expectedDynamicFeatureSplitNameSha256=dynamic-feature-names"))
        assertTrue(snapshot.contains("expectedConfigSplitAxisSha256=config-axes"))
        assertTrue(snapshot.contains("expectedConfigSplitNameSha256=config-names"))
        assertTrue(snapshot.contains("expectedConfigSplitAbiSha256=config-abis"))
        assertTrue(snapshot.contains("expectedConfigSplitLocaleSha256=config-locales"))
        assertTrue(snapshot.contains("expectedConfigSplitDensitySha256=config-densities"))
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
        assertTrue(snapshot.contains("expectedUsesSdkSha256=uses-sdk"))
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
        assertTrue(snapshot.contains("expectedUsesLibraryOnlyNameSha256=uses-library-only-names"))
        assertTrue(snapshot.contains("expectedUsesLibraryOnlyRequiredSha256=uses-library-only-required"))
        assertTrue(snapshot.contains("expectedUsesNativeLibraryNameSha256=uses-native-library-names"))
        assertTrue(snapshot.contains("expectedUsesNativeLibraryRequiredSha256=uses-native-library-required"))
        assertTrue(snapshot.contains("expectedQueriesPackageNameSha256=queries-package-names"))
        assertTrue(snapshot.contains("expectedQueriesProviderAuthoritySha256=queries-provider-authorities"))
        assertTrue(snapshot.contains("expectedQueriesIntentActionSha256=queries-intent-actions"))
        assertTrue(snapshot.contains("expectedQueriesIntentCategorySha256=queries-intent-categories"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataSha256=queries-intent-data"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataSchemeSha256=queries-intent-data-scheme"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataAuthoritySha256=queries-intent-data-authority"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataPathSha256=queries-intent-data-path"))
        assertTrue(snapshot.contains("expectedQueriesIntentDataMimeTypeSha256=queries-intent-data-mime"))
        assertTrue(snapshot.contains("expectedApplicationSemanticsSha256=application-semantics"))
        assertTrue(snapshot.contains("expectedApplicationSecuritySemanticsSha256=application-security-semantics"))
        assertTrue(snapshot.contains("expectedApplicationRuntimeSemanticsSha256=application-runtime-semantics"))
    }
}
