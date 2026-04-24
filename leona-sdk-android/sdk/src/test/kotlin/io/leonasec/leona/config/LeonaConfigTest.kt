/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class LeonaConfigTest {

    @Test
    fun `default builder enables injection and environment detection`() {
        val cfg = LeonaConfig.Builder().build()
        assertTrue(cfg.injectionDetectionEnabled)
        assertTrue(cfg.environmentDetectionEnabled)
        assertFalse(cfg.verboseNativeLogging)
        assertTrue(cfg.preferStrongBoxBackedKey)
        assertNull(cfg.reportingEndpoint)
        assertNull(cfg.apiKey)
        assertNull(cfg.tenantId)
        assertEquals("default", cfg.appId)
        assertEquals(LeonaRegion.CN_BJ, cfg.region)
        assertTrue(cfg.transportEnabled)
        assertTrue(cfg.cloudConfigEnabled)
        assertNull(cfg.cloudConfigEndpoint)
        assertFalse(cfg.syncInit)
        assertFalse(cfg.verifyServerCert)
        assertEquals(-1L, cfg.disableCollectionWindowMs)
        assertTrue(cfg.disabledSignals.isEmpty())
        assertNull(cfg.channel)
        assertNull(cfg.extraInfo)
        assertFalse(cfg.firstPartyMode)
        assertTrue(cfg.certificatePins.isEmpty())
        assertNull(cfg.attestationProvider)
        assertNull(cfg.expectedPackageName)
        assertTrue(cfg.allowedInstallerPackages.isEmpty())
        assertTrue(cfg.allowedSigningCertSha256.isEmpty())
        assertNull(cfg.expectedApkSha256)
        assertTrue(cfg.expectedNativeLibSha256.isEmpty())
        assertNull(cfg.expectedManifestEntrySha256)
        assertTrue(cfg.expectedDexSha256.isEmpty())
        assertTrue(cfg.expectedDexSectionSha256.isEmpty())
        assertTrue(cfg.expectedDexMethodSha256.isEmpty())
        assertTrue(cfg.expectedSplitApkSha256.isEmpty())
        assertNull(cfg.expectedSplitInventorySha256)
        assertNull(cfg.expectedDynamicFeatureSplitSha256)
        assertNull(cfg.expectedDynamicFeatureSplitNameSha256)
        assertNull(cfg.expectedConfigSplitAxisSha256)
        assertNull(cfg.expectedConfigSplitNameSha256)
        assertNull(cfg.expectedConfigSplitAbiSha256)
        assertNull(cfg.expectedConfigSplitLocaleSha256)
        assertNull(cfg.expectedConfigSplitDensitySha256)
        assertTrue(cfg.expectedElfSectionSha256.isEmpty())
        assertTrue(cfg.expectedElfExportSymbolSha256.isEmpty())
        assertNull(cfg.expectedRequestedPermissionsSha256)
        assertNull(cfg.expectedRequestedPermissionSemanticsSha256)
        assertNull(cfg.expectedDeclaredPermissionSemanticsSha256)
        assertTrue(cfg.expectedDeclaredPermissionFieldValues.isEmpty())
        assertTrue(cfg.expectedComponentSignatureSha256.isEmpty())
        assertTrue(cfg.expectedComponentFieldValues.isEmpty())
        assertTrue(cfg.expectedProviderUriPermissionPatternsSha256.isEmpty())
        assertTrue(cfg.expectedProviderPathPermissionsSha256.isEmpty())
        assertTrue(cfg.expectedProviderAuthoritySetSha256.isEmpty())
        assertTrue(cfg.expectedProviderSemanticsSha256.isEmpty())
        assertTrue(cfg.expectedProviderAccessSemanticsSha256.isEmpty())
        assertTrue(cfg.expectedProviderOperationalSemanticsSha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterSha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterActionSha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterCategorySha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterDataSha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterDataSchemeSha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterDataAuthoritySha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterDataPathSha256.isEmpty())
        assertTrue(cfg.expectedIntentFilterDataMimeTypeSha256.isEmpty())
        assertTrue(cfg.expectedGrantUriPermissionSha256.isEmpty())
        assertNull(cfg.expectedUsesFeatureSha256)
        assertNull(cfg.expectedUsesFeatureNameSha256)
        assertNull(cfg.expectedUsesFeatureRequiredSha256)
        assertNull(cfg.expectedUsesFeatureGlEsVersionSha256)
        assertNull(cfg.expectedUsesSdkSha256)
        assertNull(cfg.expectedUsesSdkMinSha256)
        assertNull(cfg.expectedUsesSdkTargetSha256)
        assertNull(cfg.expectedUsesSdkMaxSha256)
        assertNull(cfg.expectedSupportsScreensSha256)
        assertNull(cfg.expectedSupportsScreensSmallScreensSha256)
        assertNull(cfg.expectedSupportsScreensNormalScreensSha256)
        assertNull(cfg.expectedSupportsScreensLargeScreensSha256)
        assertNull(cfg.expectedSupportsScreensXlargeScreensSha256)
        assertNull(cfg.expectedSupportsScreensResizeableSha256)
        assertNull(cfg.expectedSupportsScreensAnyDensitySha256)
        assertNull(cfg.expectedSupportsScreensRequiresSmallestWidthDpSha256)
        assertNull(cfg.expectedSupportsScreensCompatibleWidthLimitDpSha256)
        assertNull(cfg.expectedSupportsScreensLargestWidthLimitDpSha256)
        assertNull(cfg.expectedCompatibleScreensSha256)
        assertNull(cfg.expectedCompatibleScreensScreenSizeSha256)
        assertNull(cfg.expectedCompatibleScreensScreenDensitySha256)
        assertNull(cfg.expectedUsesLibrarySha256)
        assertNull(cfg.expectedUsesLibraryNameSha256)
        assertNull(cfg.expectedUsesLibraryRequiredSha256)
        assertNull(cfg.expectedUsesLibraryOnlySha256)
        assertNull(cfg.expectedUsesLibraryOnlyNameSha256)
        assertNull(cfg.expectedUsesLibraryOnlyRequiredSha256)
        assertNull(cfg.expectedUsesNativeLibrarySha256)
        assertNull(cfg.expectedUsesNativeLibraryNameSha256)
        assertNull(cfg.expectedUsesNativeLibraryRequiredSha256)
        assertNull(cfg.expectedQueriesSha256)
        assertNull(cfg.expectedQueriesPackageSha256)
        assertNull(cfg.expectedQueriesPackageNameSha256)
        assertNull(cfg.expectedQueriesProviderSha256)
        assertNull(cfg.expectedQueriesProviderAuthoritySha256)
        assertNull(cfg.expectedQueriesIntentSha256)
        assertNull(cfg.expectedQueriesIntentActionSha256)
        assertNull(cfg.expectedQueriesIntentCategorySha256)
        assertNull(cfg.expectedQueriesIntentDataSha256)
        assertNull(cfg.expectedQueriesIntentDataSchemeSha256)
        assertNull(cfg.expectedQueriesIntentDataAuthoritySha256)
        assertNull(cfg.expectedQueriesIntentDataPathSha256)
        assertNull(cfg.expectedQueriesIntentDataMimeTypeSha256)
        assertNull(cfg.expectedApplicationSemanticsSha256)
        assertNull(cfg.expectedApplicationSecuritySemanticsSha256)
        assertNull(cfg.expectedApplicationRuntimeSemanticsSha256)
        assertTrue(cfg.expectedApplicationFieldValues.isEmpty())
        assertTrue(cfg.expectedMetaData.isEmpty())
    }

    @Test
    fun `builder respects disabled flags`() {
        val cfg = LeonaConfig.Builder()
            .enableInjectionDetection(false)
            .enableEnvironmentDetection(false)
            .transportEnabled(false)
            .enableCloudConfig(false)
            .syncInit(true)
            .verifyServerCert(true)
            .disableCollectionWindowMs(12_345L)
            .disabledSignals("androidId", "root")
            .channel("play")
            .extraInfo("demo")
            .firstPartyMode(true)
            .verboseNativeLogging(true)
            .preferStrongBoxBackedKey(false)
            .build()

        assertFalse(cfg.injectionDetectionEnabled)
        assertFalse(cfg.environmentDetectionEnabled)
        assertFalse(cfg.transportEnabled)
        assertFalse(cfg.cloudConfigEnabled)
        assertTrue(cfg.syncInit)
        assertTrue(cfg.verifyServerCert)
        assertEquals(12_345L, cfg.disableCollectionWindowMs)
        assertEquals(setOf("androidId", "root"), cfg.disabledSignals)
        assertEquals("play", cfg.channel)
        assertEquals("demo", cfg.extraInfo)
        assertTrue(cfg.firstPartyMode)
        assertTrue(cfg.verboseNativeLogging)
        assertFalse(cfg.preferStrongBoxBackedKey)
    }

    @Test
    fun `native handle encodes the enabled flags`() {
        val allOn = LeonaConfig.Builder()
            .enableInjectionDetection(true)
            .enableEnvironmentDetection(true)
            .verboseNativeLogging(true)
            .build()
        val allOff = LeonaConfig.Builder()
            .enableInjectionDetection(false)
            .enableEnvironmentDetection(false)
            .verboseNativeLogging(false)
            .build()

        assertNotEquals(0L, allOn.toNativeHandle())
        assertEquals(0L, allOff.toNativeHandle())

        val injectionOnly = LeonaConfig.Builder()
            .enableInjectionDetection(true)
            .enableEnvironmentDetection(false)
            .verboseNativeLogging(false)
            .build()
        assertEquals(1L, injectionOnly.toNativeHandle())

        val environmentOnly = LeonaConfig.Builder()
            .enableInjectionDetection(false)
            .enableEnvironmentDetection(true)
            .verboseNativeLogging(false)
            .build()
        assertEquals(2L, environmentOnly.toNativeHandle())
    }

    @Test
    fun `endpoint and apiKey are stored verbatim`() {
        val cfg = LeonaConfig.Builder()
            .reportingEndpoint("https://api.leonasec.io/v1")
            .cloudConfigEndpoint("https://cfg.leonasec.io/mobile")
            .apiKey("leona_live_abc123")
            .tenantId("tenant-demo")
            .appId("payments")
            .region(LeonaRegion.SG)
            .build()
        assertEquals("https://api.leonasec.io/v1", cfg.reportingEndpoint)
        assertEquals("https://cfg.leonasec.io/mobile", cfg.cloudConfigEndpoint)
        assertEquals("leona_live_abc123", cfg.apiKey)
        assertEquals("tenant-demo", cfg.tenantId)
        assertEquals("payments", cfg.appId)
        assertEquals(LeonaRegion.SG, cfg.region)
    }

    @Test
    fun `certificate pins and attestation provider are stored`() {
        val provider = object : AttestationProvider {
            override suspend fun attest(challenge: String, installId: String): AttestationStatement? {
                return AttestationStatement("test", "$challenge:$installId")
            }
        }

        val cfg = LeonaConfig.Builder()
            .certificatePin("api.leonasec.io", "abc", "sha256/def")
            .attestationProvider(provider)
            .build()

        assertEquals(setOf("sha256/abc", "sha256/def"), cfg.certificatePins["api.leonasec.io"])
        assertSame(provider, cfg.attestationProvider)
    }

    @Test
    fun `tamper baselines are normalized and stored`() {
        val cfg = LeonaConfig.Builder()
            .expectedPackageName("io.leonasec.demo")
            .allowedInstallerPackages("com.android.vending", " com.amazon.venezia ")
            .allowedSigningCertSha256("AA11", " bb22 ")
            .expectedApkSha256("CC33")
            .expectedNativeLibrarySha256("libleona.so", "DD44")
            .expectedNativeLibrarySha256(mapOf("libfoo.so" to "EE55"))
            .expectedManifestEntrySha256("FF66")
            .expectedDexSha256("classes.dex", "1122")
            .expectedDexSectionSha256("classes.dex#code_item", "5566")
            .expectedDexMethodSha256("classes.dex#Lcom/example/MainActivity;->isTampered()Z", "6677")
            .expectedSplitApkSha256("config.arm64_v8a.apk", "3344")
            .expectedSplitInventorySha256("4455")
            .expectedDynamicFeatureSplitSha256("4466")
            .expectedDynamicFeatureSplitNameSha256("4467")
            .expectedConfigSplitAxisSha256("4477")
            .expectedConfigSplitNameSha256("4478")
            .expectedConfigSplitAbiSha256("4488")
            .expectedConfigSplitLocaleSha256("4499")
            .expectedConfigSplitDensitySha256("44aa")
            .expectedElfSectionSha256("libleona.so#.text", "7788")
            .expectedElfExportSymbolSha256("libleona.so#JNI_OnLoad", "99aa")
            .expectedElfExportGraphSha256("libleona.so", "a1a2")
            .expectedRequestedPermissionsSha256("bbcc")
            .expectedRequestedPermissionSemanticsSha256("ccee")
            .expectedDeclaredPermissionSemanticsSha256("d0d1")
            .expectedDeclaredPermissionFieldValue(
                "permission:com.example.permission.GUARD#protectionLevel",
                "18",
            )
            .expectedComponentSignatureSha256("activity:com.example.MainActivity", "ddee")
            .expectedComponentFieldValue("activity:com.example.MainActivity#exported", "false")
            .expectedProviderUriPermissionPatternsSha256("provider:com.example.DataProvider", "eeff")
            .expectedProviderPathPermissionsSha256("provider:com.example.DataProvider", "ffaa")
            .expectedProviderAuthoritySetSha256("provider:com.example.DataProvider", "f0f0")
            .expectedProviderSemanticsSha256("provider:com.example.DataProvider", "f1f1")
            .expectedProviderAccessSemanticsSha256("provider:com.example.DataProvider", "f2f2")
            .expectedProviderOperationalSemanticsSha256("provider:com.example.DataProvider", "f3f3")
            .expectedIntentFilterSha256("activity:com.example.MainActivity", "abab")
            .expectedIntentFilterActionSha256("activity:com.example.MainActivity", "acac")
            .expectedIntentFilterCategorySha256("activity:com.example.MainActivity", "adad")
            .expectedIntentFilterDataSha256("activity:com.example.MainActivity", "aeae")
            .expectedIntentFilterDataSchemeSha256("activity:com.example.MainActivity", "afaf")
            .expectedIntentFilterDataAuthoritySha256("activity:com.example.MainActivity", "b0b0")
            .expectedIntentFilterDataPathSha256("activity:com.example.MainActivity", "b1b1")
            .expectedIntentFilterDataMimeTypeSha256("activity:com.example.MainActivity", "b2b2")
            .expectedGrantUriPermissionSha256("provider:com.example.DataProvider", "bcbc")
            .expectedUsesFeatureSha256("c1c1")
            .expectedUsesFeatureNameSha256("c1c2")
            .expectedUsesFeatureRequiredSha256("c1c3")
            .expectedUsesFeatureGlEsVersionSha256("c1c4")
            .expectedUsesSdkSha256("c2c2")
            .expectedUsesSdkMinSha256("c2c3")
            .expectedUsesSdkTargetSha256("c2c4")
            .expectedUsesSdkMaxSha256("c2c5")
            .expectedSupportsScreensSha256("c3c3")
            .expectedSupportsScreensSmallScreensSha256("c3c4")
            .expectedSupportsScreensNormalScreensSha256("c3c5")
            .expectedSupportsScreensLargeScreensSha256("c3c6")
            .expectedSupportsScreensXlargeScreensSha256("c3c7")
            .expectedSupportsScreensResizeableSha256("c3c8")
            .expectedSupportsScreensAnyDensitySha256("c3c9")
            .expectedSupportsScreensRequiresSmallestWidthDpSha256("c3ca")
            .expectedSupportsScreensCompatibleWidthLimitDpSha256("c3cb")
            .expectedSupportsScreensLargestWidthLimitDpSha256("c3cc")
            .expectedCompatibleScreensSha256("c4c4")
            .expectedCompatibleScreensScreenSizeSha256("c4c5")
            .expectedCompatibleScreensScreenDensitySha256("c4c6")
            .expectedUsesLibrarySha256("c5c5")
            .expectedUsesLibraryNameSha256("c5c8")
            .expectedUsesLibraryRequiredSha256("c5c9")
            .expectedUsesLibraryOnlySha256("c5c6")
            .expectedUsesLibraryOnlyNameSha256("c5ca")
            .expectedUsesLibraryOnlyRequiredSha256("c5cb")
            .expectedUsesNativeLibrarySha256("c5c7")
            .expectedUsesNativeLibraryNameSha256("c5cc")
            .expectedUsesNativeLibraryRequiredSha256("c5cd")
            .expectedQueriesSha256("c6c6")
            .expectedQueriesPackageSha256("c7c7")
            .expectedQueriesPackageNameSha256("c7ca")
            .expectedQueriesProviderSha256("c8c8")
            .expectedQueriesProviderAuthoritySha256("c8ca")
            .expectedQueriesIntentSha256("c9c9")
            .expectedQueriesIntentActionSha256("caca")
            .expectedQueriesIntentCategorySha256("cbcb")
            .expectedQueriesIntentDataSha256("cccc")
            .expectedQueriesIntentDataSchemeSha256("cdcd")
            .expectedQueriesIntentDataAuthoritySha256("cece")
            .expectedQueriesIntentDataPathSha256("cfcf")
            .expectedQueriesIntentDataMimeTypeSha256("d0d0")
            .expectedApplicationSemanticsSha256("d1d1")
            .expectedApplicationSecuritySemanticsSha256("d1d2")
            .expectedApplicationRuntimeSemanticsSha256("d1d3")
            .expectedApplicationFieldValue("application#usesCleartextTraffic", "false")
            .expectedMetaData("channel", "play")
            .build()

        assertEquals("io.leonasec.demo", cfg.expectedPackageName)
        assertEquals(setOf("com.android.vending", "com.amazon.venezia"), cfg.allowedInstallerPackages)
        assertEquals(setOf("aa11", "bb22"), cfg.allowedSigningCertSha256)
        assertEquals("cc33", cfg.expectedApkSha256)
        assertEquals(
            mapOf(
                "libleona.so" to "dd44",
                "libfoo.so" to "ee55",
            ),
            cfg.expectedNativeLibSha256,
        )
        assertEquals("ff66", cfg.expectedManifestEntrySha256)
        assertEquals(mapOf("classes.dex" to "1122"), cfg.expectedDexSha256)
        assertEquals(mapOf("classes.dex#code_item" to "5566"), cfg.expectedDexSectionSha256)
        assertEquals(
            mapOf("classes.dex#Lcom/example/MainActivity;->isTampered()Z" to "6677"),
            cfg.expectedDexMethodSha256,
        )
        assertEquals(mapOf("config.arm64_v8a.apk" to "3344"), cfg.expectedSplitApkSha256)
        assertEquals("4455", cfg.expectedSplitInventorySha256)
        assertEquals("4466", cfg.expectedDynamicFeatureSplitSha256)
        assertEquals("4467", cfg.expectedDynamicFeatureSplitNameSha256)
        assertEquals("4477", cfg.expectedConfigSplitAxisSha256)
        assertEquals("4478", cfg.expectedConfigSplitNameSha256)
        assertEquals("4488", cfg.expectedConfigSplitAbiSha256)
        assertEquals("4499", cfg.expectedConfigSplitLocaleSha256)
        assertEquals("44aa", cfg.expectedConfigSplitDensitySha256)
        assertEquals(mapOf("libleona.so#.text" to "7788"), cfg.expectedElfSectionSha256)
        assertEquals(mapOf("libleona.so#JNI_OnLoad" to "99aa"), cfg.expectedElfExportSymbolSha256)
        assertEquals(mapOf("libleona.so" to "a1a2"), cfg.expectedElfExportGraphSha256)
        assertEquals("bbcc", cfg.expectedRequestedPermissionsSha256)
        assertEquals("ccee", cfg.expectedRequestedPermissionSemanticsSha256)
        assertEquals("d0d1", cfg.expectedDeclaredPermissionSemanticsSha256)
        assertEquals(
            mapOf("permission:com.example.permission.GUARD#protectionLevel" to "18"),
            cfg.expectedDeclaredPermissionFieldValues,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "ddee"),
            cfg.expectedComponentSignatureSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity#exported" to "false"),
            cfg.expectedComponentFieldValues,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "eeff"),
            cfg.expectedProviderUriPermissionPatternsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "ffaa"),
            cfg.expectedProviderPathPermissionsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "f0f0"),
            cfg.expectedProviderAuthoritySetSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "f1f1"),
            cfg.expectedProviderSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "f2f2"),
            cfg.expectedProviderAccessSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "f3f3"),
            cfg.expectedProviderOperationalSemanticsSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "abab"),
            cfg.expectedIntentFilterSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "acac"),
            cfg.expectedIntentFilterActionSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "adad"),
            cfg.expectedIntentFilterCategorySha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "aeae"),
            cfg.expectedIntentFilterDataSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "afaf"),
            cfg.expectedIntentFilterDataSchemeSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "b0b0"),
            cfg.expectedIntentFilterDataAuthoritySha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "b1b1"),
            cfg.expectedIntentFilterDataPathSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "b2b2"),
            cfg.expectedIntentFilterDataMimeTypeSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "bcbc"),
            cfg.expectedGrantUriPermissionSha256,
        )
        assertEquals("c1c1", cfg.expectedUsesFeatureSha256)
        assertEquals("c1c2", cfg.expectedUsesFeatureNameSha256)
        assertEquals("c1c3", cfg.expectedUsesFeatureRequiredSha256)
        assertEquals("c1c4", cfg.expectedUsesFeatureGlEsVersionSha256)
        assertEquals("c2c2", cfg.expectedUsesSdkSha256)
        assertEquals("c2c3", cfg.expectedUsesSdkMinSha256)
        assertEquals("c2c4", cfg.expectedUsesSdkTargetSha256)
        assertEquals("c2c5", cfg.expectedUsesSdkMaxSha256)
        assertEquals("c3c3", cfg.expectedSupportsScreensSha256)
        assertEquals("c3c4", cfg.expectedSupportsScreensSmallScreensSha256)
        assertEquals("c3c5", cfg.expectedSupportsScreensNormalScreensSha256)
        assertEquals("c3c6", cfg.expectedSupportsScreensLargeScreensSha256)
        assertEquals("c3c7", cfg.expectedSupportsScreensXlargeScreensSha256)
        assertEquals("c3c8", cfg.expectedSupportsScreensResizeableSha256)
        assertEquals("c3c9", cfg.expectedSupportsScreensAnyDensitySha256)
        assertEquals("c3ca", cfg.expectedSupportsScreensRequiresSmallestWidthDpSha256)
        assertEquals("c3cb", cfg.expectedSupportsScreensCompatibleWidthLimitDpSha256)
        assertEquals("c3cc", cfg.expectedSupportsScreensLargestWidthLimitDpSha256)
        assertEquals("c4c4", cfg.expectedCompatibleScreensSha256)
        assertEquals("c4c5", cfg.expectedCompatibleScreensScreenSizeSha256)
        assertEquals("c4c6", cfg.expectedCompatibleScreensScreenDensitySha256)
        assertEquals("c5c5", cfg.expectedUsesLibrarySha256)
        assertEquals("c5c8", cfg.expectedUsesLibraryNameSha256)
        assertEquals("c5c9", cfg.expectedUsesLibraryRequiredSha256)
        assertEquals("c5c6", cfg.expectedUsesLibraryOnlySha256)
        assertEquals("c5ca", cfg.expectedUsesLibraryOnlyNameSha256)
        assertEquals("c5cb", cfg.expectedUsesLibraryOnlyRequiredSha256)
        assertEquals("c5c7", cfg.expectedUsesNativeLibrarySha256)
        assertEquals("c5cc", cfg.expectedUsesNativeLibraryNameSha256)
        assertEquals("c5cd", cfg.expectedUsesNativeLibraryRequiredSha256)
        assertEquals("c6c6", cfg.expectedQueriesSha256)
        assertEquals("c7c7", cfg.expectedQueriesPackageSha256)
        assertEquals("c7ca", cfg.expectedQueriesPackageNameSha256)
        assertEquals("c8c8", cfg.expectedQueriesProviderSha256)
        assertEquals("c8ca", cfg.expectedQueriesProviderAuthoritySha256)
        assertEquals("c9c9", cfg.expectedQueriesIntentSha256)
        assertEquals("caca", cfg.expectedQueriesIntentActionSha256)
        assertEquals("cbcb", cfg.expectedQueriesIntentCategorySha256)
        assertEquals("cccc", cfg.expectedQueriesIntentDataSha256)
        assertEquals("cdcd", cfg.expectedQueriesIntentDataSchemeSha256)
        assertEquals("cece", cfg.expectedQueriesIntentDataAuthoritySha256)
        assertEquals("cfcf", cfg.expectedQueriesIntentDataPathSha256)
        assertEquals("d0d0", cfg.expectedQueriesIntentDataMimeTypeSha256)
        assertEquals("d1d1", cfg.expectedApplicationSemanticsSha256)
        assertEquals("d1d2", cfg.expectedApplicationSecuritySemanticsSha256)
        assertEquals("d1d3", cfg.expectedApplicationRuntimeSemanticsSha256)
        assertEquals(
            mapOf("application#usesCleartextTraffic" to "false"),
            cfg.expectedApplicationFieldValues,
        )
        assertEquals(mapOf("channel" to "play"), cfg.expectedMetaData)
    }
}
