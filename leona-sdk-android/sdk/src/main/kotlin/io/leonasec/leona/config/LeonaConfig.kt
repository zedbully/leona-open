/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.config

/**
 * Configuration for the Leona SDK. Immutable — build once, pass to
 * `Leona.init`. Use [Builder] to construct.
 */
class LeonaConfig private constructor(
    /** Enable the runtime injection detector (Frida, Xposed, Substrate, …). */
    val injectionDetectionEnabled: Boolean,
    /** Enable the environment detector (emulator, root, debugger, …). */
    val environmentDetectionEnabled: Boolean,
    /** Reporting endpoint for detection events. Null disables reporting. */
    val reportingEndpoint: String?,
    /** API key for server-side attribution. */
    val apiKey: String?,
    /** Optional tenant or organization identifier for multi-tenant backends. */
    val tenantId: String?,
    /** Logical app identifier used by Leona-managed server-side policies. */
    val appId: String,
    /** Deployment region used when deriving Leona-managed defaults. */
    val region: LeonaRegion,
    /** Enable transport when secure reporting is configured. */
    val transportEnabled: Boolean,
    /** Enable cloud-delivered runtime configuration. */
    val cloudConfigEnabled: Boolean,
    /** Optional endpoint for cloud-delivered runtime configuration. */
    val cloudConfigEndpoint: String?,
    /** Whether init should block on first cloud config refresh. */
    val syncInit: Boolean,
    /** Extra certificate verification switch for future private-core policy. */
    val verifyServerCert: Boolean,
    /** Minimum gap between full Java-side snapshot collections. Negative disables throttling. */
    val disableCollectionWindowMs: Long,
    /** Field-level disable list for privacy and compatibility downgrades. */
    val disabledSignals: Set<String>,
    /** Optional distribution channel label. */
    val channel: String?,
    /** Optional extra business context, trimmed to 1024 chars. */
    val extraInfo: String?,
    /** Whether the embedding app is a first-party/trusted distribution. */
    val firstPartyMode: Boolean,
    /** Whether to emit verbose native logs — disable for release builds. */
    val verboseNativeLogging: Boolean,
    /** Prefer generating the device-binding key inside StrongBox when available. */
    val preferStrongBoxBackedKey: Boolean,
    /** Optional host → certificate pin map used by OkHttp's CertificatePinner. */
    val certificatePins: Map<String, Set<String>>,
    /** Optional device attestation plug point (Play Integrity / OEM / enterprise). */
    val attestationProvider: AttestationProvider?,
    /** Optional expected package name baseline for repackaging detection. */
    val expectedPackageName: String?,
    /** Optional installer allowlist; empty means no installer baseline. */
    val allowedInstallerPackages: Set<String>,
    /** Optional signing certificate allowlist; values are lower-case SHA-256 digests. */
    val allowedSigningCertSha256: Set<String>,
    /** Optional fingerprint over the sorted signing certificate digest lineage. */
    val expectedSigningCertificateLineageSha256: String?,
    /** Optional APK Signing Block hash baseline for v2/v3 signing metadata drift. */
    val expectedApkSigningBlockSha256: String?,
    /** Optional APK Signing Block ID value hashes keyed by decimal or `0x...` ID. */
    val expectedApkSigningBlockIdSha256: Map<String, String>,
    /** Optional APK file hash baseline; lower-case SHA-256 digest. */
    val expectedApkSha256: String?,
    /** Optional native library hash baselines keyed by filename. */
    val expectedNativeLibSha256: Map<String, String>,
    /** Optional AndroidManifest.xml entry hash baseline from the base APK zip. */
    val expectedManifestEntrySha256: String?,
    /** Optional resources.arsc entry hash baseline from the base APK zip. */
    val expectedResourcesArscSha256: String?,
    /** Optional fingerprint over sorted base APK resource/asset entry names. */
    val expectedResourceInventorySha256: String?,
    /** Optional APK resource/asset entry hash baselines keyed by zip entry name. */
    val expectedResourceEntrySha256: Map<String, String>,
    /** Optional classes*.dex hash baselines keyed by entry name. */
    val expectedDexSha256: Map<String, String>,
    /** Optional DEX internal section hashes keyed by `classes.dex#section_name`. */
    val expectedDexSectionSha256: Map<String, String>,
    /** Optional DEX method code hashes keyed by `classes.dex#Lpkg/Cls;->method(sig)ret`. */
    val expectedDexMethodSha256: Map<String, String>,
    /** Optional split APK hash baselines keyed by split filename. */
    val expectedSplitApkSha256: Map<String, String>,
    /** Optional fingerprint over the sorted split APK filename inventory. */
    val expectedSplitInventorySha256: String?,
    /** Optional fingerprint over normalized dynamic-feature split names. */
    val expectedDynamicFeatureSplitSha256: String?,
    /** Optional fingerprint over raw dynamic-feature split filenames. */
    val expectedDynamicFeatureSplitNameSha256: String?,
    /** Optional fingerprint over normalized config split axes. */
    val expectedConfigSplitAxisSha256: String?,
    /** Optional fingerprint over raw config split filenames. */
    val expectedConfigSplitNameSha256: String?,
    /** Optional fingerprint over normalized config split ABI axes. */
    val expectedConfigSplitAbiSha256: String?,
    /** Optional fingerprint over normalized config split locale axes. */
    val expectedConfigSplitLocaleSha256: String?,
    /** Optional fingerprint over normalized config split density axes. */
    val expectedConfigSplitDensitySha256: String?,
    /** Optional ELF section hashes keyed by `libname.so#section_name`. */
    val expectedElfSectionSha256: Map<String, String>,
    /** Optional ELF exported symbol fingerprints keyed by `libname.so#symbol_name`. */
    val expectedElfExportSymbolSha256: Map<String, String>,
    /** Optional ELF export graph hashes keyed by library filename. */
    val expectedElfExportGraphSha256: Map<String, String>,
    /** Optional hash over sorted requested permissions. */
    val expectedRequestedPermissionsSha256: String?,
    /** Optional hash over requested permissions plus semantic flags. */
    val expectedRequestedPermissionSemanticsSha256: String?,
    /** Optional hash over app-declared permission semantics. */
    val expectedDeclaredPermissionSemanticsSha256: String?,
    /** Optional fine-grained declared permission field baselines keyed by `permission:name#field`. */
    val expectedDeclaredPermissionFieldValues: Map<String, String>,
    /** Optional manifest component fingerprints keyed by `type:componentName`. */
    val expectedComponentSignatureSha256: Map<String, String>,
    /** Optional component access semantics fingerprints keyed by `type:componentName`. */
    val expectedComponentAccessSemanticsSha256: Map<String, String>,
    /** Optional component operational semantics fingerprints keyed by `type:componentName`. */
    val expectedComponentOperationalSemanticsSha256: Map<String, String>,
    /** Optional fine-grained component field baselines keyed by `type:name#field`. */
    val expectedComponentFieldValues: Map<String, String>,
    /** Optional provider uriPermissionPatterns fingerprints keyed by `provider:name`. */
    val expectedProviderUriPermissionPatternsSha256: Map<String, String>,
    /** Optional provider pathPermissions fingerprints keyed by `provider:name`. */
    val expectedProviderPathPermissionsSha256: Map<String, String>,
    /** Optional provider authority-set fingerprints keyed by `provider:name`. */
    val expectedProviderAuthoritySetSha256: Map<String, String>,
    /** Optional provider combined semantics fingerprints keyed by `provider:name`. */
    val expectedProviderSemanticsSha256: Map<String, String>,
    /** Optional provider access semantics fingerprints keyed by `provider:name`. */
    val expectedProviderAccessSemanticsSha256: Map<String, String>,
    /** Optional provider operational semantics fingerprints keyed by `provider:name`. */
    val expectedProviderOperationalSemanticsSha256: Map<String, String>,
    /** Optional raw manifest intent-filter fingerprints keyed by `type:name`. */
    val expectedIntentFilterSha256: Map<String, String>,
    /** Optional raw manifest intent-filter action-set fingerprints keyed by `type:name`. */
    val expectedIntentFilterActionSha256: Map<String, String>,
    /** Optional raw manifest intent-filter category-set fingerprints keyed by `type:name`. */
    val expectedIntentFilterCategorySha256: Map<String, String>,
    /** Optional raw manifest intent-filter data-set fingerprints keyed by `type:name`. */
    val expectedIntentFilterDataSha256: Map<String, String>,
    /** Optional raw manifest intent-filter data scheme-set fingerprints keyed by `type:name`. */
    val expectedIntentFilterDataSchemeSha256: Map<String, String>,
    /** Optional raw manifest intent-filter data authority-set fingerprints keyed by `type:name`. */
    val expectedIntentFilterDataAuthoritySha256: Map<String, String>,
    /** Optional raw manifest intent-filter data path-set fingerprints keyed by `type:name`. */
    val expectedIntentFilterDataPathSha256: Map<String, String>,
    /** Optional raw manifest intent-filter data mimeType-set fingerprints keyed by `type:name`. */
    val expectedIntentFilterDataMimeTypeSha256: Map<String, String>,
    /** Optional normalized manifest intent-filter semantics fingerprints keyed by `type:name`. */
    val expectedIntentFilterSemanticsSha256: Map<String, String>,
    /** Optional raw manifest grant-uri-permission fingerprints keyed by `provider:name`. */
    val expectedGrantUriPermissionSha256: Map<String, String>,
    /** Optional normalized manifest grant-uri-permission semantics fingerprints keyed by `provider:name`. */
    val expectedGrantUriPermissionSemanticsSha256: Map<String, String>,
    /** Optional raw manifest uses-feature fingerprint. */
    val expectedUsesFeatureSha256: String?,
    /** Optional raw manifest uses-feature name fingerprint. */
    val expectedUsesFeatureNameSha256: String?,
    /** Optional raw manifest uses-feature required flag fingerprint. */
    val expectedUsesFeatureRequiredSha256: String?,
    /** Optional raw manifest uses-feature glEsVersion fingerprint. */
    val expectedUsesFeatureGlEsVersionSha256: String?,
    /** Optional raw manifest uses-feature field values keyed by `uses-feature:<name-or-glEsVersion>#field`. */
    val expectedUsesFeatureFieldValues: Map<String, String>,
    /** Optional raw manifest uses-sdk fingerprint. */
    val expectedUsesSdkSha256: String?,
    /** Optional raw manifest uses-sdk minSdkVersion fingerprint. */
    val expectedUsesSdkMinSha256: String?,
    /** Optional raw manifest uses-sdk targetSdkVersion fingerprint. */
    val expectedUsesSdkTargetSha256: String?,
    /** Optional raw manifest uses-sdk maxSdkVersion fingerprint. */
    val expectedUsesSdkMaxSha256: String?,
    /** Optional raw manifest uses-sdk field values keyed by `uses-sdk#field`. */
    val expectedUsesSdkFieldValues: Map<String, String>,
    /** Optional raw manifest supports-screens fingerprint. */
    val expectedSupportsScreensSha256: String?,
    /** Optional raw manifest supports-screens smallScreens fingerprint. */
    val expectedSupportsScreensSmallScreensSha256: String?,
    /** Optional raw manifest supports-screens normalScreens fingerprint. */
    val expectedSupportsScreensNormalScreensSha256: String?,
    /** Optional raw manifest supports-screens largeScreens fingerprint. */
    val expectedSupportsScreensLargeScreensSha256: String?,
    /** Optional raw manifest supports-screens xlargeScreens fingerprint. */
    val expectedSupportsScreensXlargeScreensSha256: String?,
    /** Optional raw manifest supports-screens resizeable fingerprint. */
    val expectedSupportsScreensResizeableSha256: String?,
    /** Optional raw manifest supports-screens anyDensity fingerprint. */
    val expectedSupportsScreensAnyDensitySha256: String?,
    /** Optional raw manifest supports-screens requiresSmallestWidthDp fingerprint. */
    val expectedSupportsScreensRequiresSmallestWidthDpSha256: String?,
    /** Optional raw manifest supports-screens compatibleWidthLimitDp fingerprint. */
    val expectedSupportsScreensCompatibleWidthLimitDpSha256: String?,
    /** Optional raw manifest supports-screens largestWidthLimitDp fingerprint. */
    val expectedSupportsScreensLargestWidthLimitDpSha256: String?,
    /** Optional raw manifest compatible-screens fingerprint. */
    val expectedCompatibleScreensSha256: String?,
    /** Optional raw manifest compatible-screens screenSize fingerprint. */
    val expectedCompatibleScreensScreenSizeSha256: String?,
    /** Optional raw manifest compatible-screens screenDensity fingerprint. */
    val expectedCompatibleScreensScreenDensitySha256: String?,
    /** Optional raw manifest uses-library / uses-native-library fingerprint. */
    val expectedUsesLibrarySha256: String?,
    /** Optional raw manifest uses-library / uses-native-library name fingerprint. */
    val expectedUsesLibraryNameSha256: String?,
    /** Optional raw manifest uses-library / uses-native-library required fingerprint. */
    val expectedUsesLibraryRequiredSha256: String?,
    /** Optional raw manifest uses-library field values keyed by `uses-library:<name>#field`. */
    val expectedUsesLibraryFieldValues: Map<String, String>,
    /** Optional raw manifest uses-library fingerprint. */
    val expectedUsesLibraryOnlySha256: String?,
    /** Optional raw manifest uses-library name fingerprint. */
    val expectedUsesLibraryOnlyNameSha256: String?,
    /** Optional raw manifest uses-library required fingerprint. */
    val expectedUsesLibraryOnlyRequiredSha256: String?,
    /** Optional raw manifest uses-native-library fingerprint. */
    val expectedUsesNativeLibrarySha256: String?,
    /** Optional raw manifest uses-native-library name fingerprint. */
    val expectedUsesNativeLibraryNameSha256: String?,
    /** Optional raw manifest uses-native-library required fingerprint. */
    val expectedUsesNativeLibraryRequiredSha256: String?,
    /** Optional raw manifest uses-native-library field values keyed by `uses-native-library:<name>#field`. */
    val expectedUsesNativeLibraryFieldValues: Map<String, String>,
    /** Optional raw manifest queries fingerprint. */
    val expectedQueriesSha256: String?,
    /** Optional raw manifest queries package fingerprint. */
    val expectedQueriesPackageSha256: String?,
    /** Optional raw manifest queries package-name fingerprint. */
    val expectedQueriesPackageNameSha256: String?,
    /** Optional normalized manifest queries package semantics fingerprint. */
    val expectedQueriesPackageSemanticsSha256: String?,
    /** Optional raw manifest queries provider fingerprint. */
    val expectedQueriesProviderSha256: String?,
    /** Optional raw manifest queries provider-authorities fingerprint. */
    val expectedQueriesProviderAuthoritySha256: String?,
    /** Optional normalized manifest queries provider semantics fingerprint. */
    val expectedQueriesProviderSemanticsSha256: String?,
    /** Optional raw manifest queries intent fingerprint. */
    val expectedQueriesIntentSha256: String?,
    /** Optional raw manifest queries intent action fingerprint. */
    val expectedQueriesIntentActionSha256: String?,
    /** Optional raw manifest queries intent category fingerprint. */
    val expectedQueriesIntentCategorySha256: String?,
    /** Optional raw manifest queries intent data fingerprint. */
    val expectedQueriesIntentDataSha256: String?,
    /** Optional raw manifest queries intent data scheme fingerprint. */
    val expectedQueriesIntentDataSchemeSha256: String?,
    /** Optional raw manifest queries intent data authority fingerprint. */
    val expectedQueriesIntentDataAuthoritySha256: String?,
    /** Optional raw manifest queries intent data path fingerprint. */
    val expectedQueriesIntentDataPathSha256: String?,
    /** Optional raw manifest queries intent data mimeType fingerprint. */
    val expectedQueriesIntentDataMimeTypeSha256: String?,
    /** Optional normalized manifest queries intent semantics fingerprint. */
    val expectedQueriesIntentSemanticsSha256: String?,
    /** Optional raw manifest application combined semantics fingerprint. */
    val expectedApplicationSemanticsSha256: String?,
    /** Optional raw manifest application security semantics fingerprint. */
    val expectedApplicationSecuritySemanticsSha256: String?,
    /** Optional raw manifest application runtime semantics fingerprint. */
    val expectedApplicationRuntimeSemanticsSha256: String?,
    /** Optional raw manifest application field values keyed by `application#field`. */
    val expectedApplicationFieldValues: Map<String, String>,
    /** Optional manifest meta-data runtime type baselines keyed by meta-data name. */
    val expectedMetaDataType: Map<String, String>,
    /** Optional manifest meta-data runtime value hashes keyed by meta-data name. */
    val expectedMetaDataValueSha256: Map<String, String>,
    /** Optional raw manifest meta-data entry hashes keyed by meta-data name. */
    val expectedManifestMetaDataEntrySha256: Map<String, String>,
    /** Optional manifest meta-data semantics hashes keyed by meta-data name. */
    val expectedManifestMetaDataSemanticsSha256: Map<String, String>,
    /** Optional manifest meta-data baselines keyed by meta-data name. */
    val expectedMetaData: Map<String, String>,
) {

    internal fun toNativeHandle(): Long {
        var flags = 0L
        if (injectionDetectionEnabled) flags = flags or FLAG_INJECTION
        if (environmentDetectionEnabled) flags = flags or FLAG_ENVIRONMENT
        if (verboseNativeLogging) flags = flags or FLAG_VERBOSE_LOG
        return flags
    }

    class Builder {
        private var injection = true
        private var environment = true
        private var reportingEndpoint: String? = null
        private var apiKey: String? = null
        private var tenantId: String? = null
        private var appId: String = "default"
        private var region: LeonaRegion = LeonaRegion.CN_BJ
        private var transportEnabled = true
        private var cloudConfigEnabled = true
        private var cloudConfigEndpoint: String? = null
        private var syncInit = false
        private var verifyServerCert = false
        private var disableCollectionWindowMs = -1L
        private val disabledSignals = linkedSetOf<String>()
        private var channel: String? = null
        private var extraInfo: String? = null
        private var firstPartyMode = false
        private var verboseNativeLogging = false
        private var preferStrongBoxBackedKey = true
        private val certificatePins = linkedMapOf<String, LinkedHashSet<String>>()
        private var attestationProvider: AttestationProvider? = null
        private var expectedPackageName: String? = null
        private val allowedInstallerPackages = linkedSetOf<String>()
        private val allowedSigningCertSha256 = linkedSetOf<String>()
        private var expectedSigningCertificateLineageSha256: String? = null
        private var expectedApkSigningBlockSha256: String? = null
        private val expectedApkSigningBlockIdSha256 = linkedMapOf<String, String>()
        private var expectedApkSha256: String? = null
        private val expectedNativeLibSha256 = linkedMapOf<String, String>()
        private var expectedManifestEntrySha256: String? = null
        private var expectedResourcesArscSha256: String? = null
        private var expectedResourceInventorySha256: String? = null
        private val expectedResourceEntrySha256 = linkedMapOf<String, String>()
        private val expectedDexSha256 = linkedMapOf<String, String>()
        private val expectedDexSectionSha256 = linkedMapOf<String, String>()
        private val expectedDexMethodSha256 = linkedMapOf<String, String>()
        private val expectedSplitApkSha256 = linkedMapOf<String, String>()
        private var expectedSplitInventorySha256: String? = null
        private var expectedDynamicFeatureSplitSha256: String? = null
        private var expectedDynamicFeatureSplitNameSha256: String? = null
        private var expectedConfigSplitAxisSha256: String? = null
        private var expectedConfigSplitNameSha256: String? = null
        private var expectedConfigSplitAbiSha256: String? = null
        private var expectedConfigSplitLocaleSha256: String? = null
        private var expectedConfigSplitDensitySha256: String? = null
        private val expectedElfSectionSha256 = linkedMapOf<String, String>()
        private val expectedElfExportSymbolSha256 = linkedMapOf<String, String>()
        private val expectedElfExportGraphSha256 = linkedMapOf<String, String>()
        private var expectedRequestedPermissionsSha256: String? = null
        private var expectedRequestedPermissionSemanticsSha256: String? = null
        private var expectedDeclaredPermissionSemanticsSha256: String? = null
        private val expectedDeclaredPermissionFieldValues = linkedMapOf<String, String>()
        private val expectedComponentSignatureSha256 = linkedMapOf<String, String>()
        private val expectedComponentAccessSemanticsSha256 = linkedMapOf<String, String>()
        private val expectedComponentOperationalSemanticsSha256 = linkedMapOf<String, String>()
        private val expectedComponentFieldValues = linkedMapOf<String, String>()
        private val expectedProviderUriPermissionPatternsSha256 = linkedMapOf<String, String>()
        private val expectedProviderPathPermissionsSha256 = linkedMapOf<String, String>()
        private val expectedProviderAuthoritySetSha256 = linkedMapOf<String, String>()
        private val expectedProviderSemanticsSha256 = linkedMapOf<String, String>()
        private val expectedProviderAccessSemanticsSha256 = linkedMapOf<String, String>()
        private val expectedProviderOperationalSemanticsSha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterSha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterActionSha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterCategorySha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterDataSha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterDataSchemeSha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterDataAuthoritySha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterDataPathSha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterDataMimeTypeSha256 = linkedMapOf<String, String>()
        private val expectedIntentFilterSemanticsSha256 = linkedMapOf<String, String>()
        private val expectedGrantUriPermissionSha256 = linkedMapOf<String, String>()
        private val expectedGrantUriPermissionSemanticsSha256 = linkedMapOf<String, String>()
        private var expectedUsesFeatureSha256: String? = null
        private var expectedUsesFeatureNameSha256: String? = null
        private var expectedUsesFeatureRequiredSha256: String? = null
        private var expectedUsesFeatureGlEsVersionSha256: String? = null
        private val expectedUsesFeatureFieldValues = linkedMapOf<String, String>()
        private var expectedUsesSdkSha256: String? = null
        private var expectedUsesSdkMinSha256: String? = null
        private var expectedUsesSdkTargetSha256: String? = null
        private var expectedUsesSdkMaxSha256: String? = null
        private val expectedUsesSdkFieldValues = linkedMapOf<String, String>()
        private var expectedSupportsScreensSha256: String? = null
        private var expectedSupportsScreensSmallScreensSha256: String? = null
        private var expectedSupportsScreensNormalScreensSha256: String? = null
        private var expectedSupportsScreensLargeScreensSha256: String? = null
        private var expectedSupportsScreensXlargeScreensSha256: String? = null
        private var expectedSupportsScreensResizeableSha256: String? = null
        private var expectedSupportsScreensAnyDensitySha256: String? = null
        private var expectedSupportsScreensRequiresSmallestWidthDpSha256: String? = null
        private var expectedSupportsScreensCompatibleWidthLimitDpSha256: String? = null
        private var expectedSupportsScreensLargestWidthLimitDpSha256: String? = null
        private var expectedCompatibleScreensSha256: String? = null
        private var expectedCompatibleScreensScreenSizeSha256: String? = null
        private var expectedCompatibleScreensScreenDensitySha256: String? = null
        private var expectedUsesLibrarySha256: String? = null
        private var expectedUsesLibraryNameSha256: String? = null
        private var expectedUsesLibraryRequiredSha256: String? = null
        private val expectedUsesLibraryFieldValues = linkedMapOf<String, String>()
        private var expectedUsesLibraryOnlySha256: String? = null
        private var expectedUsesLibraryOnlyNameSha256: String? = null
        private var expectedUsesLibraryOnlyRequiredSha256: String? = null
        private var expectedUsesNativeLibrarySha256: String? = null
        private var expectedUsesNativeLibraryNameSha256: String? = null
        private var expectedUsesNativeLibraryRequiredSha256: String? = null
        private val expectedUsesNativeLibraryFieldValues = linkedMapOf<String, String>()
        private var expectedQueriesSha256: String? = null
        private var expectedQueriesPackageSha256: String? = null
        private var expectedQueriesPackageNameSha256: String? = null
        private var expectedQueriesPackageSemanticsSha256: String? = null
        private var expectedQueriesProviderSha256: String? = null
        private var expectedQueriesProviderAuthoritySha256: String? = null
        private var expectedQueriesProviderSemanticsSha256: String? = null
        private var expectedQueriesIntentSha256: String? = null
        private var expectedQueriesIntentActionSha256: String? = null
        private var expectedQueriesIntentCategorySha256: String? = null
        private var expectedQueriesIntentDataSha256: String? = null
        private var expectedQueriesIntentDataSchemeSha256: String? = null
        private var expectedQueriesIntentDataAuthoritySha256: String? = null
        private var expectedQueriesIntentDataPathSha256: String? = null
        private var expectedQueriesIntentDataMimeTypeSha256: String? = null
        private var expectedQueriesIntentSemanticsSha256: String? = null
        private var expectedApplicationSemanticsSha256: String? = null
        private var expectedApplicationSecuritySemanticsSha256: String? = null
        private var expectedApplicationRuntimeSemanticsSha256: String? = null
        private val expectedApplicationFieldValues = linkedMapOf<String, String>()
        private val expectedMetaDataType = linkedMapOf<String, String>()
        private val expectedMetaDataValueSha256 = linkedMapOf<String, String>()
        private val expectedManifestMetaDataEntrySha256 = linkedMapOf<String, String>()
        private val expectedManifestMetaDataSemanticsSha256 = linkedMapOf<String, String>()
        private val expectedMetaData = linkedMapOf<String, String>()

        fun enableInjectionDetection(enabled: Boolean) = apply { injection = enabled }
        fun enableEnvironmentDetection(enabled: Boolean) = apply { environment = enabled }
        fun reportingEndpoint(url: String?) = apply { reportingEndpoint = url }
        fun apiKey(key: String?) = apply { apiKey = key }
        fun tenantId(value: String?) = apply { tenantId = value?.trim()?.ifEmpty { null } }
        fun appId(value: String?) = apply { appId = value?.trim()?.ifEmpty { "default" } ?: "default" }
        fun region(value: LeonaRegion) = apply { region = value }
        fun transportEnabled(enabled: Boolean) = apply { transportEnabled = enabled }
        fun enableCloudConfig(enabled: Boolean) = apply { cloudConfigEnabled = enabled }
        fun cloudConfigEndpoint(url: String?) = apply { cloudConfigEndpoint = url?.trim()?.ifEmpty { null } }
        fun syncInit(enabled: Boolean) = apply { syncInit = enabled }
        fun verifyServerCert(enabled: Boolean) = apply { verifyServerCert = enabled }
        fun disableCollectionWindowMs(value: Long) = apply { disableCollectionWindowMs = value }
        fun disabledSignal(name: String) = apply { normalizeToken(name)?.let(disabledSignals::add) }
        fun disabledSignals(values: Iterable<String>) = apply { disabledSignals += values.mapNotNull(::normalizeToken) }
        fun disabledSignals(vararg values: String) = apply { disabledSignals(values.asIterable()) }
        fun channel(value: String?) = apply { channel = value?.trim()?.ifEmpty { null } }
        fun extraInfo(value: String?) = apply { extraInfo = value?.trim()?.take(1024)?.ifEmpty { null } }
        fun firstPartyMode(enabled: Boolean) = apply { firstPartyMode = enabled }
        fun verboseNativeLogging(enabled: Boolean) = apply { verboseNativeLogging = enabled }
        fun preferStrongBoxBackedKey(enabled: Boolean) = apply { preferStrongBoxBackedKey = enabled }
        fun attestationProvider(provider: AttestationProvider?) = apply { attestationProvider = provider }
        fun certificatePin(host: String, vararg pins: String) = apply {
            val normalizedHost = normalizeToken(host) ?: return@apply
            val bucket = certificatePins.getOrPut(normalizedHost) { linkedSetOf() }
            pins.mapNotNull(::normalizePin).forEach(bucket::add)
        }
        fun certificatePins(host: String, pins: Iterable<String>) = apply {
            certificatePin(host, *pins.toList().toTypedArray())
        }
        fun expectedPackageName(packageName: String?) = apply {
            expectedPackageName = packageName?.trim()?.ifEmpty { null }
        }
        fun allowedInstallerPackages(vararg packageNames: String) = apply {
            allowedInstallerPackages += packageNames.mapNotNull { normalizeToken(it) }
        }
        fun allowedInstallerPackages(packageNames: Iterable<String>) = apply {
            allowedInstallerPackages += packageNames.mapNotNull { normalizeToken(it) }
        }
        fun allowedSigningCertSha256(vararg digests: String) = apply {
            allowedSigningCertSha256 += digests.mapNotNull { normalizeDigest(it) }
        }
        fun allowedSigningCertSha256(digests: Iterable<String>) = apply {
            allowedSigningCertSha256 += digests.mapNotNull { normalizeDigest(it) }
        }
        fun expectedSigningCertificateLineageSha256(digest: String?) = apply {
            expectedSigningCertificateLineageSha256 = normalizeDigest(digest)
        }
        fun expectedApkSigningBlockSha256(digest: String?) = apply {
            expectedApkSigningBlockSha256 = normalizeDigest(digest)
        }
        fun expectedApkSigningBlockIdSha256(signingBlockId: String, digest: String?) = apply {
            putNormalized(expectedApkSigningBlockIdSha256, signingBlockId, digest)
        }
        fun expectedApkSigningBlockIdSha256(values: Map<String, String>) = apply {
            values.forEach { (signingBlockId, digest) ->
                expectedApkSigningBlockIdSha256(signingBlockId, digest)
            }
        }
        fun expectedApkSha256(digest: String?) = apply {
            expectedApkSha256 = normalizeDigest(digest)
        }
        fun expectedNativeLibrarySha256(fileName: String, digest: String?) = apply {
            val normalizedName = fileName.trim()
            val normalizedDigest = normalizeDigest(digest)
            if (normalizedName.isNotEmpty() && normalizedDigest != null) {
                expectedNativeLibSha256[normalizedName] = normalizedDigest
            }
        }
        fun expectedNativeLibrarySha256(values: Map<String, String>) = apply {
            values.forEach { (fileName, digest) -> expectedNativeLibrarySha256(fileName, digest) }
        }
        fun expectedManifestEntrySha256(digest: String?) = apply {
            expectedManifestEntrySha256 = normalizeDigest(digest)
        }
        fun expectedResourcesArscSha256(digest: String?) = apply {
            expectedResourcesArscSha256 = normalizeDigest(digest)
        }
        fun expectedResourceInventorySha256(digest: String?) = apply {
            expectedResourceInventorySha256 = normalizeDigest(digest)
        }
        fun expectedResourceEntrySha256(entryName: String, digest: String?) = apply {
            putNormalized(expectedResourceEntrySha256, entryName, digest)
        }
        fun expectedResourceEntrySha256(values: Map<String, String>) = apply {
            values.forEach { (entryName, digest) -> expectedResourceEntrySha256(entryName, digest) }
        }
        fun expectedDexSha256(entryName: String, digest: String?) = apply {
            putNormalized(expectedDexSha256, entryName, digest)
        }
        fun expectedDexSha256(values: Map<String, String>) = apply {
            values.forEach { (entryName, digest) -> expectedDexSha256(entryName, digest) }
        }
        fun expectedDexSectionSha256(entryAndSection: String, digest: String?) = apply {
            putNormalized(expectedDexSectionSha256, entryAndSection, digest)
        }
        fun expectedDexSectionSha256(values: Map<String, String>) = apply {
            values.forEach { (entryAndSection, digest) -> expectedDexSectionSha256(entryAndSection, digest) }
        }
        fun expectedDexMethodSha256(entryAndMethod: String, digest: String?) = apply {
            putNormalized(expectedDexMethodSha256, entryAndMethod, digest)
        }
        fun expectedDexMethodSha256(values: Map<String, String>) = apply {
            values.forEach { (entryAndMethod, digest) -> expectedDexMethodSha256(entryAndMethod, digest) }
        }
        fun expectedSplitApkSha256(fileName: String, digest: String?) = apply {
            putNormalized(expectedSplitApkSha256, fileName, digest)
        }
        fun expectedSplitApkSha256(values: Map<String, String>) = apply {
            values.forEach { (fileName, digest) -> expectedSplitApkSha256(fileName, digest) }
        }
        fun expectedSplitInventorySha256(digest: String?) = apply {
            expectedSplitInventorySha256 = normalizeDigest(digest)
        }
        fun expectedDynamicFeatureSplitSha256(digest: String?) = apply {
            expectedDynamicFeatureSplitSha256 = normalizeDigest(digest)
        }
        fun expectedDynamicFeatureSplitNameSha256(digest: String?) = apply {
            expectedDynamicFeatureSplitNameSha256 = normalizeDigest(digest)
        }
        fun expectedConfigSplitAxisSha256(digest: String?) = apply {
            expectedConfigSplitAxisSha256 = normalizeDigest(digest)
        }
        fun expectedConfigSplitNameSha256(digest: String?) = apply {
            expectedConfigSplitNameSha256 = normalizeDigest(digest)
        }
        fun expectedConfigSplitAbiSha256(digest: String?) = apply {
            expectedConfigSplitAbiSha256 = normalizeDigest(digest)
        }
        fun expectedConfigSplitLocaleSha256(digest: String?) = apply {
            expectedConfigSplitLocaleSha256 = normalizeDigest(digest)
        }
        fun expectedConfigSplitDensitySha256(digest: String?) = apply {
            expectedConfigSplitDensitySha256 = normalizeDigest(digest)
        }
        fun expectedElfSectionSha256(libAndSection: String, digest: String?) = apply {
            putNormalized(expectedElfSectionSha256, libAndSection, digest)
        }
        fun expectedElfSectionSha256(values: Map<String, String>) = apply {
            values.forEach { (libAndSection, digest) -> expectedElfSectionSha256(libAndSection, digest) }
        }
        fun expectedElfExportSymbolSha256(libAndSymbol: String, digest: String?) = apply {
            putNormalized(expectedElfExportSymbolSha256, libAndSymbol, digest)
        }
        fun expectedElfExportSymbolSha256(values: Map<String, String>) = apply {
            values.forEach { (libAndSymbol, digest) -> expectedElfExportSymbolSha256(libAndSymbol, digest) }
        }
        fun expectedElfExportGraphSha256(libName: String, digest: String?) = apply {
            putNormalized(expectedElfExportGraphSha256, libName, digest)
        }
        fun expectedElfExportGraphSha256(values: Map<String, String>) = apply {
            values.forEach { (libName, digest) -> expectedElfExportGraphSha256(libName, digest) }
        }
        fun expectedRequestedPermissionsSha256(digest: String?) = apply {
            expectedRequestedPermissionsSha256 = normalizeDigest(digest)
        }
        fun expectedRequestedPermissionSemanticsSha256(digest: String?) = apply {
            expectedRequestedPermissionSemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedDeclaredPermissionSemanticsSha256(digest: String?) = apply {
            expectedDeclaredPermissionSemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedDeclaredPermissionFieldValue(permissionFieldKey: String, value: String?) = apply {
            putRawValue(expectedDeclaredPermissionFieldValues, permissionFieldKey, value)
        }
        fun expectedDeclaredPermissionFieldValues(values: Map<String, String>) = apply {
            values.forEach { (permissionFieldKey, value) ->
                expectedDeclaredPermissionFieldValue(permissionFieldKey, value)
            }
        }
        fun expectedComponentSignatureSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedComponentSignatureSha256, componentKey, digest)
        }
        fun expectedComponentSignatureSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedComponentSignatureSha256(componentKey, digest) }
        }
        fun expectedComponentAccessSemanticsSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedComponentAccessSemanticsSha256, componentKey, digest)
        }
        fun expectedComponentAccessSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) ->
                expectedComponentAccessSemanticsSha256(componentKey, digest)
            }
        }
        fun expectedComponentOperationalSemanticsSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedComponentOperationalSemanticsSha256, componentKey, digest)
        }
        fun expectedComponentOperationalSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) ->
                expectedComponentOperationalSemanticsSha256(componentKey, digest)
            }
        }
        fun expectedComponentFieldValue(componentFieldKey: String, value: String?) = apply {
            putRawValue(expectedComponentFieldValues, componentFieldKey, value)
        }
        fun expectedComponentFieldValues(values: Map<String, String>) = apply {
            values.forEach { (componentFieldKey, value) -> expectedComponentFieldValue(componentFieldKey, value) }
        }
        fun expectedProviderUriPermissionPatternsSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedProviderUriPermissionPatternsSha256, providerKey, digest)
        }
        fun expectedProviderUriPermissionPatternsSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) ->
                expectedProviderUriPermissionPatternsSha256(providerKey, digest)
            }
        }
        fun expectedProviderPathPermissionsSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedProviderPathPermissionsSha256, providerKey, digest)
        }
        fun expectedProviderPathPermissionsSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) -> expectedProviderPathPermissionsSha256(providerKey, digest) }
        }
        fun expectedProviderAuthoritySetSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedProviderAuthoritySetSha256, providerKey, digest)
        }
        fun expectedProviderAuthoritySetSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) -> expectedProviderAuthoritySetSha256(providerKey, digest) }
        }
        fun expectedProviderSemanticsSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedProviderSemanticsSha256, providerKey, digest)
        }
        fun expectedProviderSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) -> expectedProviderSemanticsSha256(providerKey, digest) }
        }
        fun expectedProviderAccessSemanticsSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedProviderAccessSemanticsSha256, providerKey, digest)
        }
        fun expectedProviderAccessSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) ->
                expectedProviderAccessSemanticsSha256(providerKey, digest)
            }
        }
        fun expectedProviderOperationalSemanticsSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedProviderOperationalSemanticsSha256, providerKey, digest)
        }
        fun expectedProviderOperationalSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) ->
                expectedProviderOperationalSemanticsSha256(providerKey, digest)
            }
        }
        fun expectedIntentFilterSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterSha256, componentKey, digest)
        }
        fun expectedIntentFilterSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterSha256(componentKey, digest) }
        }
        fun expectedIntentFilterActionSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterActionSha256, componentKey, digest)
        }
        fun expectedIntentFilterActionSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterActionSha256(componentKey, digest) }
        }
        fun expectedIntentFilterCategorySha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterCategorySha256, componentKey, digest)
        }
        fun expectedIntentFilterCategorySha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterCategorySha256(componentKey, digest) }
        }
        fun expectedIntentFilterDataSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterDataSha256, componentKey, digest)
        }
        fun expectedIntentFilterDataSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterDataSha256(componentKey, digest) }
        }
        fun expectedIntentFilterDataSchemeSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterDataSchemeSha256, componentKey, digest)
        }
        fun expectedIntentFilterDataSchemeSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterDataSchemeSha256(componentKey, digest) }
        }
        fun expectedIntentFilterDataAuthoritySha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterDataAuthoritySha256, componentKey, digest)
        }
        fun expectedIntentFilterDataAuthoritySha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterDataAuthoritySha256(componentKey, digest) }
        }
        fun expectedIntentFilterDataPathSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterDataPathSha256, componentKey, digest)
        }
        fun expectedIntentFilterDataPathSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterDataPathSha256(componentKey, digest) }
        }
        fun expectedIntentFilterDataMimeTypeSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterDataMimeTypeSha256, componentKey, digest)
        }
        fun expectedIntentFilterDataMimeTypeSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterDataMimeTypeSha256(componentKey, digest) }
        }
        fun expectedIntentFilterSemanticsSha256(componentKey: String, digest: String?) = apply {
            putNormalized(expectedIntentFilterSemanticsSha256, componentKey, digest)
        }
        fun expectedIntentFilterSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (componentKey, digest) -> expectedIntentFilterSemanticsSha256(componentKey, digest) }
        }
        fun expectedGrantUriPermissionSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedGrantUriPermissionSha256, providerKey, digest)
        }
        fun expectedGrantUriPermissionSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) -> expectedGrantUriPermissionSha256(providerKey, digest) }
        }
        fun expectedGrantUriPermissionSemanticsSha256(providerKey: String, digest: String?) = apply {
            putNormalized(expectedGrantUriPermissionSemanticsSha256, providerKey, digest)
        }
        fun expectedGrantUriPermissionSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (providerKey, digest) ->
                expectedGrantUriPermissionSemanticsSha256(providerKey, digest)
            }
        }
        fun expectedUsesFeatureSha256(digest: String?) = apply {
            expectedUsesFeatureSha256 = normalizeDigest(digest)
        }
        fun expectedUsesFeatureNameSha256(digest: String?) = apply {
            expectedUsesFeatureNameSha256 = normalizeDigest(digest)
        }
        fun expectedUsesFeatureRequiredSha256(digest: String?) = apply {
            expectedUsesFeatureRequiredSha256 = normalizeDigest(digest)
        }
        fun expectedUsesFeatureGlEsVersionSha256(digest: String?) = apply {
            expectedUsesFeatureGlEsVersionSha256 = normalizeDigest(digest)
        }
        fun expectedUsesFeatureFieldValue(featureFieldKey: String, value: String?) = apply {
            putRawValue(expectedUsesFeatureFieldValues, featureFieldKey, value)
        }
        fun expectedUsesFeatureFieldValues(values: Map<String, String>) = apply {
            values.forEach { (featureFieldKey, value) ->
                expectedUsesFeatureFieldValue(featureFieldKey, value)
            }
        }
        fun expectedUsesSdkSha256(digest: String?) = apply {
            expectedUsesSdkSha256 = normalizeDigest(digest)
        }
        fun expectedUsesSdkMinSha256(digest: String?) = apply {
            expectedUsesSdkMinSha256 = normalizeDigest(digest)
        }
        fun expectedUsesSdkTargetSha256(digest: String?) = apply {
            expectedUsesSdkTargetSha256 = normalizeDigest(digest)
        }
        fun expectedUsesSdkMaxSha256(digest: String?) = apply {
            expectedUsesSdkMaxSha256 = normalizeDigest(digest)
        }
        fun expectedUsesSdkFieldValue(usesSdkFieldKey: String, value: String?) = apply {
            putRawValue(expectedUsesSdkFieldValues, usesSdkFieldKey, value)
        }
        fun expectedUsesSdkFieldValues(values: Map<String, String>) = apply {
            values.forEach { (usesSdkFieldKey, value) ->
                expectedUsesSdkFieldValue(usesSdkFieldKey, value)
            }
        }
        fun expectedSupportsScreensSha256(digest: String?) = apply {
            expectedSupportsScreensSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensSmallScreensSha256(digest: String?) = apply {
            expectedSupportsScreensSmallScreensSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensNormalScreensSha256(digest: String?) = apply {
            expectedSupportsScreensNormalScreensSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensLargeScreensSha256(digest: String?) = apply {
            expectedSupportsScreensLargeScreensSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensXlargeScreensSha256(digest: String?) = apply {
            expectedSupportsScreensXlargeScreensSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensResizeableSha256(digest: String?) = apply {
            expectedSupportsScreensResizeableSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensAnyDensitySha256(digest: String?) = apply {
            expectedSupportsScreensAnyDensitySha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensRequiresSmallestWidthDpSha256(digest: String?) = apply {
            expectedSupportsScreensRequiresSmallestWidthDpSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensCompatibleWidthLimitDpSha256(digest: String?) = apply {
            expectedSupportsScreensCompatibleWidthLimitDpSha256 = normalizeDigest(digest)
        }
        fun expectedSupportsScreensLargestWidthLimitDpSha256(digest: String?) = apply {
            expectedSupportsScreensLargestWidthLimitDpSha256 = normalizeDigest(digest)
        }
        fun expectedCompatibleScreensSha256(digest: String?) = apply {
            expectedCompatibleScreensSha256 = normalizeDigest(digest)
        }
        fun expectedCompatibleScreensScreenSizeSha256(digest: String?) = apply {
            expectedCompatibleScreensScreenSizeSha256 = normalizeDigest(digest)
        }
        fun expectedCompatibleScreensScreenDensitySha256(digest: String?) = apply {
            expectedCompatibleScreensScreenDensitySha256 = normalizeDigest(digest)
        }
        fun expectedUsesLibrarySha256(digest: String?) = apply {
            expectedUsesLibrarySha256 = normalizeDigest(digest)
        }
        fun expectedUsesLibraryNameSha256(digest: String?) = apply {
            expectedUsesLibraryNameSha256 = normalizeDigest(digest)
        }
        fun expectedUsesLibraryRequiredSha256(digest: String?) = apply {
            expectedUsesLibraryRequiredSha256 = normalizeDigest(digest)
        }
        fun expectedUsesLibraryFieldValue(libraryFieldKey: String, value: String?) = apply {
            putRawValue(expectedUsesLibraryFieldValues, libraryFieldKey, value)
        }
        fun expectedUsesLibraryFieldValues(values: Map<String, String>) = apply {
            values.forEach { (libraryFieldKey, value) ->
                expectedUsesLibraryFieldValue(libraryFieldKey, value)
            }
        }
        fun expectedUsesLibraryOnlySha256(digest: String?) = apply {
            expectedUsesLibraryOnlySha256 = normalizeDigest(digest)
        }
        fun expectedUsesLibraryOnlyNameSha256(digest: String?) = apply {
            expectedUsesLibraryOnlyNameSha256 = normalizeDigest(digest)
        }
        fun expectedUsesLibraryOnlyRequiredSha256(digest: String?) = apply {
            expectedUsesLibraryOnlyRequiredSha256 = normalizeDigest(digest)
        }
        fun expectedUsesNativeLibrarySha256(digest: String?) = apply {
            expectedUsesNativeLibrarySha256 = normalizeDigest(digest)
        }
        fun expectedUsesNativeLibraryNameSha256(digest: String?) = apply {
            expectedUsesNativeLibraryNameSha256 = normalizeDigest(digest)
        }
        fun expectedUsesNativeLibraryRequiredSha256(digest: String?) = apply {
            expectedUsesNativeLibraryRequiredSha256 = normalizeDigest(digest)
        }
        fun expectedUsesNativeLibraryFieldValue(nativeLibraryFieldKey: String, value: String?) = apply {
            putRawValue(expectedUsesNativeLibraryFieldValues, nativeLibraryFieldKey, value)
        }
        fun expectedUsesNativeLibraryFieldValues(values: Map<String, String>) = apply {
            values.forEach { (nativeLibraryFieldKey, value) ->
                expectedUsesNativeLibraryFieldValue(nativeLibraryFieldKey, value)
            }
        }
        fun expectedQueriesSha256(digest: String?) = apply {
            expectedQueriesSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesPackageSha256(digest: String?) = apply {
            expectedQueriesPackageSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesPackageNameSha256(digest: String?) = apply {
            expectedQueriesPackageNameSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesPackageSemanticsSha256(digest: String?) = apply {
            expectedQueriesPackageSemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesProviderSha256(digest: String?) = apply {
            expectedQueriesProviderSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesProviderAuthoritySha256(digest: String?) = apply {
            expectedQueriesProviderAuthoritySha256 = normalizeDigest(digest)
        }
        fun expectedQueriesProviderSemanticsSha256(digest: String?) = apply {
            expectedQueriesProviderSemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentSha256(digest: String?) = apply {
            expectedQueriesIntentSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentActionSha256(digest: String?) = apply {
            expectedQueriesIntentActionSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentCategorySha256(digest: String?) = apply {
            expectedQueriesIntentCategorySha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentDataSha256(digest: String?) = apply {
            expectedQueriesIntentDataSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentDataSchemeSha256(digest: String?) = apply {
            expectedQueriesIntentDataSchemeSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentDataAuthoritySha256(digest: String?) = apply {
            expectedQueriesIntentDataAuthoritySha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentDataPathSha256(digest: String?) = apply {
            expectedQueriesIntentDataPathSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentDataMimeTypeSha256(digest: String?) = apply {
            expectedQueriesIntentDataMimeTypeSha256 = normalizeDigest(digest)
        }
        fun expectedQueriesIntentSemanticsSha256(digest: String?) = apply {
            expectedQueriesIntentSemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedApplicationSemanticsSha256(digest: String?) = apply {
            expectedApplicationSemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedApplicationSecuritySemanticsSha256(digest: String?) = apply {
            expectedApplicationSecuritySemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedApplicationRuntimeSemanticsSha256(digest: String?) = apply {
            expectedApplicationRuntimeSemanticsSha256 = normalizeDigest(digest)
        }
        fun expectedApplicationFieldValue(applicationFieldKey: String, value: String?) = apply {
            putRawValue(expectedApplicationFieldValues, applicationFieldKey, value)
        }
        fun expectedApplicationFieldValues(values: Map<String, String>) = apply {
            values.forEach { (applicationFieldKey, value) ->
                expectedApplicationFieldValue(applicationFieldKey, value)
            }
        }
        fun expectedMetaDataType(name: String, type: String?) = apply {
            val normalizedName = name.trim()
            val normalizedType = type?.trim()?.lowercase()?.ifEmpty { null }
            if (normalizedName.isNotEmpty() && normalizedType != null) {
                expectedMetaDataType[normalizedName] = normalizedType
            }
        }
        fun expectedMetaDataType(values: Map<String, String>) = apply {
            values.forEach { (name, type) -> expectedMetaDataType(name, type) }
        }
        fun expectedMetaDataValueSha256(name: String, digest: String?) = apply {
            val normalizedName = name.trim()
            val normalizedDigest = normalizeDigest(digest)
            if (normalizedName.isNotEmpty() && normalizedDigest != null) {
                expectedMetaDataValueSha256[normalizedName] = normalizedDigest
            }
        }
        fun expectedMetaDataValueSha256(values: Map<String, String>) = apply {
            values.forEach { (name, digest) -> expectedMetaDataValueSha256(name, digest) }
        }
        fun expectedManifestMetaDataEntrySha256(name: String, digest: String?) = apply {
            val normalizedName = name.trim()
            val normalizedDigest = normalizeDigest(digest)
            if (normalizedName.isNotEmpty() && normalizedDigest != null) {
                expectedManifestMetaDataEntrySha256[normalizedName] = normalizedDigest
            }
        }
        fun expectedManifestMetaDataEntrySha256(values: Map<String, String>) = apply {
            values.forEach { (name, digest) -> expectedManifestMetaDataEntrySha256(name, digest) }
        }
        fun expectedManifestMetaDataSemanticsSha256(name: String, digest: String?) = apply {
            val normalizedName = name.trim()
            val normalizedDigest = normalizeDigest(digest)
            if (normalizedName.isNotEmpty() && normalizedDigest != null) {
                expectedManifestMetaDataSemanticsSha256[normalizedName] = normalizedDigest
            }
        }
        fun expectedManifestMetaDataSemanticsSha256(values: Map<String, String>) = apply {
            values.forEach { (name, digest) -> expectedManifestMetaDataSemanticsSha256(name, digest) }
        }
        fun expectedMetaData(name: String, value: String?) = apply {
            val normalizedName = name.trim()
            val normalizedValue = value?.trim()?.ifEmpty { null }
            if (normalizedName.isNotEmpty() && normalizedValue != null) {
                expectedMetaData[normalizedName] = normalizedValue
            }
        }
        fun expectedMetaData(values: Map<String, String>) = apply {
            values.forEach { (name, value) -> expectedMetaData(name, value) }
        }

        fun build() = LeonaConfig(
            injectionDetectionEnabled = injection,
            environmentDetectionEnabled = environment,
            reportingEndpoint = reportingEndpoint,
            apiKey = apiKey,
            tenantId = tenantId,
            appId = appId,
            region = region,
            transportEnabled = transportEnabled,
            cloudConfigEnabled = cloudConfigEnabled,
            cloudConfigEndpoint = cloudConfigEndpoint,
            syncInit = syncInit,
            verifyServerCert = verifyServerCert,
            disableCollectionWindowMs = disableCollectionWindowMs,
            disabledSignals = disabledSignals.toSet(),
            channel = channel,
            extraInfo = extraInfo,
            firstPartyMode = firstPartyMode,
            verboseNativeLogging = verboseNativeLogging,
            preferStrongBoxBackedKey = preferStrongBoxBackedKey,
            certificatePins = certificatePins.mapValues { it.value.toSet() }.toMap(),
            attestationProvider = attestationProvider,
            expectedPackageName = expectedPackageName,
            allowedInstallerPackages = allowedInstallerPackages.toSet(),
            allowedSigningCertSha256 = allowedSigningCertSha256.toSet(),
            expectedSigningCertificateLineageSha256 = expectedSigningCertificateLineageSha256,
            expectedApkSigningBlockSha256 = expectedApkSigningBlockSha256,
            expectedApkSigningBlockIdSha256 = expectedApkSigningBlockIdSha256.toMap(),
            expectedApkSha256 = expectedApkSha256,
            expectedNativeLibSha256 = expectedNativeLibSha256.toMap(),
            expectedManifestEntrySha256 = expectedManifestEntrySha256,
            expectedResourcesArscSha256 = expectedResourcesArscSha256,
            expectedResourceInventorySha256 = expectedResourceInventorySha256,
            expectedResourceEntrySha256 = expectedResourceEntrySha256.toMap(),
            expectedDexSha256 = expectedDexSha256.toMap(),
            expectedDexSectionSha256 = expectedDexSectionSha256.toMap(),
            expectedDexMethodSha256 = expectedDexMethodSha256.toMap(),
            expectedSplitApkSha256 = expectedSplitApkSha256.toMap(),
            expectedSplitInventorySha256 = expectedSplitInventorySha256,
            expectedDynamicFeatureSplitSha256 = expectedDynamicFeatureSplitSha256,
            expectedDynamicFeatureSplitNameSha256 = expectedDynamicFeatureSplitNameSha256,
            expectedConfigSplitAxisSha256 = expectedConfigSplitAxisSha256,
            expectedConfigSplitNameSha256 = expectedConfigSplitNameSha256,
            expectedConfigSplitAbiSha256 = expectedConfigSplitAbiSha256,
            expectedConfigSplitLocaleSha256 = expectedConfigSplitLocaleSha256,
            expectedConfigSplitDensitySha256 = expectedConfigSplitDensitySha256,
            expectedElfSectionSha256 = expectedElfSectionSha256.toMap(),
            expectedElfExportSymbolSha256 = expectedElfExportSymbolSha256.toMap(),
            expectedElfExportGraphSha256 = expectedElfExportGraphSha256.toMap(),
            expectedRequestedPermissionsSha256 = expectedRequestedPermissionsSha256,
            expectedRequestedPermissionSemanticsSha256 = expectedRequestedPermissionSemanticsSha256,
            expectedDeclaredPermissionSemanticsSha256 = expectedDeclaredPermissionSemanticsSha256,
            expectedDeclaredPermissionFieldValues = expectedDeclaredPermissionFieldValues.toMap(),
            expectedComponentSignatureSha256 = expectedComponentSignatureSha256.toMap(),
            expectedComponentAccessSemanticsSha256 = expectedComponentAccessSemanticsSha256.toMap(),
            expectedComponentOperationalSemanticsSha256 =
                expectedComponentOperationalSemanticsSha256.toMap(),
            expectedComponentFieldValues = expectedComponentFieldValues.toMap(),
            expectedProviderUriPermissionPatternsSha256 = expectedProviderUriPermissionPatternsSha256.toMap(),
            expectedProviderPathPermissionsSha256 = expectedProviderPathPermissionsSha256.toMap(),
            expectedProviderAuthoritySetSha256 = expectedProviderAuthoritySetSha256.toMap(),
            expectedProviderSemanticsSha256 = expectedProviderSemanticsSha256.toMap(),
            expectedProviderAccessSemanticsSha256 = expectedProviderAccessSemanticsSha256.toMap(),
            expectedProviderOperationalSemanticsSha256 =
                expectedProviderOperationalSemanticsSha256.toMap(),
            expectedIntentFilterSha256 = expectedIntentFilterSha256.toMap(),
            expectedIntentFilterActionSha256 = expectedIntentFilterActionSha256.toMap(),
            expectedIntentFilterCategorySha256 = expectedIntentFilterCategorySha256.toMap(),
            expectedIntentFilterDataSha256 = expectedIntentFilterDataSha256.toMap(),
            expectedIntentFilterDataSchemeSha256 = expectedIntentFilterDataSchemeSha256.toMap(),
            expectedIntentFilterDataAuthoritySha256 = expectedIntentFilterDataAuthoritySha256.toMap(),
            expectedIntentFilterDataPathSha256 = expectedIntentFilterDataPathSha256.toMap(),
            expectedIntentFilterDataMimeTypeSha256 = expectedIntentFilterDataMimeTypeSha256.toMap(),
            expectedIntentFilterSemanticsSha256 = expectedIntentFilterSemanticsSha256.toMap(),
            expectedGrantUriPermissionSha256 = expectedGrantUriPermissionSha256.toMap(),
            expectedGrantUriPermissionSemanticsSha256 =
                expectedGrantUriPermissionSemanticsSha256.toMap(),
            expectedUsesFeatureSha256 = expectedUsesFeatureSha256,
            expectedUsesFeatureNameSha256 = expectedUsesFeatureNameSha256,
            expectedUsesFeatureRequiredSha256 = expectedUsesFeatureRequiredSha256,
            expectedUsesFeatureGlEsVersionSha256 = expectedUsesFeatureGlEsVersionSha256,
            expectedUsesFeatureFieldValues = expectedUsesFeatureFieldValues.toMap(),
            expectedUsesSdkSha256 = expectedUsesSdkSha256,
            expectedUsesSdkMinSha256 = expectedUsesSdkMinSha256,
            expectedUsesSdkTargetSha256 = expectedUsesSdkTargetSha256,
            expectedUsesSdkMaxSha256 = expectedUsesSdkMaxSha256,
            expectedUsesSdkFieldValues = expectedUsesSdkFieldValues.toMap(),
            expectedSupportsScreensSha256 = expectedSupportsScreensSha256,
            expectedSupportsScreensSmallScreensSha256 = expectedSupportsScreensSmallScreensSha256,
            expectedSupportsScreensNormalScreensSha256 = expectedSupportsScreensNormalScreensSha256,
            expectedSupportsScreensLargeScreensSha256 = expectedSupportsScreensLargeScreensSha256,
            expectedSupportsScreensXlargeScreensSha256 = expectedSupportsScreensXlargeScreensSha256,
            expectedSupportsScreensResizeableSha256 = expectedSupportsScreensResizeableSha256,
            expectedSupportsScreensAnyDensitySha256 = expectedSupportsScreensAnyDensitySha256,
            expectedSupportsScreensRequiresSmallestWidthDpSha256 =
                expectedSupportsScreensRequiresSmallestWidthDpSha256,
            expectedSupportsScreensCompatibleWidthLimitDpSha256 =
                expectedSupportsScreensCompatibleWidthLimitDpSha256,
            expectedSupportsScreensLargestWidthLimitDpSha256 =
                expectedSupportsScreensLargestWidthLimitDpSha256,
            expectedCompatibleScreensSha256 = expectedCompatibleScreensSha256,
            expectedCompatibleScreensScreenSizeSha256 = expectedCompatibleScreensScreenSizeSha256,
            expectedCompatibleScreensScreenDensitySha256 = expectedCompatibleScreensScreenDensitySha256,
            expectedUsesLibrarySha256 = expectedUsesLibrarySha256,
            expectedUsesLibraryNameSha256 = expectedUsesLibraryNameSha256,
            expectedUsesLibraryRequiredSha256 = expectedUsesLibraryRequiredSha256,
            expectedUsesLibraryFieldValues = expectedUsesLibraryFieldValues.toMap(),
            expectedUsesLibraryOnlySha256 = expectedUsesLibraryOnlySha256,
            expectedUsesLibraryOnlyNameSha256 = expectedUsesLibraryOnlyNameSha256,
            expectedUsesLibraryOnlyRequiredSha256 = expectedUsesLibraryOnlyRequiredSha256,
            expectedUsesNativeLibrarySha256 = expectedUsesNativeLibrarySha256,
            expectedUsesNativeLibraryNameSha256 = expectedUsesNativeLibraryNameSha256,
            expectedUsesNativeLibraryRequiredSha256 = expectedUsesNativeLibraryRequiredSha256,
            expectedUsesNativeLibraryFieldValues = expectedUsesNativeLibraryFieldValues.toMap(),
            expectedQueriesSha256 = expectedQueriesSha256,
            expectedQueriesPackageSha256 = expectedQueriesPackageSha256,
            expectedQueriesPackageNameSha256 = expectedQueriesPackageNameSha256,
            expectedQueriesPackageSemanticsSha256 = expectedQueriesPackageSemanticsSha256,
            expectedQueriesProviderSha256 = expectedQueriesProviderSha256,
            expectedQueriesProviderAuthoritySha256 = expectedQueriesProviderAuthoritySha256,
            expectedQueriesProviderSemanticsSha256 = expectedQueriesProviderSemanticsSha256,
            expectedQueriesIntentSha256 = expectedQueriesIntentSha256,
            expectedQueriesIntentActionSha256 = expectedQueriesIntentActionSha256,
            expectedQueriesIntentCategorySha256 = expectedQueriesIntentCategorySha256,
            expectedQueriesIntentDataSha256 = expectedQueriesIntentDataSha256,
            expectedQueriesIntentDataSchemeSha256 = expectedQueriesIntentDataSchemeSha256,
            expectedQueriesIntentDataAuthoritySha256 = expectedQueriesIntentDataAuthoritySha256,
            expectedQueriesIntentDataPathSha256 = expectedQueriesIntentDataPathSha256,
            expectedQueriesIntentDataMimeTypeSha256 = expectedQueriesIntentDataMimeTypeSha256,
            expectedQueriesIntentSemanticsSha256 = expectedQueriesIntentSemanticsSha256,
            expectedApplicationSemanticsSha256 = expectedApplicationSemanticsSha256,
            expectedApplicationSecuritySemanticsSha256 = expectedApplicationSecuritySemanticsSha256,
            expectedApplicationRuntimeSemanticsSha256 = expectedApplicationRuntimeSemanticsSha256,
            expectedApplicationFieldValues = expectedApplicationFieldValues.toMap(),
            expectedMetaDataType = expectedMetaDataType.toMap(),
            expectedMetaDataValueSha256 = expectedMetaDataValueSha256.toMap(),
            expectedManifestMetaDataEntrySha256 = expectedManifestMetaDataEntrySha256.toMap(),
            expectedManifestMetaDataSemanticsSha256 = expectedManifestMetaDataSemanticsSha256.toMap(),
            expectedMetaData = expectedMetaData.toMap(),
        )

        private fun normalizeToken(value: String?): String? =
            value?.trim()?.ifEmpty { null }

        private fun normalizeDigest(value: String?): String? =
            value?.trim()?.lowercase()?.ifEmpty { null }

        private fun normalizePin(value: String?): String? {
            val pin = value?.trim()?.ifEmpty { null } ?: return null
            return if (pin.startsWith("sha256/")) pin else "sha256/$pin"
        }

        private fun putNormalized(target: MutableMap<String, String>, key: String, digest: String?) {
            val normalizedKey = key.trim()
            val normalizedDigest = normalizeDigest(digest)
            if (normalizedKey.isNotEmpty() && normalizedDigest != null) {
                target[normalizedKey] = normalizedDigest
            }
        }

        private fun putRawValue(target: MutableMap<String, String>, key: String, value: String?) {
            val normalizedKey = key.trim()
            val normalizedValue = value?.trim()?.ifEmpty { null }
            if (normalizedKey.isNotEmpty() && normalizedValue != null) {
                target[normalizedKey] = normalizedValue
            }
        }
    }

    private companion object {
        const val FLAG_INJECTION = 1L shl 0
        const val FLAG_ENVIRONMENT = 1L shl 1
        const val FLAG_VERBOSE_LOG = 1L shl 2
    }
}
