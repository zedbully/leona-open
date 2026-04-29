<div align="center">

# 🛡️ Leona Android SDK

**Runtime security for Android apps — no client-side decisions, no bypass-by-one-byte-patch.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Min SDK](https://img.shields.io/badge/minSdk-21-brightgreen)]()
[![Version](https://img.shields.io/badge/version-0.1.0--alpha.1-orange)]()

</div>

---

## Why this SDK exists

Most Android security SDKs detect Frida, Xposed, and friends by checking
**process names**, **file paths**, or **API name hashes**, and then return
`true` or `false` from some public method. Attackers rename processes, repack
libraries, or just `return false;` — all defeated in minutes.

**Leona is built on three principles that change that.**

### Principle #A — Zero client-side decisions

No public method on this SDK returns `hasCritical()`, `isTampered()`, or any
other boolean that your app should trust. Every such method is a single-byte
patch target. Leona's API gives you a single opaque **BoxId** per sensing
session. Your *backend* exchanges that BoxId with Leona's server to get the
authoritative verdict. Attackers can't reach your backend; they can reach
every line of your APK.

### Principle #B — BoxId server handshake

```
[ Your app + Leona SDK ]  ──sense()──▶  [ Leona backend ]
                          ◀──BoxId──────
        │
        │  business API call (carries BoxId)
        ▼
[ Your backend ]  ──query(BoxId)──▶  [ Leona backend ]
                  ◀─deviceId + risk────
        │
        ▼
  your decision (allow / challenge / deny / honeypot)
```

The client cannot inspect detection results. The server can.

### Principle #C — Layered deception (onion defense)

Some functions on this SDK are decoys. They look meaningful, they're easy to
patch, and patching them achieves nothing — because the real defense runs on
an independent path inside the native core, encrypts its output client-side,
and delivers it to the server without ever materializing typed results in
the JVM. Attackers spend days defeating layers that weren't protecting
anything.

## Quick start

```kotlin
// Application.onCreate()
Leona.init(this, LeonaConfig.Builder()
    .apiKey("your-leona-api-key")
    .reportingEndpoint("https://api.leonasec.io")
    // Optional tamper baselines (alpha):
    .expectedPackageName("com.example.app")
    .allowedInstallerPackages("com.android.vending")
    .allowedSigningCertSha256("your_signing_cert_sha256")
    .expectedSigningCertificateLineageSha256("expected_signing_lineage_fingerprint")
    .expectedApkSigningBlockSha256("expected_apk_signing_block_sha256")
    .expectedApkSigningBlockIdSha256("0x7109871a", "expected_v2_signing_block_value_sha256")
    .expectedApkSha256("expected_apk_sha256")
    .expectedNativeLibrarySha256("libleona.so", "expected_lib_sha256")
    .expectedManifestEntrySha256("expected_manifest_entry_sha256")
    .expectedResourcesArscSha256("expected_resources_arsc_sha256")
    .expectedResourceInventorySha256("expected_resource_inventory_fingerprint")
    .expectedResourceEntrySha256("res/raw/leona.bin", "expected_resource_entry_sha256")
    .expectedDexSha256("classes.dex", "expected_classes_dex_sha256")
    .expectedDexSectionSha256("classes.dex#code_item", "expected_code_item_section_sha256")
    .expectedDexMethodSha256(
        "classes.dex#Lcom/example/app/MainActivity;->isTampered()Z",
        "expected_method_code_hash"
    )
    .expectedSplitApkSha256("config.arm64_v8a.apk", "expected_split_sha256")
    .expectedSplitInventorySha256("expected_split_inventory_fingerprint")
    .expectedDynamicFeatureSplitSha256("expected_dynamic_feature_split_fingerprint")
    .expectedDynamicFeatureSplitNameSha256("expected_dynamic_feature_split_name_fingerprint")
    .expectedConfigSplitAxisSha256("expected_config_split_axis_fingerprint")
    .expectedConfigSplitNameSha256("expected_config_split_name_fingerprint")
    .expectedConfigSplitAbiSha256("expected_config_split_abi_fingerprint")
    .expectedConfigSplitLocaleSha256("expected_config_split_locale_fingerprint")
    .expectedConfigSplitDensitySha256("expected_config_split_density_fingerprint")
    .expectedElfSectionSha256("libleona.so#.text", "expected_elf_text_section_sha256")
    .expectedElfExportSymbolSha256("libleona.so#JNI_OnLoad", "expected_export_symbol_fingerprint")
    .expectedElfExportGraphSha256("libleona.so", "expected_export_graph_fingerprint")
    .expectedRequestedPermissionsSha256("expected_permissions_fingerprint")
    .expectedRequestedPermissionSemanticsSha256("expected_permission_semantics_fingerprint")
    .expectedDeclaredPermissionSemanticsSha256("expected_declared_permission_semantics_fingerprint")
    .expectedDeclaredPermissionFieldValue(
        "permission:com.example.permission.GUARD#protectionLevel",
        "18"
    )
    .expectedComponentSignatureSha256(
        "activity:com.example.app.MainActivity",
        "expected_component_fingerprint"
    )
    .expectedComponentAccessSemanticsSha256(
        "activity:com.example.app.MainActivity",
        "expected_component_access_fingerprint"
    )
    .expectedComponentOperationalSemanticsSha256(
        "activity:com.example.app.MainActivity",
        "expected_component_operational_fingerprint"
    )
    .expectedComponentFieldValue(
        "activity:com.example.app.MainActivity#exported",
        "false"
    )
    .expectedProviderUriPermissionPatternsSha256(
        "provider:com.example.app.DataProvider",
        "expected_uri_permission_patterns_fingerprint"
    )
    .expectedProviderPathPermissionsSha256(
        "provider:com.example.app.DataProvider",
        "expected_path_permissions_fingerprint"
    )
    .expectedProviderAuthoritySetSha256(
        "provider:com.example.app.DataProvider",
        "expected_authority_set_fingerprint"
    )
    .expectedProviderSemanticsSha256(
        "provider:com.example.app.DataProvider",
        "expected_provider_semantics_fingerprint"
    )
    .expectedProviderAccessSemanticsSha256(
        "provider:com.example.app.DataProvider",
        "expected_provider_access_semantics_fingerprint"
    )
    .expectedProviderOperationalSemanticsSha256(
        "provider:com.example.app.DataProvider",
        "expected_provider_operational_semantics_fingerprint"
    )
    .expectedIntentFilterSha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_fingerprint"
    )
    .expectedIntentFilterActionSha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_action_fingerprint"
    )
    .expectedIntentFilterCategorySha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_category_fingerprint"
    )
    .expectedIntentFilterDataSha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_data_fingerprint"
    )
    .expectedIntentFilterDataSchemeSha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_data_scheme_fingerprint"
    )
    .expectedIntentFilterDataAuthoritySha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_data_authority_fingerprint"
    )
    .expectedIntentFilterDataPathSha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_data_path_fingerprint"
    )
    .expectedIntentFilterDataMimeTypeSha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_data_mimetype_fingerprint"
    )
    .expectedIntentFilterSemanticsSha256(
        "activity:com.example.app.MainActivity",
        "expected_intent_filter_semantics_fingerprint"
    )
    .expectedGrantUriPermissionSha256(
        "provider:com.example.app.DataProvider",
        "expected_grant_uri_permission_fingerprint"
    )
    .expectedGrantUriPermissionSemanticsSha256(
        "provider:com.example.app.DataProvider",
        "expected_grant_uri_permission_semantics_fingerprint"
    )
    .expectedUsesFeatureSha256("expected_uses_feature_fingerprint")
    .expectedUsesFeatureNameSha256("expected_uses_feature_name_fingerprint")
    .expectedUsesFeatureRequiredSha256("expected_uses_feature_required_fingerprint")
    .expectedUsesFeatureGlEsVersionSha256("expected_uses_feature_gles_fingerprint")
    .expectedUsesFeatureFieldValue("uses-feature:android.hardware.camera#required", "true")
    .expectedUsesSdkSha256("expected_uses_sdk_fingerprint")
    .expectedUsesSdkMinSha256("expected_uses_sdk_min_fingerprint")
    .expectedUsesSdkTargetSha256("expected_uses_sdk_target_fingerprint")
    .expectedUsesSdkMaxSha256("expected_uses_sdk_max_fingerprint")
    .expectedUsesSdkFieldValue("uses-sdk#targetSdkVersion", "34")
    .expectedSupportsScreensSha256("expected_supports_screens_fingerprint")
    .expectedSupportsScreensAnyDensitySha256("expected_supports_screens_any_density_fingerprint")
    .expectedSupportsScreensResizeableSha256("expected_supports_screens_resizeable_fingerprint")
    .expectedCompatibleScreensScreenSizeSha256("expected_compatible_screens_size_fingerprint")
    .expectedCompatibleScreensScreenDensitySha256("expected_compatible_screens_density_fingerprint")
    .expectedCompatibleScreensSha256("expected_compatible_screens_fingerprint")
    .expectedUsesLibrarySha256("expected_uses_library_fingerprint")
    .expectedUsesLibraryNameSha256("expected_uses_library_name_fingerprint")
    .expectedUsesLibraryRequiredSha256("expected_uses_library_required_fingerprint")
    .expectedUsesLibraryFieldValue("uses-library:org.apache.http.legacy#required", "false")
    .expectedUsesLibraryOnlySha256("expected_uses_library_only_fingerprint")
    .expectedUsesLibraryOnlyNameSha256("expected_uses_library_only_name_fingerprint")
    .expectedUsesLibraryOnlyRequiredSha256("expected_uses_library_only_required_fingerprint")
    .expectedUsesNativeLibrarySha256("expected_uses_native_library_fingerprint")
    .expectedUsesNativeLibraryNameSha256("expected_uses_native_library_name_fingerprint")
    .expectedUsesNativeLibraryRequiredSha256("expected_uses_native_library_required_fingerprint")
    .expectedUsesNativeLibraryFieldValue("uses-native-library:com.example.sec#required", "true")
    .expectedQueriesSha256("expected_queries_fingerprint")
    .expectedQueriesPackageSha256("expected_queries_package_fingerprint")
    .expectedQueriesPackageNameSha256("expected_queries_package_name_fingerprint")
    .expectedQueriesPackageSemanticsSha256("expected_queries_package_semantics_fingerprint")
    .expectedQueriesProviderSha256("expected_queries_provider_fingerprint")
    .expectedQueriesProviderAuthoritySha256("expected_queries_provider_authority_fingerprint")
    .expectedQueriesProviderSemanticsSha256("expected_queries_provider_semantics_fingerprint")
    .expectedQueriesIntentSha256("expected_queries_intent_fingerprint")
    .expectedQueriesIntentActionSha256("expected_queries_intent_action_fingerprint")
    .expectedQueriesIntentCategorySha256("expected_queries_intent_category_fingerprint")
    .expectedQueriesIntentDataSha256("expected_queries_intent_data_fingerprint")
    .expectedQueriesIntentDataSchemeSha256("expected_queries_intent_data_scheme_fingerprint")
    .expectedQueriesIntentDataAuthoritySha256("expected_queries_intent_data_authority_fingerprint")
    .expectedQueriesIntentDataPathSha256("expected_queries_intent_data_path_fingerprint")
    .expectedQueriesIntentDataMimeTypeSha256("expected_queries_intent_mimetype_fingerprint")
    .expectedQueriesIntentSemanticsSha256("expected_queries_intent_semantics_fingerprint")
    .expectedApplicationSemanticsSha256("expected_application_semantics_fingerprint")
    .expectedApplicationSecuritySemanticsSha256("expected_application_security_semantics_fingerprint")
    .expectedApplicationRuntimeSemanticsSha256("expected_application_runtime_semantics_fingerprint")
    .expectedApplicationFieldValue("application#usesCleartextTraffic", "false")
    .expectedApplicationFieldValue("application#allowBackup", "false")
    .expectedMetaDataType("channel", "string")
    .expectedMetaDataValueSha256("channel", "expected_metadata_value_hash")
    .expectedManifestMetaDataEntrySha256("channel", "expected_manifest_metadata_entry_hash")
    .expectedManifestMetaDataSemanticsSha256("channel", "expected_manifest_metadata_semantics_hash")
    .expectedMetaData("channel", "play")
    .build())
```

If your Leona server returns a `tamperBaseline` object from `/v1/handshake`,
the SDK will merge that remote baseline with the local Builder values before
each sensing session.

You can generate the APK-side baseline fields from a built APK:

```bash
./scripts/generate-tamper-baseline.py \
  sample-app/build/outputs/apk/debug/sample-app-debug.apk \
  --package-name io.leonasec.leona.sample \
  --resource-entry res/raw/leona.bin \
  --dex-section classes.dex#code_item \
  --split-dir /path/to/bundletool/splits \
  > tamper-baseline.json
```

Use `--all-resource-entries` only when you intentionally want every
`res/...` and `assets/...` file pinned; for most channel builds the resource
inventory hash plus a few high-value entries is easier to operate. Use
`--dex-section ENTRY#SECTION` for high-value DEX regions such as
`classes.dex#code_item` or `classes.dex#class_defs`; `--all-dex-sections`
is available for stricter release baselines. Use `--split-apk` or
`--split-dir` for bundletool/dynamic-feature/config split outputs; the
generator keys split hashes by filename so channel packages can keep separate
server baselines without rebuilding client code.

```kotlin
// At a sensitive moment (login, payment, high-value API call):
val boxId: BoxId = Leona.sense()

// Pass the opaque token to YOUR backend:
val loginResponse = myApi.login(
    username,
    password,
    leonaBoxId = boxId.toString(),
)

// Your backend calls Leona's API with boxId and gets the real verdict.
```

From Java, use the async variant:

```java
Leona.senseAsync(new BoxIdCallback() {
    @Override public void onSuccess(BoxId id) { /* forward id.toString() */ }
    @Override public void onError(Throwable t) { /* policy: fail open vs closed */ }
});
```

For internal QA / debug UI only, you can also inspect the local diagnostic
snapshot:

```kotlin
val diag = Leona.getDiagnosticSnapshot()
// deviceId / fingerprint / localRiskSignals / nativeRiskTags / nativeFindingIds

val diagJson = Leona.getDiagnosticSnapshotJson()
val lastVerdict = Leona.getLastServerVerdict()
val lastVerdictJson = Leona.getLastServerVerdictJson()
val transportJson = Leona.getSecureTransportSnapshotJson()
val supportBundleJson = Leona.getSupportBundleJson()
// support bundle also includes:
// - effective tamper policy entries
// - last integrity snapshot key/value pairs
// - cached cloud-config payload + fetchedAt
// - secure transport diagnostics:
//   device-binding key presence / pubkey hash / hardware-backed state
//   cached secure session status / expiry / canonicalDeviceId
//   last attestation format + token hash + last handshake status
```

See:

- `/Users/a/back/Game/cq/leona-sdk-android/docs/device-identity-risk-protocol.md`

Latency: **5–50ms** for the native collection phase; network adds whatever
your reporting endpoint does. The public surface remains intentionally small.

## Current status

`0.1.0-alpha.1` is a **real engineering alpha**, not a design-only drop.

- The SDK already contains the native detection path, JNI bridge, payload
  format, and the Kotlin-side secure upload implementation.
- The public sample app is intended to run with a Leona-issued API key and
  Leona hosted endpoints.
- Authoritative verdicts, policy, tenant settings, and data interpretation
  are handled by the Leona API/backend. The Android client collects and
  reports signals; it does not make the final allow/deny decision.

## Public SDK vs closed-source runtime

This repository publishes the Android public integration SDK only. Customers
can integrate the SDK into their APK and use it in production, but the open
source checkout must be configured with Leona API/backend access to obtain
authoritative verdicts.

For security reasons, this public repository does not include:

- Leona hosted API/backend implementation
- private detector catalogs and native runtime internals
- risk scoring weights and tenant policy execution
- internal operations, deployment, and release automation

## What v0.1.0-alpha.1 detects

| Category | Check | Note |
|----------|-------|------|
| Injection | `TracerPid` in `/proc/self/status` | ptrace attach |
| Injection | `frida-gadget` / `frida-agent` as mapped library | weak signal, corroboration only |
| Injection | **Frida trampoline machine-code pattern** (ARM64) | Leona's core signal |
| Environment | Emulator system-property heuristic | QEMU, Genymotion, etc. |
| **Unidbg** | CNTVCT_EL0 / CNTFRQ_EL0 timing coherence | **New in alpha.1** |
| **Unidbg** | Parent process non-zygote | **New in alpha.1** |
| **Unidbg** | `/proc/cpuinfo` shape | **New in alpha.1** |

## Roadmap — what's coming

**v0.1.0 (next release)**:
- ARM32 / x86_64 Frida signatures
- Xposed `art_method` modification signatures, Substrate PLT trampolines, Magisk Zygisk residue
- Full emulator catalog (Genymotion, LDPlayer, NoxPlayer, MuMu, BlueStacks)
- Root indicators (Magisk hidden, Zygisk modules, KernelSU)
- Honeypot primitives

**v0.2.0**:
- Harden and validate the existing ECDHE + AES-GCM BoxId channel end-to-end
- Non-standard algorithm proxy module
- Dual-path injection detector (patch-resistance hardening)

**v0.3.0+**:
- Separate build-time tools: `leona-so-protector`, `leona-dex-packer`
- Hosted Leona API/backend integration hardening
- Commercial/private: persistent device fingerprint, VM virtualization, private deployment

## Architecture

```
┌────────────────────────────────────────────────────────┐
│ Your app (Kotlin / Java)                               │
│                                                        │
│    Leona.init(context, config)                         │
│    val boxId = Leona.sense()                           │
│    → send boxId to your backend                        │
└──────────────────────┬─────────────────────────────────┘
                       │ Public API: 4 classes total
                       │ (Leona, BoxId, BoxIdCallback, LeonaConfig)
┌──────────────────────┴─────────────────────────────────┐
│ io.leonasec.leona.internal  (not part of public API)   │
│   NativeBridge: JNI calls                              │
│   SecureChannel: collection upload + BoxId minting     │
└──────────────────────┬─────────────────────────────────┘
                       │ Single JNI boundary; crosses
                       │ only opaque byte payloads.
┌──────────────────────┴─────────────────────────────────┐
│ libleona.so (C++17, NDK)                               │
│                                                        │
│   jni_bridge          ──➋ init / collect / decoyCheck  │
│     │                                                  │
│     └─▶ report::collector                              │
│            │                                           │
│            ├─▶ detection::injection   (Frida, ptrace)  │
│            ├─▶ detection::environment (emu, props)     │
│            └─▶ detection::unidbg      (timing, proc)   │
│                                                        │
│     ── serialize → scramble → bytes → JVM ──▶          │
│     (format deliberately undocumented)                 │
└────────────────────────────────────────────────────────┘
```

**Design principles**:
1. **Native-first** — all sensitive checks live in C++; Kotlin-level hooks cannot disable them.
2. **No reflection** — reflection is itself a hook surface.
3. **Single JNI call per session** — one round trip, one opaque payload.
4. **Opaque payload on both sides of the boundary** — the JVM sees bytes it cannot decode.
5. **Decoy API isolation** — the decoy `quickCheck()` lives on a separate native path so patching it leaves the real `collect()` intact.

## Public API surface

That's the entire API.

```
io.leonasec.leona
├─ object Leona
│   ├─ init(Context, LeonaConfig)
│   ├─ suspend sense(): BoxId
│   ├─ senseAsync(BoxIdCallback)
│   ├─ version: String
│   └─ @Deprecated quickCheck(): Boolean   ← decoy, don't use
├─ class BoxId           (opaque token; toString forwards to backend)
├─ interface BoxIdCallback
└─ io.leonasec.leona.config
    ├─ class LeonaConfig
    └─ class LeonaConfig.Builder
```

## Building from source

```bash
./gradlew :sdk:assembleRelease
# AAR output: sdk/build/outputs/aar/sdk-release.aar
```

Requirements: JDK 17+, Android Gradle Plugin 8.5+, NDK r26+ (Gradle auto-installs).

For the public/open-source boundary, see
[`../docs/open-source-policy.md`](../docs/open-source-policy.md).

## CI

This repo includes:

- regular Android public SDK CI in `../.github/workflows/android.yml`
- nightly public SDK checks for unit tests, AAR assembly, and native source sanity

Public CI does not include Leona hosted backend implementation, demo backend,
private detector modules, private risk policy, or internal release flows.
Those are closed-source for security reasons.

To build or install the sample app against Leona hosted endpoints:

```bash
LEONA_API_KEY=<appKey> \
LEONA_REPORTING_ENDPOINT=https://<leona-api> \
LEONA_CLOUD_CONFIG_ENDPOINT=https://<leona-config-api>/v1/mobile-config \
./scripts/run-live-sample.sh
```

The public SDK requires Leona hosted API/backend access for authoritative
verdicts. It does not ship a self-hosted production backend.

## Contributing

Leona is in alpha. High-leverage places to help right now:

- 🧪 Test on real devices and Unidbg — open issues with `/proc/self/maps`
  dumps when trampoline detection produces false positives.
- 📝 Add signatures for Xposed / Substrate / Magisk — see `frida_signatures.cpp`
  for the masked-byte format.
- 🕳️ Identify decoy patterns that do *not* look decoy-shaped — the best
  decoys are the ones that pass code review.

## License

[Apache License 2.0](LICENSE) — free for commercial use, patent grant included.

---

<div align="center">

*If Leona stops a hook in your production app, a ⭐ on GitHub is the best thanks you can give.*

</div>
