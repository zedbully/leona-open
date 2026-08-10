<div align="center">

# 🛡️ Leona Android SDK

**Device environment evidence collection for Android apps — no client-side decisions, no built-in business policy.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Min SDK](https://img.shields.io/badge/minSdk-21-brightgreen)]()
[![Version](https://img.shields.io/badge/version-0.4.0-blue)]()

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
collected device/environment evidence. Your backend owns the business policy;
attackers can't reach your backend, but they can reach every line of your APK.

### Principle #B — BoxId server handshake

```
[ Your app + Leona SDK ]  ──sense()──▶  [ Leona backend ]
                          ◀──BoxId──────
        │
        │  business API call (carries BoxId)
        ▼
[ Your backend ]  ──query(BoxId)──▶  [ Leona backend ]
                  ◀─deviceId + evidence────
        │
        ▼
  your own business policy
```

The client cannot inspect detection results. Leona returns evidence; the
calling business system defines how that evidence is interpreted.

### Principle #C — Layered deception (onion defense)

Some functions on this SDK are decoys. They look meaningful, they're easy to
patch, and patching them achieves nothing — because the real defense runs on
an independent path inside the native core, encrypts its output client-side,
and delivers it to the server without ever materializing typed results in
the JVM. Attackers spend days defeating layers that weren't protecting
anything.

## Install from Maven

The automated Maven channel for `v0.4.0` is GitHub Packages. It is the
lowest-risk public-safe path for this repository because tag builds can publish
with the repository-scoped `GITHUB_TOKEN` and do not require Maven Central
namespace approval, Central Portal tokens, or PGP signing keys.

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://maven.pkg.github.com/zedbully/leona-open") {
            credentials {
                username = providers.gradleProperty("gpr.user")
                    .orElse(providers.environmentVariable("GITHUB_ACTOR"))
                    .orNull
                password = providers.gradleProperty("gpr.key")
                    .orElse(providers.environmentVariable("GITHUB_TOKEN"))
                    .orNull
            }
        }
    }
}
```

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("io.leonasec:leona-sdk-android:0.4.0")
}
```

GitHub Packages may require a token with `read:packages` for Gradle dependency
resolution. Maven Central remains the preferred zero-token public consumer
experience, but it is blocked until the project has a verified namespace,
Central Portal publishing credentials, and signing material.

The SDK Gradle publication has a public-safe `MavenCentral` repository path and
in-memory PGP signing wiring. Credentials are read only from Gradle properties
or environment variables such as `CENTRAL_PORTAL_USERNAME`,
`CENTRAL_PORTAL_PASSWORD`, `SIGNING_KEY`, and `SIGNING_PASSWORD`; secret values
must stay outside the public repository and outside public workflow logs.

For the pre-Central release gate, run the public-safe readiness check:

```bash
./scripts/verify-maven-central-readiness.sh
```

The script validates the current publication metadata, GitHub fallback path,
local consumer entrypoint, and required Central/PGP environment names without
printing secret values. Missing Central Portal or signing material is reported
as an external blocker unless `LEONA_REQUIRE_MAVEN_CENTRAL_SECRETS=1` is set.

Before cutting a tag, run the local consumer gate:

```bash
./scripts/verify-maven-local-consumer.sh
```

This publishes `io.leonasec:leona-sdk-android:0.4.0` into an isolated temporary
Maven local repository, then resolves it from a separate Gradle consumer project
and checks that the AAR plus expected public transitive dependencies are
available. This does not replace the required post-tag GitHub Packages remote
pull check.

### Domestic direct/private distribution

Deployments that do not use Google runtime services may distribute the same
coordinate through a customer-controlled Maven repository. Prepare exactly the
AAR, POM, Gradle module metadata, sources JAR, and javadoc JAR, with one
detached armored OpenPGP signature and one SHA-256 sidecar for each artifact.
Then verify the prepared repository and an independent consumer result:

```bash
python3 scripts/verify-v0.4-domestic-private-distribution.py \
  --repository-dir /path/to/prepared-maven-repository \
  --public-key /path/to/customer-trusted-public-key.asc \
  --consumer-summary /path/to/independent-consumer-summary.json \
  --expected-aar-sha256 expected_lowercase_sha256 \
  --output-dir /tmp/leona-domestic-private-distribution
```

The verifier never publishes or signs artifacts. It rejects ambiguous files,
checksum/signature drift, coordinate traversal, private-key input, any
`com.google` Maven dependency, and any `com/google/` runtime package embedded
in the AAR. A passing result is support evidence only: the customer must
configure its own signing trust and its backend remains the sole owner of
business decisions.

The release-readiness wrapper combines the lightweight local checks and lists
the external gates that cannot be completed until a tag or real device is
available:

```bash
./scripts/verify-v0.3-release-readiness.sh
```

Set `LEONA_RUN_MAVEN_CONSUMER_GATE=1` or `LEONA_RUN_PUBLIC_GRADLE_GATE=1` when
you want that wrapper to rerun the heavier Gradle gates instead of only checking
their configured entrypoints.

For the v0.4 Android/Server commercial pilot track, run the aggregate
public-safe readiness gate:

```bash
./scripts/verify-v0.4-release-readiness.sh
```

It composes the clean OEM ledger, Android matrix readiness, Maven Central
readiness, backend wrapper mock HTTP smoke, and optional Gradle/consumer gates.
Real provider material, Maven Central credentials, and non-public customer
pilot inputs are reported as blockers instead of being printed or embedded.

The attestation preflight is no-contact by default. It verifies the public
SDK/sample bridge, the optional private server verifier contract, package and
certificate binding, request-hash binding, and evidence-only handshake defaults:

```bash
python3 scripts/verify-v0.4-attestation-real-smoke-preflight.py \
  --output-dir /tmp/leona-v0.4-attestation-preflight
```

Real Play Integrity smoke additionally requires a cloud project number,
package name, certificate SHA-256 allowlist, mode-0600 Application Default
Credentials JSON, and a mode-0600 device token artifact. Both private files
must be outside the repository. The report records blocker codes and hashes,
not credential values, token contents, or private paths. OEM provider material
uses the corresponding private allowlist/namespace/verifier/device bridge.

After a release is published, run the public consumption smoke:

```bash
LEONA_TARGET_RELEASE_VERSION=0.4.0 ./scripts/verify-v0.4-post-release-consumption.sh
```

By default the v0.4 wrapper records `blocked-release-not-published` until the
real tag workflow has published artifacts. After the release exists, it
downloads the GitHub Release AAR and `.sha256`, then verifies the checksum. If
you also need to validate the GitHub Packages Maven path, provide a token with
package read permission and make the check strict:

```bash
LEONA_GITHUB_PACKAGES_TOKEN=read_packages_token \
  LEONA_TARGET_RELEASE_VERSION=0.4.0 \
  LEONA_REQUIRE_POST_RELEASE_CONSUMPTION=1 \
  ./scripts/verify-v0.4-post-release-consumption.sh
```

Do not commit this token or bake it into Gradle files. Keep it in CI secrets,
developer environment variables, or your dependency-management secret store.

Customer backend wrapper requirements are tracked in
[`docs/backend-wrapper-contract.md`](docs/backend-wrapper-contract.md). Wrapper
libraries are server-side only: they sign requests, fetch evidence reports,
submit feedback labels, and redact support exports. They must not run inside an
Android app or produce business `allow` / `reject` / `block` decisions.

The public-safe wrapper skeletons live under [`wrappers/`](wrappers/). Run:

```bash
./scripts/verify-backend-wrapper-skeletons.sh
```

The v0.4 Android evidence and privacy boundary is documented in
[`docs/v0.4-evidence-privacy-boundary.md`](docs/v0.4-evidence-privacy-boundary.md).
It defines the evidence-only contract, redaction rules, backend-wrapper
boundary, and external blocker handling for the Android/Server commercial pilot
track.

The public-safe release-note draft for the same track is
[`docs/v0.4-release-notes-draft.md`](docs/v0.4-release-notes-draft.md). It lists
completed local gates, explicit external blockers, privacy rules, and non-goals
that must be reviewed again before a real tag.

The v0.4 Android release checklist is
[`docs/v0.4-release-checklist.md`](docs/v0.4-release-checklist.md). It is the
public-safe pre-tag review entrypoint for local gates, optional heavy gates,
external blockers, artifact paths, and post-release consumption smoke.

The v0.4 tag release runbook is
[`docs/v0.4-tag-release-runbook.md`](docs/v0.4-tag-release-runbook.md). It
documents the exact public-safe order for version alignment, local candidate
review, annotated tag push, GitHub workflow verification, and post-release
consumption smoke.

The public archive dry-run is:

```bash
./scripts/verify-v0.4-public-archive.sh
```

It creates a temporary public Android SDK archive and manifest summary without
writing release artifacts back into the repository.

To validate the archive as a consumer would receive it, run:

```bash
./scripts/verify-v0.4-public-archive-consumer.sh
```

It generates or accepts a public archive, extracts it under `/tmp`, checks the
required public Android files, rejects private/server/iOS/Web/homepage roots,
checks archived shell-script syntax, and scans the extracted artifact for
forbidden public-boundary material.

## Android 6 through Android 16 compatibility

The public build contract covers Android 6.0 / API 23 through Android 16 /
API 36. The SDK and sample compile against API 36, the sample targets API 36,
and the public SDK keeps `minSdk = 21` so existing integrations are not raised
above the declared API 23 compatibility matrix floor.

Build compatibility and runtime acceptance are intentionally separate. Run
the build-contract and fail-closed manifest checks with:

```bash
python3 -m unittest discover -v -s scripts/tests -p 'test_*.py'
python3 scripts/verify-android-6-16-compatibility.py \
  --android-sdk-root "$ANDROID_HOME" \
  --output-dir /tmp/leona-android-6-16-build-contract
```

That command may report `build-pass-runtime-incomplete`; a successful Gradle
build never creates runtime evidence. Full acceptance requires a redacted
runtime manifest with exactly one fresh, collection-timestamp-bound,
hash-verified, direct `sense()` and report sample for every API from 23 through
36. Every sample must carry the same valid APK SHA-256 so a mixed-candidate
matrix fails closed. Build that manifest only from
the redacted importer summaries (repeat `--sample` for each API):

```bash
python3 scripts/build-android-6-16-runtime-manifest.py \
  --sample 23=/path/to/api23-import/summary.json \
  --sample 36=/path/to/api36-import/summary.json \
  --require-complete \
  --output-dir /tmp/leona-android-6-16-runtime-manifest
```

Without `--require-complete`, the builder stays `partial` until all 14 APIs are
supplied. It rejects samples that do not prove a direct trigger, verified
report, valid APK SHA-256, and one identical candidate across the matrix. Then
run strict acceptance:

```bash
python3 scripts/verify-android-6-16-compatibility.py \
  --android-sdk-root "$ANDROID_HOME" \
  --runtime-evidence /tmp/leona-android-6-16-runtime-manifest/runtime-evidence.json \
  --strict-runtime \
  --output-dir /tmp/leona-android-6-16-strict
```

When a redacted physical/OEM closure summary is available, independently bind
it to that complete API 23-36 candidate:

```bash
python3 scripts/verify-android-physical-oem-closure.py \
  --physical-summary /path/to/redacted-physical-summary.json \
  --runtime-evidence /tmp/leona-android-6-16-runtime-manifest/runtime-evidence.json \
  --output-dir /tmp/leona-android-physical-oem-closure
```

The physical closure verifier requires at least two distinct OEMs and two API
levels, direct `sense()` plus verified report transport, hash-only BoxIds,
redaction flags, and the same APK SHA-256 as all 14 runtime rows. It fails
closed on raw identifiers or mixed candidates. This is runtime compatibility
evidence only; it does not make a customer business decision or claim
commercial admission.

The aggregate readiness wrapper can run both strict gates together:

```bash
LEONA_ANDROID_6_16_RUNTIME_EVIDENCE=/path/to/runtime-evidence.json \
LEONA_ANDROID_PHYSICAL_OEM_CLOSURE_SUMMARY=/path/to/redacted-physical-summary.json \
LEONA_REQUIRE_ANDROID_6_16_RUNTIME=1 \
  ./scripts/verify-v0.4-release-readiness.sh
```

The compatibility contract is stored in
[`compatibility/android-6-16-contract.json`](compatibility/android-6-16-contract.json).
It preserves the product boundary: the Android SDK only collects and reports
evidence; the customer backend owns all final business decisions.

The public repository also contains a separately triggered GitHub-hosted
boundary runtime workflow in
[`../.github/workflows/android-cloud-runtime.yml`](../.github/workflows/android-cloud-runtime.yml).
It builds one short-lived `cloudTest` APK candidate, runs direct `sense()` and
public-hosted report transport on Google APIs x86_64 AVDs at API 23 and API 36,
and uploads only redacted, hash-bound evidence. The fixture returns opaque
identifiers but never an allow/deny decision, its credentials are generated
ephemerally, and neither the APK nor the private environment file is uploaded.

This boundary workflow strengthens Android 6/16 runtime coverage; it does not
replace the complete API 23-36 matrix, clean physical/OEM coverage, Play
Integrity or OEM attestation, and it never claims commercial admission.

After downloading the workflow artifact, consume the two API directories with
the normal matrix readiness gate instead of trusting the uploaded summary:

```bash
LEONA_GITHUB_HOSTED_RUNTIME_ROOT=/path/to/leona-github-cloud-runtime \
  ./scripts/verify-v0.4-android-matrix-readiness.sh
```

The gate reruns the fail-closed same-candidate verifier and records
`github_hosted_boundary_runtime=pass`, while explicitly keeping
`countsTowardFullExternalMatrix=false`.

The Android tag publish workflow dry-run is:

```bash
./scripts/verify-v0.4-publish-workflow-dry-run.sh
```

It checks the public GitHub Actions tag workflow structure for release AAR and
`.sha256` assets, GitHub Packages publishing, required permissions, and absence
of non-public provider/customer/Central secrets. It does not trigger a GitHub
workflow, create a tag, or publish artifacts.

For a single pre-tag summary that composes the local readiness gate, public
archive consumer smoke, publish workflow dry-run, public commit scope gate, and
public release batch planner, run:

```bash
./scripts/verify-v0.4-release-candidate-manifest.sh
```

It writes a release-candidate manifest under `/tmp`, records component summary
paths, public release batch counts, do-not-stage counts, and external blockers,
and writes `release-evidence-pack.md` / `release-evidence-pack.json` with
component summary SHA-256 digests, byte counts, redaction scan status, and
before/after git index snapshots. The redaction scan covers component summaries,
git index snapshots, and the generated evidence pack Markdown/JSON itself. It
then runs `verify-v0.4-release-evidence-pack-schema.py` against the generated
JSON to validate required fields, expected components, file SHA-256/byte counts,
and Markdown/JSON parity. The schema gate is structural; it does not treat
`redactionScan=failed` as a schema failure, so synthetic redaction tests still
fail only on the redaction gate. The manifest fails if the staged index changes
during the full candidate run. It still does not create a tag, trigger GitHub
Actions, publish artifacts, execute real `git add`, stage files, start paid
devices, or print secrets.

To prove the generated-pack redaction path fails closed, run the same manifest
with `LEONA_RC_SELF_SCAN_TEST=1`. That mode injects a synthetic marker into the
temporary generated Markdown pack and should fail only the evidence pack
redaction scan while still preserving the git index.

For the final tag check, set `LEONA_REQUIRE_PRETAG_READY=1` so the manifest
fails if version-alignment blockers remain.

To run the manifest and its schema gate together, use the read-only review
wrapper:

```bash
./scripts/verify-v0.4-release-candidate-review.sh
```

The wrapper writes one summary that points at the generated manifest summary
and schema summary. It preserves the underlying manifest exit behavior, so
strict pre-tag mode still fails while `VERSION_NAME` has not been bumped to the
target release. It does not create tags, trigger GitHub Actions, publish
artifacts, execute `git add`, start devices, or print secrets.

Validate the wrapper summary shape separately when reviewing generated release
evidence:

```bash
./scripts/verify-v0.4-release-candidate-review-schema.py /tmp/<review-report>/summary.md
```

The review schema gate checks manifest/schema summary paths, failure semantics,
and the no-tag/no-publish/no-stage/no-device guarantees without staging files or
publishing artifacts.

For the final local pre-tag review command, run the review wrapper and review
schema gate together:

```bash
./scripts/verify-v0.4-release-candidate-final-review.sh
```

The final review wrapper preserves the underlying review exit behavior, so
strict pre-tag mode still fails while version blockers remain, and
synthetic-negative redaction tests still fail closed. It does not create tags,
trigger GitHub Actions, publish artifacts, execute `git add`, start devices, or
print secrets.

Validate the final review summary shape separately when archiving a pre-tag
review:

```bash
./scripts/verify-v0.4-release-candidate-final-review-schema.py /tmp/<final-review-report>/summary.md
```

The final review schema gate checks the nested review/schema summary paths,
wrapper failure semantics, and the no-tag/no-publish/no-stage/no-device
guarantees without staging files or publishing artifacts.

Before applying the real version bump, generate a read-only bump plan:

```bash
./scripts/verify-v0.4-version-bump-plan.py
```

It lists the required runtime marker files, optional sample/docs preview
markers, replacement counts, current SHA-256 digests, and planned SHA-256
digests for `0.4.0`. It does not edit files, stage paths, create tags, publish
artifacts, start devices, or print secrets. The release candidate manifest also
includes this plan in the local evidence pack so the tag commit can be reviewed
before the actual version bump is applied.

To prove the planned replacements converge without writing patched files, run:

```bash
./scripts/verify-v0.4-version-bump-dry-run.py
```

It applies the planned public Android marker replacements in memory and checks
that required `VERSION_NAME`, runtime, and sample markers converge to `0.4.0`.
It does not edit files, stage paths, create tags, publish artifacts, start
devices, or print secrets.

Before staging a public Android SDK commit from a mixed local workspace, run:

```bash
./scripts/verify-v0.4-public-commit-scope.sh
```

It checks that staged paths stay inside the public Android commit boundary and
reports non-public dirty paths such as iOS, Web, server, homepage, deployment,
policy, private detector, and internal-doc work so they are not included in a
public GitHub commit. By default, non-public unstaged or untracked paths are
reported as blockers to keep out of the commit; set
`LEONA_REQUIRE_PUBLIC_COMMIT_CLEAN=1` when you need a strict all-clean public
scope gate.

To generate a reviewable public Android release batch plan without staging
anything, run:

```bash
./scripts/verify-v0.4-public-release-batch.sh
```

It writes public candidate paths, do-not-stage paths, staged forbidden paths,
the extracted stage-command draft paths, and a stage-command draft under
`/tmp`. The verifier checks that the generated draft is parseable, exactly
matches the public batch path list, excludes every do-not-stage path, and
records SHA-256 digests for the reviewed path lists. It also runs the draft in
`LEONA_ANDROID_STAGE_DRY_RUN=1` mode and confirms `git add --dry-run` preserves
the git index. It never performs real staging, commits, tags, publishes, starts
devices, or prints secrets.

To independently validate that generated batch plan, run:

```bash
./scripts/verify-v0.4-public-release-batch-schema.py /tmp/<batch-report>/summary.md
```

The schema gate checks path-list parity, SHA-256 digests, do-not-stage
exclusion, forbidden public prefixes, and dry-run git index preservation. It is
also included in the aggregate readiness gate and release candidate manifest.

To independently validate a generated release candidate manifest summary, run:

```bash
./scripts/verify-v0.4-release-candidate-manifest-schema.py /tmp/<rc-report>/summary.md
```

The schema gate checks component summary paths, no-tag/no-publish/no-stage
guarantees, evidence pack schema status, public release batch fields, git index
preservation, and version-blocker semantics. It is read-only and does not
create tags, trigger GitHub Actions, publish artifacts, execute `git add`, start
devices, or print secrets.

The Android SDK changelog is maintained in [`CHANGELOG.md`](CHANGELOG.md). It
records public-safe SDK distribution changes only, and keeps credentials,
complete BoxIds, raw device identifiers, server implementation details, and
customer-specific policy out of the public release surface.

`v0.4.0` keeps the evidence-only SDK contract and adds Device Evidence Graph
release gates, Android matrix readiness checks, customer evidence report
contracts, feedback-loop gates, release evidence-pack validation, and stricter
public release review wrappers. Real custom ROM/GSI/unlocked-device samples,
broader external emulator templates, and real Play Integrity/OEM provider
smoke remain tracked as external-input follow-ups.

## Install from GitHub Release

GitHub Release AAR downloads remain supported as a fallback. Download
`leona-sdk-android-0.4.0.aar` from the GitHub Release and place it in your app
module, for example `app/libs/leona-sdk-android-0.4.0.aar`.

```kotlin
// app/build.gradle.kts
dependencies {
    implementation(files("libs/leona-sdk-android-0.4.0.aar"))

    // Transitive dependencies required by the public AAR.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
}
```

The host app must request network access:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
```

## Quick start

```kotlin
// Application.onCreate()
Leona.init(this, LeonaConfig.Builder()
    .apiKey("your-leona-api-key")
    .reportingEndpoint("https://leona.xiyanshan.com")
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

### Public hosted reporting mode

The public AAR can obtain a BoxId without packaging `:sdk-private-core`. When
`reportingEndpoint` and `apiKey` are configured and the closed-source secure
engine is absent, `SecureChannel` uses public hosted reporting mode:

- `POST <reportingEndpoint>/v1/sense/public`
- Header `X-Leona-App-Key: <your-leona-api-key>`
- Header `X-Leona-Reporting-Mode: public_hosted`
- JSON body containing an opaque base64 native payload, hashed device identity
  fields, and low-trust evidence metadata.

If `reportingEndpoint` already ends with `/v1` or `/v1/sense`, the SDK resolves
the public hosted path to `/v1/sense/public`. The hosted API returns an opaque
`boxId`, and may also return `canonicalDeviceId` plus evidence summary fields.
The client still does not make allow/reject/block decisions; your backend must
query `/v1/verdict` with the SecretKey and apply its own business policy.

Public hosted reporting does not require the APK to sign uploads with the
device wall clock. `serverTimeMillis` / `serverClockOffsetMillis` are private
signed-transport diagnostics, not public hosted response fields. If
your backend query receives a timestamp-related error, treat it as a
transport/authentication issue and retry with a fresh backend timestamp; do not
interpret it as device risk evidence.

Advanced private secure transport, attestation binding, encrypted sessions,
hosted policy baselines, and private detector catalogs remain closed-source.
Deployments that require those features should include the private runtime or
use Leona hosted service support for the public mode above.

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

// Your backend calls Leona's API with boxId and gets the environment evidence report.
```

## Backend: query device evidence by BoxId

The mobile app only forwards the opaque `BoxId`. The customer's backend owns
the server-side query and business decision.

```text
App -> your backend: login/payment/API request with leonaBoxId
Your backend -> Leona: POST /v1/verdict with tenant SecretKey
Leona -> your backend: deviceFingerprint, canonicalDeviceId, events, provenance
Your backend -> product: allow/challenge/deny according to your own policy
```

Use different keys for the two sides:

- `LEONA_API_KEY` / AppKey goes into the Android app and is used by the SDK to
  upload evidence.
- `LEONA_SECRET_KEY` stays only on your backend and is used to query evidence
  for a BoxId.

`POST /v1/verdict`:

```http
POST https://leona.xiyanshan.com/v1/verdict
Authorization: Bearer <LEONA_SECRET_KEY>
Content-Type: application/json
X-Leona-Timestamp: <unix-time-ms>
X-Leona-Nonce: <random-nonce>
X-Leona-Signature: <base64url-hmac-sha256>

{"boxId":"<BOX_ID_FROM_APP>"}
```

Signature:

```text
signingText = timestamp + "\n" + nonce + "\n" + sha256(requestBody)
signature = base64url_no_padding(HMAC-SHA256(secretKey, signingText))
```

Node.js example:

```js
import crypto from "node:crypto";

async function queryLeonaEvidence(boxId) {
  const endpoint = "https://leona.xiyanshan.com/v1/verdict";
  const secret = process.env.LEONA_SECRET_KEY;
  const body = JSON.stringify({ boxId });
  const timestamp = Date.now().toString();
  const nonce = crypto.randomBytes(16).toString("base64url");
  const bodySha256 = crypto.createHash("sha256").update(body).digest("hex");
  const signingText = `${timestamp}\n${nonce}\n${bodySha256}`;
  const signature = crypto
    .createHmac("sha256", secret)
    .update(signingText)
    .digest("base64url");

  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${secret}`,
      "Content-Type": "application/json",
      "X-Leona-Timestamp": timestamp,
      "X-Leona-Nonce": nonce,
      "X-Leona-Signature": signature,
    },
    body,
  });

  if (!res.ok) {
    throw new Error(`Leona query failed: ${res.status} ${await res.text()}`);
  }
  return res.json();
}
```

Ready-to-run backend examples are available in
[`../examples/boxid-verdict`](../examples/boxid-verdict) for Python, Java, Go,
C, C++, and Node.js.

Backend cache flow:

```text
Leona.sense()
  -> app sends BoxId to customer backend
  -> backend checks its login/order/payment/risk record cache
  -> cache miss: backend signs POST /v1/verdict with SecretKey
  -> backend stores the returned evidence report before making a business action
  -> retries/audits read the cached report instead of reusing the consumed BoxId
```

Representative response shape:

```json
{
  "boxId": "<BOX_ID_FROM_APP>",
  "deviceFingerprint": "fp_...",
  "canonicalDeviceId": "L...",
  "risk": {
    "level": "clean",
    "score": 0,
    "reasons": []
  },
  "events": [
    {
      "id": "environment.emulator.detected",
      "category": "ENVIRONMENT",
      "severity": "MEDIUM",
      "evidence": {
        "source": "native_payload",
        "trust": "authoritative"
      }
    }
  ],
  "authoritativeRiskTags": [],
  "telemetryRiskTags": [],
  "riskTagsBySource": {},
  "provenance": {},
  "policyExplanation": {}
}
```

Important semantics:

- `decision` is always neutral compatibility data. Leona does not tell your
  business to allow, reject, or block.
- `events` are the raw evidence details your backend should persist with the
  related login/order/payment/risk record.
- `authoritativeRiskTags` come from server/native authoritative sources.
- `telemetryRiskTags` and `riskTagsBySource.client_header` are low-trust
  context for explanation and debugging.
- `/v1/verdict` is single-use. A successful query consumes the BoxId; repeated
  calls return `410 LEONA_BOX_ALREADY_USED`. Cache the returned report in your
  own backend if you need to read it again.

Customer integration checklist:

- Android SDK receives only the Leona AppKey and reporting endpoint.
- Backend stores the Leona SecretKey outside the APK and signs verdict queries.
- App forwards only the opaque `BoxId` to the backend.
- Backend caches the first successful `/v1/verdict` report with its own business record.
- Backend treats `410 LEONA_BOX_ALREADY_USED` as an idempotency/cache condition.
- Backend owns allow/challenge/deny/manual-review policy; Leona provides evidence, not final business decisions.

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
// deviceId / fingerprint / evidenceSignals / nativeFactTags / nativeFindingIds

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

`0.4.0` keeps the public Android SDK integration surface stable while adding
Device Evidence Graph release gates, Android matrix readiness checks, customer
evidence report contracts, feedback-loop gates, release evidence-pack
validation, and stricter public release review wrappers. The SDK is ready for
hosted Leona API integration, while advanced private detectors and hosted
policy remain closed-source.

- The SDK already contains the native detection path, JNI bridge, payload
  format, and the Kotlin-side secure upload implementation.
- The public sample app is intended to run with a Leona-issued API key and
  Leona hosted endpoints.
- Device/environment evidence, tenant settings, and data persistence are
  handled by the Leona API/backend. The Android client collects and reports
  signals; Leona itself does not make the final business decision.

## Public SDK vs closed-source runtime

This repository publishes the Android public integration SDK only. Customers
can integrate the SDK into their APK and use it in production, but the open
source checkout must be configured with Leona API/backend access to obtain
device/environment evidence reports.

For security reasons, this public repository does not include:

- Leona hosted API/backend implementation
- private detector catalogs and native runtime internals
- risk scoring weights and tenant policy execution
- internal operations, deployment, and release automation

## What v0.1.0 detects

| Category | Check | Note |
|----------|-------|------|
| Injection | `TracerPid` in `/proc/self/status` | ptrace attach |
| Injection | `frida-gadget` / `frida-agent` as mapped library | weak signal, corroboration only |
| Injection | **Frida trampoline machine-code pattern** (ARM64) | Leona's core signal |
| Environment | Emulator system-property heuristic | QEMU, Genymotion, etc. |
| **Unidbg** | CNTVCT_EL0 / CNTFRQ_EL0 timing coherence | **Included in v0.1.0** |
| **Unidbg** | Parent process non-zygote | **Included in v0.1.0** |
| **Unidbg** | `/proc/cpuinfo` shape | **Included in v0.1.0** |

## Roadmap — what's coming

**v0.2.0**:
- GitHub Packages Maven publishing for `io.leonasec:leona-sdk-android`
- GitHub Release AAR + sha256 fallback remains available
- Evidence-only client posture remains unchanged; backend policy owns decisions

**v0.3.0**:
- Android API 23-30 compatibility diagnostics
- Cloud-phone, HMA, Magisk, Zygisk, and Xposed evidence provenance validation
- Attestation provider dry-run reporting

**v0.4.0+**:
- Real custom ROM, GSI, unlocked-device, and broader external emulator samples
- Real Play Integrity/OEM provider smoke with production-like provider material
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

Cloud config is a control-plane input because it can tune collection policy. The
SDK only trusts HTTPS cloud config endpoints; HTTP endpoints are ignored for
cloud config even when they are useful for local upload/evidence-report testing.
Canonical device identity is only persisted from the secure reporting server,
not from mobile-config responses.

The public SDK requires Leona hosted API/backend access for environment evidence
reports. It does not ship a self-hosted production backend.

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
