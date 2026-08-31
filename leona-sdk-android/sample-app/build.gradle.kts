import com.android.build.api.variant.HasUnitTestBuilder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import javax.inject.Inject
import org.gradle.api.configuration.BuildFeatures

plugins {
    alias(libs.plugins.android.application)
}

abstract class BuildFeaturesAccessor @Inject constructor(
    val buildFeatures: BuildFeatures,
)

val leonaBuildFeatures = objects.newInstance(BuildFeaturesAccessor::class.java).buildFeatures

val leonaApiKey = providers.gradleProperty("LEONA_API_KEY").orElse("").get()
val leonaTenantId = providers.gradleProperty("LEONA_TENANT_ID").orElse("sample").get()
val leonaReportingEndpoint = providers.gradleProperty("LEONA_REPORTING_ENDPOINT").orElse("").get()
val leonaCloudConfigEndpoint = providers.gradleProperty("LEONA_CLOUD_CONFIG_ENDPOINT").orElse("").get()
val leonaE2EToken = providers.gradleProperty("LEONA_E2E_TOKEN").orElse("").get()
val leonaCloudTestToken = providers.gradleProperty("LEONA_CLOUD_TEST_TOKEN").orElse("").get()
val leonaSampleAttestationMode = providers.gradleProperty("LEONA_SAMPLE_ATTESTATION_MODE").orElse("off").get()
val leonaSamplePlayIntegrityCloudProjectNumber =
    providers.gradleProperty("LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER").orElse("").get()
val leonaSampleEnableRealPlayIntegrityDep =
    providers.gradleProperty("LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP").orElse("false").get().toBoolean()
val leonaSampleHuaweiAppId =
    providers.gradleProperty("LEONA_SAMPLE_HUAWEI_APP_ID").orElse("").get()
val leonaSampleHuaweiAppIdFile =
    providers.environmentVariable("LEONA_SAMPLE_HUAWEI_APP_ID_FILE").orElse("").get()
val huaweiReleaseTaskRequested =
    gradle.startParameter.taskNames.any { taskName ->
        taskName.contains("HuaweiRelease", ignoreCase = true)
    }
val leonaPrivateCoreIncluded = findProject(":sdk-private-core") != null

if (huaweiReleaseTaskRequested && leonaBuildFeatures.configurationCache.active.get()) {
    throw GradleException(
        "Huawei release requires --no-configuration-cache so private App ID material is not persisted",
    )
}

fun String.quoted(): String = "\"${replace("\\", "\\\\").replace("\"", "\\\"")}\""

fun loadPrivateHuaweiAppId(): String {
    if (!huaweiReleaseTaskRequested) return ""
    if (leonaSampleHuaweiAppIdFile.isBlank()) {
        throw GradleException("Huawei release requires LEONA_SAMPLE_HUAWEI_APP_ID_FILE")
    }
    val requested = Path.of(leonaSampleHuaweiAppIdFile)
    if (!requested.isAbsolute || Files.isSymbolicLink(requested)) {
        throw GradleException("Huawei App ID input path must be an absolute non-symlink")
    }
    val path = try {
        requested.toRealPath()
    } catch (error: Exception) {
        throw GradleException("Huawei App ID input is unavailable", error)
    }
    if (!Files.isRegularFile(path) || path.startsWith(rootDir.toPath().toRealPath())) {
        throw GradleException("Huawei App ID input must be a private file outside the repository")
    }
    val permissions = try {
        Files.getPosixFilePermissions(path)
    } catch (error: Exception) {
        throw GradleException("Huawei App ID input permissions are unavailable", error)
    }
    if (permissions != setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)) {
        throw GradleException("Huawei App ID input must use mode 0600")
    }
    val links = try {
        (Files.getAttribute(path, "unix:nlink") as Number).toLong()
    } catch (error: Exception) {
        throw GradleException("Huawei App ID input link count is unavailable", error)
    }
    if (links != 1L) {
        throw GradleException("Huawei App ID input must not be hard-linked")
    }
    val raw = Files.readString(path)
    val value = raw.trim()
    if (raw != "$value\n" || !Regex("[A-Za-z0-9._-]{1,128}").matches(value)) {
        throw GradleException("Huawei App ID input must contain one canonical value")
    }
    return value
}

val leonaSampleHuaweiReleaseAppId = loadPrivateHuaweiAppId()

tasks.register("guardSampleReleaseBuild") {
    group = "verification"
    description = "Fail sample release builds that would embed debug/test-only configuration."
    inputs.property("leonaApiKey", leonaApiKey)
    inputs.property("leonaE2EToken", leonaE2EToken)
    inputs.property("leonaCloudTestToken", leonaCloudTestToken)
    inputs.property("leonaSampleAttestationMode", leonaSampleAttestationMode)
    inputs.property("leonaSampleHuaweiAppId", leonaSampleHuaweiAppId)
    doLast {
        val debugOnlySampleProperties = mapOf(
            "LEONA_API_KEY" to inputs.properties["leonaApiKey"]?.toString().orEmpty(),
            "LEONA_E2E_TOKEN" to inputs.properties["leonaE2EToken"]?.toString().orEmpty(),
            "LEONA_CLOUD_TEST_TOKEN" to inputs.properties["leonaCloudTestToken"]?.toString().orEmpty(),
            "LEONA_SAMPLE_ATTESTATION_MODE" to inputs.properties["leonaSampleAttestationMode"]?.toString().orEmpty(),
            "LEONA_SAMPLE_HUAWEI_APP_ID" to inputs.properties["leonaSampleHuaweiAppId"]?.toString().orEmpty(),
        )
        val unsafe = debugOnlySampleProperties.filterValues { value -> value.isNotBlank() && value != "off" }
        if (unsafe.isNotEmpty()) {
            throw GradleException(
                "sample-app release must not embed debug/test-only Gradle properties: " +
                    unsafe.keys.sorted().joinToString(", "),
            )
        }
    }
}

tasks.register("guardSampleHuaweiReleaseBuild") {
    group = "verification"
    description = "Fail Huawei release builds without private provider and release-only inputs."
    inputs.property("huaweiAppIdPresent", leonaSampleHuaweiReleaseAppId.isNotBlank())
    inputs.property("privateCoreIncluded", leonaPrivateCoreIncluded)
    inputs.property("leonaApiKey", leonaApiKey)
    inputs.property("leonaE2EToken", leonaE2EToken)
    inputs.property("leonaCloudTestToken", leonaCloudTestToken)
    inputs.property("playIntegrityDependencyEnabled", leonaSampleEnableRealPlayIntegrityDep)
    doLast {
        if (inputs.properties["huaweiAppIdPresent"] != true) {
            throw GradleException("Huawei release App ID input is unavailable")
        }
        if (inputs.properties["privateCoreIncluded"] != true) {
            throw GradleException("Huawei release requires LEONA_INCLUDE_PRIVATE_CORE=true")
        }
        val unsafe = mapOf(
            "LEONA_API_KEY" to inputs.properties["leonaApiKey"]?.toString().orEmpty(),
            "LEONA_E2E_TOKEN" to inputs.properties["leonaE2EToken"]?.toString().orEmpty(),
            "LEONA_CLOUD_TEST_TOKEN" to inputs.properties["leonaCloudTestToken"]?.toString().orEmpty(),
        ).filterValues { value -> value.isNotBlank() }
        if (unsafe.isNotEmpty()) {
            throw GradleException(
                "Huawei release must not embed debug/test-only properties: " +
                    unsafe.keys.sorted().joinToString(", "),
            )
        }
        if (inputs.properties["playIntegrityDependencyEnabled"] == true) {
            throw GradleException("Huawei release must not include Google Play Integrity")
        }
    }
}

android {
    namespace = "io.leonasec.leona.sample"
    compileSdk = 36
    ndkVersion = "26.3.11579264"

    defaultConfig {
        applicationId = "io.leonasec.leona.sample"
        // The sample exercises the SDK's Android 6/API 23 identity contract.
        minSdk = 23
        targetSdk = 36
        versionCode = 1
        versionName = "0.4.0"
        buildConfigField("String", "LEONA_API_KEY", "\"\"")
        buildConfigField("String", "LEONA_TENANT_ID", "sample".quoted())
        buildConfigField("String", "LEONA_REPORTING_ENDPOINT", "\"\"")
        buildConfigField("String", "LEONA_CLOUD_CONFIG_ENDPOINT", "\"\"")
        buildConfigField("String", "LEONA_E2E_TOKEN", "\"\"")
        buildConfigField("String", "LEONA_CLOUD_TEST_TOKEN", "\"\"")
        buildConfigField("String", "LEONA_SAMPLE_ATTESTATION_MODE", "\"off\"")
        buildConfigField("Boolean", "LEONA_VERBOSE_NATIVE_LOGGING", "false")
        buildConfigField(
            "String",
            "LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
            "\"\"",
        )
        buildConfigField("String", "LEONA_SAMPLE_HUAWEI_APP_ID", "\"\"")

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
        debug {
            isMinifyEnabled = false
            buildConfigField("String", "LEONA_API_KEY", leonaApiKey.quoted())
            buildConfigField("String", "LEONA_TENANT_ID", leonaTenantId.quoted())
            buildConfigField("String", "LEONA_REPORTING_ENDPOINT", leonaReportingEndpoint.quoted())
            buildConfigField("String", "LEONA_CLOUD_CONFIG_ENDPOINT", leonaCloudConfigEndpoint.quoted())
            buildConfigField("String", "LEONA_E2E_TOKEN", leonaE2EToken.quoted())
            buildConfigField("String", "LEONA_CLOUD_TEST_TOKEN", "\"\"")
            buildConfigField("String", "LEONA_SAMPLE_ATTESTATION_MODE", leonaSampleAttestationMode.quoted())
            buildConfigField("Boolean", "LEONA_VERBOSE_NATIVE_LOGGING", "true")
            buildConfigField(
                "String",
                "LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
                leonaSamplePlayIntegrityCloudProjectNumber.quoted(),
            )
            buildConfigField("String", "LEONA_SAMPLE_HUAWEI_APP_ID", leonaSampleHuaweiAppId.quoted())
        }
        create("cloudTest") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            isDebuggable = false
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("debug")
            buildConfigField("String", "LEONA_API_KEY", leonaApiKey.quoted())
            buildConfigField("String", "LEONA_TENANT_ID", leonaTenantId.quoted())
            buildConfigField("String", "LEONA_REPORTING_ENDPOINT", leonaReportingEndpoint.quoted())
            buildConfigField("String", "LEONA_CLOUD_CONFIG_ENDPOINT", leonaCloudConfigEndpoint.quoted())
            buildConfigField("String", "LEONA_E2E_TOKEN", "\"\"")
            buildConfigField("String", "LEONA_CLOUD_TEST_TOKEN", leonaCloudTestToken.quoted())
            buildConfigField("String", "LEONA_SAMPLE_ATTESTATION_MODE", leonaSampleAttestationMode.quoted())
            buildConfigField("Boolean", "LEONA_VERBOSE_NATIVE_LOGGING", "false")
            buildConfigField(
                "String",
                "LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
                leonaSamplePlayIntegrityCloudProjectNumber.quoted(),
            )
            buildConfigField("String", "LEONA_SAMPLE_HUAWEI_APP_ID", leonaSampleHuaweiAppId.quoted())
        }
        create("huaweiRelease") {
            initWith(getByName("release"))
            matchingFallbacks += listOf("release")
            isDebuggable = false
            buildConfigField("String", "LEONA_SAMPLE_ATTESTATION_MODE", "huawei_sysintegrity".quoted())
            buildConfigField("String", "LEONA_SAMPLE_HUAWEI_APP_ID", leonaSampleHuaweiReleaseAppId.quoted())
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    sourceSets {
        getByName("cloudTest") {
            kotlin.directories += listOf("src/release/kotlin", "src/cloudTest/kotlin")
        }
        getByName("huaweiRelease") {
            kotlin.directories += "src/release/kotlin"
        }
    }
}

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn("guardSampleReleaseBuild")
}

tasks.matching { it.name == "preHuaweiReleaseBuild" }.configureEach {
    dependsOn("guardSampleHuaweiReleaseBuild")
}

kotlin {
    compilerOptions {
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_0)
    }
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:1.9.24")
    implementation(project(":sdk"))
    findProject(":sdk-private-core")?.let { implementation(it) }

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    if (leonaSampleEnableRealPlayIntegrityDep) {
        implementation("com.google.android.play:integrity:1.6.0")
    }

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.mockito.core)
}

androidComponents {
    // AGP 9 enables unit tests only for the tested build type by default.
    // cloudTest has contract tests of its own, so keep that variant explicit.
    beforeVariants(selector().withBuildType("cloudTest")) { variantBuilder ->
        (variantBuilder as HasUnitTestBuilder).enableUnitTest = true
    }
}
