plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

val leonaApiKey = providers.gradleProperty("LEONA_API_KEY").orElse("").get()
val leonaTenantId = providers.gradleProperty("LEONA_TENANT_ID").orElse("sample").get()
val leonaReportingEndpoint = providers.gradleProperty("LEONA_REPORTING_ENDPOINT").orElse("").get()
val leonaCloudConfigEndpoint = providers.gradleProperty("LEONA_CLOUD_CONFIG_ENDPOINT").orElse("").get()
val leonaDemoBackendBaseUrl = providers.gradleProperty("LEONA_DEMO_BACKEND_BASE_URL").orElse("").get()
val leonaE2EToken = providers.gradleProperty("LEONA_E2E_TOKEN").orElse("").get()
val leonaSampleAttestationMode = providers.gradleProperty("LEONA_SAMPLE_ATTESTATION_MODE").orElse("off").get()
val leonaSamplePlayIntegrityCloudProjectNumber =
    providers.gradleProperty("LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER").orElse("").get()
val leonaSampleEnableRealPlayIntegrityDep =
    providers.gradleProperty("LEONA_SAMPLE_ENABLE_REAL_PLAY_INTEGRITY_DEP").orElse("false").get().toBoolean()

fun String.quoted(): String = "\"${replace("\\", "\\\\").replace("\"", "\\\"")}\""

val debugOnlySampleProperties = mapOf(
    "LEONA_API_KEY" to leonaApiKey,
    "LEONA_E2E_TOKEN" to leonaE2EToken,
    "LEONA_SAMPLE_ATTESTATION_MODE" to leonaSampleAttestationMode,
)

tasks.register("guardSampleReleaseBuild") {
    group = "verification"
    description = "Fail sample release builds that would embed debug/test-only configuration."
    doLast {
        val unsafe = debugOnlySampleProperties.filterValues { value -> value.isNotBlank() && value != "off" }
        if (unsafe.isNotEmpty()) {
            throw GradleException(
                "sample-app release must not embed debug/test-only Gradle properties: " +
                    unsafe.keys.sorted().joinToString(", "),
            )
        }
    }
}

android {
    namespace = "io.leonasec.leona.sample"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.leonasec.leona.sample"
        minSdk = if (leonaSampleEnableRealPlayIntegrityDep) 23 else 21
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-alpha.1"
        buildConfigField("String", "LEONA_API_KEY", "\"\"")
        buildConfigField("String", "LEONA_TENANT_ID", "sample".quoted())
        buildConfigField("String", "LEONA_REPORTING_ENDPOINT", "\"\"")
        buildConfigField("String", "LEONA_CLOUD_CONFIG_ENDPOINT", "\"\"")
        buildConfigField("String", "LEONA_DEMO_BACKEND_BASE_URL", "\"\"")
        buildConfigField("String", "LEONA_E2E_TOKEN", "\"\"")
        buildConfigField("String", "LEONA_SAMPLE_ATTESTATION_MODE", "\"off\"")
        buildConfigField("Boolean", "LEONA_VERBOSE_NATIVE_LOGGING", "false")
        buildConfigField(
            "String",
            "LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
            "\"\"",
        )

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
            buildConfigField("String", "LEONA_DEMO_BACKEND_BASE_URL", leonaDemoBackendBaseUrl.quoted())
            buildConfigField("String", "LEONA_E2E_TOKEN", leonaE2EToken.quoted())
            buildConfigField("String", "LEONA_SAMPLE_ATTESTATION_MODE", leonaSampleAttestationMode.quoted())
            buildConfigField("Boolean", "LEONA_VERBOSE_NATIVE_LOGGING", "true")
            buildConfigField(
                "String",
                "LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER",
                leonaSamplePlayIntegrityCloudProjectNumber.quoted(),
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        buildConfig = true
        viewBinding = true
    }

    sourceSets {
        getByName("main") {
            kotlin.srcDirs("src/main/kotlin")
        }
    }
}

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn("guardSampleReleaseBuild")
}

dependencies {
    implementation(project(":sdk"))
    findProject(":sdk-private-core")?.let { implementation(it) }

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
    if (leonaSampleEnableRealPlayIntegrityDep) {
        implementation("com.google.android.play:integrity:1.6.0")
    }

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.mockito.core)
}
