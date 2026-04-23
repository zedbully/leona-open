plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

val leonaApiKey = providers.gradleProperty("LEONA_API_KEY").orElse("").get()
val leonaReportingEndpoint = providers.gradleProperty("LEONA_REPORTING_ENDPOINT").orElse("").get()
val leonaCloudConfigEndpoint = providers.gradleProperty("LEONA_CLOUD_CONFIG_ENDPOINT").orElse("").get()
val leonaDemoBackendBaseUrl = providers.gradleProperty("LEONA_DEMO_BACKEND_BASE_URL").orElse("").get()

android {
    namespace = "io.leonasec.leona.sample"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.leonasec.leona.sample"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0-alpha.1"
        buildConfigField("String", "LEONA_API_KEY", "\"$leonaApiKey\"")
        buildConfigField("String", "LEONA_REPORTING_ENDPOINT", "\"$leonaReportingEndpoint\"")
        buildConfigField("String", "LEONA_CLOUD_CONFIG_ENDPOINT", "\"$leonaCloudConfigEndpoint\"")
        buildConfigField("String", "LEONA_DEMO_BACKEND_BASE_URL", "\"$leonaDemoBackendBaseUrl\"")

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
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            isMinifyEnabled = false
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

dependencies {
    implementation(project(":sdk"))
    findProject(":sdk-private-core")?.let { implementation(it) }

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)
}
