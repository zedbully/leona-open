plugins {
    alias(libs.plugins.android.library)
}

val leoCryptoAarPath = providers.gradleProperty("LEONA_CRYPTO_AAR")
    .orElse(providers.environmentVariable("LEONA_CRYPTO_AAR"))
    .orElse("")
    .get()
    .trim()
val leoCryptoAar = file(leoCryptoAarPath)
require(leoCryptoAar.isFile) {
    "LEONA_CRYPTO_AAR must point to the external Leo Android facade AAR"
}

group = "io.leonasec"
version = providers.gradleProperty("VERSION_NAME").orElse("0.0.0-crypto-adapter").get()

android {
    namespace = "io.leonasec.leona.crypto.leofacade"
    compileSdk = 36

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            kotlin.directories += "src/main/kotlin"
        }
        getByName("test") {
            kotlin.directories += "src/test/kotlin"
        }
    }
}

kotlin {
    compilerOptions {
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_0)
        freeCompilerArgs.addAll("-Xjvm-default=all")
    }
}

dependencies {
    api(project(":sdk"))
    implementation(libs.okhttp)
    // compileOnly is deliberate: the application must add the exact external
    // AAR so its JNI DSO is packaged and can be upgraded independently.
    compileOnly(files(leoCryptoAar))
    compileOnly("org.jetbrains.kotlin:kotlin-stdlib:1.9.24")
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.okhttp.tls)
}
