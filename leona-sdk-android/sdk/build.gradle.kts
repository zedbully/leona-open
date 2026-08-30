plugins {
    alias(libs.plugins.android.library)
    id("maven-publish")
    id("signing")
}

val releaseTagVersion = providers.environmentVariable("GITHUB_REF_NAME")
    .map { refName -> refName.removePrefix("v") }
    .orNull
    ?.takeIf { version -> Regex("""\d+\.\d+\.\d+([-.][0-9A-Za-z.-]+)?""").matches(version) }
val sdkGroupId = providers.gradleProperty("GROUP").get()
val sdkVersionName = releaseTagVersion ?: providers.gradleProperty("VERSION_NAME").get()

group = sdkGroupId
version = sdkVersionName

android {
    namespace = "io.leonasec.leona"
    compileSdk = 36
    ndkVersion = "26.3.11579264"

    defaultConfig {
        // Android 6/API 23 is the identity-storage compatibility floor.
        // Do not lower this until a formally verified Provider contract exists.
        minSdk = 23

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            // Target 64-bit ABIs only. 32-bit Android is legacy.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++17", "-fvisibility=hidden")
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    sourceSets {
        getByName("main") {
            kotlin.directories += "src/main/kotlin"
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }
}

kotlin {
    compilerOptions {
        // AGP 9.3 ships Kotlin 2.2. Compile public metadata at language level
        // 2.0 so existing Kotlin 1.9 applications remain binary consumers.
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_0)
        freeCompilerArgs.addAll(
            "-Xjvm-default=all",
            "-opt-in=kotlin.RequiresOptIn",
        )
    }
}

dependencies {
    api("org.jetbrains.kotlin:kotlin-stdlib:1.9.24")
    implementation(libs.androidx.core.ktx)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.okhttp)

    testImplementation(libs.junit)
    testImplementation(libs.mockito.core)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.json)

    androidTestImplementation(libs.androidx.test.ext)
    androidTestImplementation(libs.androidx.test.espresso)
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = sdkGroupId
            artifactId = "leona-sdk-android"
            version = sdkVersionName

            pom {
                name.set("Leona Android SDK")
                description.set("Public Android SDK for device environment evidence collection.")
                url.set("https://github.com/zedbully/leona-open")
                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("leona")
                        name.set("Leona Contributors")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/zedbully/leona-open.git")
                    developerConnection.set("scm:git:ssh://git@github.com/zedbully/leona-open.git")
                    url.set("https://github.com/zedbully/leona-open")
                }
            }

            afterEvaluate {
                from(components["release"])
            }
        }
    }

    repositories {
        maven {
            name = "GitHubPackages"
            url = uri(
                providers.gradleProperty("LEONA_GITHUB_PACKAGES_URL")
                    .orElse(
                        providers.environmentVariable("GITHUB_REPOSITORY")
                            .map { repository -> "https://maven.pkg.github.com/$repository" }
                            .orElse("https://maven.pkg.github.com/zedbully/leona-open"),
                    )
                    .get(),
            )
            credentials {
                username = providers.gradleProperty("gpr.user")
                    .orElse(providers.environmentVariable("GITHUB_ACTOR"))
                    .orElse("")
                    .get()
                password = providers.gradleProperty("gpr.key")
                    .orElse(providers.environmentVariable("GITHUB_TOKEN"))
                    .orElse("")
                    .get()
            }
        }
        maven {
            name = "MavenCentral"
            url = uri(
                providers.gradleProperty("LEONA_MAVEN_CENTRAL_URL")
                    .orElse(providers.environmentVariable("CENTRAL_PORTAL_URL"))
                    .orElse("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
                    .get(),
            )
            credentials {
                username = providers.gradleProperty("centralPortalUsername")
                    .orElse(providers.environmentVariable("CENTRAL_PORTAL_USERNAME"))
                    .orElse("")
                    .get()
                password = providers.gradleProperty("centralPortalPassword")
                    .orElse(providers.environmentVariable("CENTRAL_PORTAL_PASSWORD"))
                    .orElse("")
                    .get()
            }
        }
    }
}

signing {
    val signingKey = providers.gradleProperty("signingKey")
        .orElse(providers.environmentVariable("LEONA_RELEASE_ASC_PRIVATE_KEY"))
        .orElse(providers.environmentVariable("SIGNING_KEY"))
        .orNull
    val signingPassword = providers.gradleProperty("signingPassword")
        .orElse(providers.environmentVariable("LEONA_RELEASE_ASC_PASSPHRASE"))
        .orElse(providers.environmentVariable("SIGNING_PASSWORD"))
        .orNull
    val signingKeyId = providers.gradleProperty("signingKeyId")
        .orElse(providers.environmentVariable("LEONA_RELEASE_ASC_KEY_ID"))
        .orElse(providers.environmentVariable("SIGNING_KEY_ID"))
        .orNull

    val requirePublishingSigning = providers.gradleProperty("requirePublishingSigning")
        .orElse(providers.environmentVariable("LEONA_REQUIRE_PUBLISH_SIGNING"))
        .orElse("false")
        .get()
        .lowercase()
        .let { value -> value == "true" || value == "1" || value == "yes" }
    val publishingRequested = gradle.startParameter.taskNames.any { task ->
        task.contains("publish", ignoreCase = true)
    }

    if (!signingKey.isNullOrBlank() && !signingPassword.isNullOrBlank()) {
        if (signingKeyId.isNullOrBlank()) {
            useInMemoryPgpKeys(signingKey, signingPassword)
        } else {
            useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
        }
        sign(publishing.publications["release"])
    } else if (requirePublishingSigning && publishingRequested) {
        throw GradleException(
            "Publishing is fail-closed: provide SIGNING_KEY, SIGNING_PASSWORD, and optionally SIGNING_KEY_ID."
        )
    }
}

android {
    sourceSets {
        getByName("test") {
            kotlin.directories += "src/test/kotlin"
        }
        getByName("androidTest") {
            kotlin.directories += "src/androidTest/kotlin"
        }
    }
}
