val includePrivateSdkCore =
    providers.gradleProperty("LEONA_INCLUDE_PRIVATE_CORE")
        .orElse(providers.environmentVariable("LEONA_INCLUDE_PRIVATE_CORE"))
        .orElse("false")
        .get()
        .lowercase()
        .let { value -> value == "true" || value == "1" || value == "yes" }

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
        // Mirrors last: use them as fallback only when primary upstreams are unavailable.
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        maven("https://maven.aliyun.com/repository/gradle-plugin")
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        if (includePrivateSdkCore) {
            // The Huawei repository is reachable only for the explicitly enabled
            // closed-source module. Public SDK builds and artifacts remain free of
            // HMS (and Google Play Integrity) runtime dependencies.
            maven("https://developer.huawei.com/repo/") {
                content {
                    includeGroupByRegex("com\\.huawei(\\..*)?")
                }
            }
        }
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
    }
}

rootProject.name = "leona-sdk-android"

include(":sdk")
include(":sample-app")

val privateSdkCoreDir = file("private/sdk-private-core")

if (includePrivateSdkCore && privateSdkCoreDir.isDirectory) {
    include(":sdk-private-core")
    project(":sdk-private-core").projectDir = privateSdkCoreDir
}
