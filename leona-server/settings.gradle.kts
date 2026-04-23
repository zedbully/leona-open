pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
    }
}

rootProject.name = "leona-server"

include(
    ":common",
    ":gateway",
    ":ingestion-service",
    ":query-service",
    ":admin-service",
    ":worker-event-persister",
)

val privateApiBackendDir = file("private/api-backend")
if (privateApiBackendDir.isDirectory) {
    include(":private-api-backend")
    project(":private-api-backend").projectDir = privateApiBackendDir
}
