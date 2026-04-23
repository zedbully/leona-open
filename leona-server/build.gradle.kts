plugins {
    java
    alias(libs.plugins.spring.boot) apply false
    alias(libs.plugins.spring.dependency.management) apply false
}

val serverJavaVersion = libs.findVersion("java").get().requiredVersion.toInt()
val springBootVersion = libs.findVersion("spring-boot").get().requiredVersion
val springCloudVersion = libs.findVersion("spring-cloud").get().requiredVersion

allprojects {
    group = "io.leonasec.server"
    version = "0.1.0-alpha.1"
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "io.spring.dependency-management")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(serverJavaVersion))
        }
    }

    configure<io.spring.gradle.dependencymanagement.dsl.DependencyManagementExtension> {
        imports {
            mavenBom("org.springframework.boot:spring-boot-dependencies:$springBootVersion")
            mavenBom("org.springframework.cloud:spring-cloud-dependencies:$springCloudVersion")
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
        options.compilerArgs.addAll(listOf(
            "-Xlint:all,-serial,-processing",
            "-parameters",
        ))
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        systemProperty("spring.profiles.active", "test")
        jvmArgs("-XX:+EnableDynamicAgentLoading")
    }
}

// Convenience accessor for version catalogs inside subprojects blocks.
val org.gradle.api.Project.libs get() =
    rootProject.extensions.getByType<org.gradle.api.artifacts.VersionCatalogsExtension>().named("libs")
