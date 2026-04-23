plugins {
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
}

dependencies {
    implementation(project(":common"))
    findProject(":private-api-backend")?.let { implementation(it) }

    implementation(libs.spring.cloud.starter.gateway)
    implementation(libs.spring.boot.starter.data.redis.reactive)
    implementation(libs.spring.boot.starter.actuator)
    implementation(libs.spring.cloud.starter.circuitbreaker.reactor.resilience4j)
    implementation(libs.resilience4j.reactor)
    implementation(libs.micrometer.registry.prometheus)
    implementation(libs.micrometer.tracing.bridge.otel)

    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.reactor.test)
}
