dependencies {
    implementation("org.springframework:spring-web")
    implementation("org.springframework.data:spring-data-redis")
    implementation("io.projectreactor:reactor-core")

    implementation(libs.jackson.databind)
    implementation(libs.jackson.datatype.jsr310)
    implementation(libs.ulid.creator)

    testImplementation(libs.spring.boot.starter.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
