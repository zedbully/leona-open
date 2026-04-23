/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.config

/** Deployment region for Leona-managed defaults. */
enum class LeonaRegion(
    internal val uploadHost: String,
    internal val cloudConfigPath: String,
) {
    CN_BJ(
        uploadHost = "https://api.leonasec.io",
        cloudConfigPath = "/v1/mobile-config",
    ),
    SG(
        uploadHost = "https://sg-api.leonasec.io",
        cloudConfigPath = "/v1/mobile-config",
    ),
    US(
        uploadHost = "https://us-api.leonasec.io",
        cloudConfigPath = "/v1/mobile-config",
    ),
}
