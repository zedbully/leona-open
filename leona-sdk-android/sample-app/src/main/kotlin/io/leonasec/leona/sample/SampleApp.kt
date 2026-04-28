/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.app.Application
import io.leonasec.leona.Leona
import io.leonasec.leona.config.LeonaConfig

class SampleApp : Application() {
    private val tenantId: String
        get() = BuildConfig.LEONA_TENANT_ID.ifBlank { "sample" }

    override fun onCreate() {
        super.onCreate()
        val endpoint = BuildConfig.LEONA_REPORTING_ENDPOINT.ifBlank { null }
        val cloudConfigEndpoint = BuildConfig.LEONA_CLOUD_CONFIG_ENDPOINT.ifBlank { null }
        val apiKey = BuildConfig.LEONA_API_KEY.ifBlank { null }
        val playIntegrityCloudProjectNumber =
            BuildConfig.LEONA_SAMPLE_PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER.trim().toLongOrNull()
        val attestationMode = BuildConfig.LEONA_SAMPLE_ATTESTATION_MODE.trim().lowercase()
        if (attestationMode == "bridge") {
            SamplePlayIntegrity.installBridge(
                ReflectivePlayIntegrityBridge.createIfAvailable(
                    context = this,
                    cloudProjectNumber = playIntegrityCloudProjectNumber,
                ),
            )
        }
        Leona.init(
            this,
            LeonaConfig.Builder()
                .apiKey(apiKey)
                .tenantId(tenantId)
                .appId("sample-app")
                .reportingEndpoint(endpoint)
                .cloudConfigEndpoint(cloudConfigEndpoint)
                .enableCloudConfig(endpoint != null || cloudConfigEndpoint != null)
                .channel("sample")
                .firstPartyMode(true)
                .attestationProvider(resolveSampleAttestationProvider())
                .verboseNativeLogging(true)        // verbose logcat for the demo
                .enableInjectionDetection(true)
                .enableEnvironmentDetection(true)
                .build(),
        )
    }


    private fun resolveSampleAttestationProvider() =
        SampleMainlandAttestation.createProvider(this)
            ?: SamplePlayIntegrity.createProvider()
}
