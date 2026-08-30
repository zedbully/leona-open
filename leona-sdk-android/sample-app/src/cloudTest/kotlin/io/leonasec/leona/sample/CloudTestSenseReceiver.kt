/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import io.leonasec.leona.Leona
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

class CloudTestSenseReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != ACTION) {
            return
        }
        val expectedToken = BuildConfig.LEONA_CLOUD_TEST_TOKEN
        val suppliedToken = intent.getStringExtra(EXTRA_TOKEN).orEmpty()
        val runId = intent.getStringExtra(EXTRA_RUN_ID).orEmpty()
        val runIdSha256 = SampleJsonRedaction.hash(runId)
        if (expectedToken.isBlank() || suppliedToken != expectedToken || runId.isBlank()) {
            val payload = JSONObject()
                .put("class", "SecurityException")
                .put("messageSha256", SampleJsonRedaction.hash("cloudTest sense trigger is not authorized"))
                .put("durationMs", 0)
                .put("reportingEndpointConfigured", reportingEndpointConfigured())
                .put("apiKeyConfigured", apiKeyConfigured())
                .put("runIdSha256", runIdSha256)
            persistAndEmit(context, "error", JSONObject().put("error", payload), payload)
            emit("error", payload)
            return
        }
        val pendingResult = goAsync()
        Thread {
            val startedAt = System.currentTimeMillis()
            try {
                emit(
                    "started",
                    JSONObject()
                        .put("sdkVersion", Leona.version)
                        .put("reportingEndpointConfigured", reportingEndpointConfigured())
                        .put("apiKeyConfigured", apiKeyConfigured())
                        .put("runIdSha256", runIdSha256),
                )
                val boxId = runBlocking { Leona.sense() }
                val diagnostic = Leona.getDiagnosticSnapshot()
                val durationMs = System.currentTimeMillis() - startedAt
                val boxIdSha256 = sha256Hex(boxId.toString())
                val serverInstallIdSha256 = SampleJsonRedaction.hash(diagnostic.installId)
                // Persist and emit only a one-way digest. Android 11+ scoped storage prevents
                // ADB shell from reading app-owned external files, so the log terminal event
                // must itself be sufficient for collection without exposing an opaque BoxId.
                val terminalPayload = JSONObject()
                    .put("boxIdSha256", boxIdSha256)
                    .put("serverInstallIdSha256", serverInstallIdSha256)
                    .put("canonicalDeviceIdHint", SampleJsonRedaction.hint(diagnostic.canonicalDeviceId))
                    .put("canonicalDeviceIdSha256", SampleJsonRedaction.hash(diagnostic.canonicalDeviceId))
                    .put("durationMs", durationMs)
                    .put("reportingEndpointConfigured", reportingEndpointConfigured())
                    .put("apiKeyConfigured", apiKeyConfigured())
                    .put("runIdSha256", runIdSha256)
                // The collection signal is distinct from opaque BoxId and server canonical
                // identity. This redacted diagnostic carries only a full SHA-256 of the
                // already-derived fingerprint signal; the raw signal and BoxId never enter logs.
                val fingerprintPayload = JSONObject()
                    .put("boxIdSha256", boxIdSha256)
                    .put("serverInstallIdSha256", serverInstallIdSha256)
                    .put("canonicalDeviceIdHint", SampleJsonRedaction.hint(diagnostic.canonicalDeviceId))
                    .put("canonicalDeviceIdSha256", SampleJsonRedaction.hash(diagnostic.canonicalDeviceId))
                    .put("fingerprintHashSha256", fingerprintDiagnosticSha256(diagnostic.fingerprintHash))
                    .put("fingerprintSchemaVersion", diagnostic.fingerprintSchemaVersion.toString())
                    .put("fingerprintSource", diagnostic.fingerprintSource)
                    .put("identityAnchorSource", diagnostic.identityAnchorSource)
                    .put("durationMs", durationMs)
                    .put("reportingEndpointConfigured", reportingEndpointConfigured())
                    .put("apiKeyConfigured", apiKeyConfigured())
                    .put("runIdSha256", runIdSha256)
                persistAndEmit(context, "sense", terminalPayload, terminalPayload)
                emit("fingerprint_diagnostic", fingerprintPayload)
                emit("sense", terminalPayload)
            } catch (t: Throwable) {
                // A stability run may intentionally omit server credentials. sense() must
                // fail closed without minting a client-side BoxId, but the local, already-
                // derived fingerprint diagnostic remains valid runtime-support evidence.
                runCatching { Leona.getDiagnosticSnapshot() }
                    .getOrNull()
                    ?.let { diagnostic ->
                        emit(
                            "fingerprint_diagnostic",
                            JSONObject()
                                .put("boxIdSha256", JSONObject.NULL)
                                .put("canonicalDeviceIdHint", SampleJsonRedaction.hint(diagnostic.canonicalDeviceId))
                                .put("canonicalDeviceIdSha256", SampleJsonRedaction.hash(diagnostic.canonicalDeviceId))
                                .put("fingerprintHashSha256", fingerprintDiagnosticSha256(diagnostic.fingerprintHash))
                                .put("fingerprintSchemaVersion", diagnostic.fingerprintSchemaVersion.toString())
                                .put("fingerprintSource", diagnostic.fingerprintSource)
                                .put("identityAnchorSource", diagnostic.identityAnchorSource)
                                .put("durationMs", System.currentTimeMillis() - startedAt)
                                .put("reportingEndpointConfigured", reportingEndpointConfigured())
                                .put("apiKeyConfigured", apiKeyConfigured())
                                .put("runIdSha256", runIdSha256),
                        )
                    }
                val payload = JSONObject()
                    .put("class", t.javaClass.name)
                    .put("messageSha256", SampleJsonRedaction.hash(t.message))
                    .put("durationMs", System.currentTimeMillis() - startedAt)
                    .put("reportingEndpointConfigured", reportingEndpointConfigured())
                    .put("apiKeyConfigured", apiKeyConfigured())
                    .put("runIdSha256", runIdSha256)
                persistAndEmit(context, "error", JSONObject().put("error", payload), payload)
                emit("error", payload)
            } finally {
                pendingResult.finish()
            }
        }.start()
    }

    private fun emit(event: String, payload: JSONObject) {
        Log.i(LOG_TAG, JSONObject().put("event", event).put("payload", payload).toString())
    }

    private fun persistAndEmit(
        context: Context,
        terminalEvent: String,
        persistedPayload: JSONObject,
        terminalPayload: JSONObject,
    ) {
        val persisted = writeResult(context, persistedPayload)
        emit(
            if (persisted) "result_persisted" else "result_persist_failed",
            JSONObject()
                .put("terminalEvent", terminalEvent)
                .put("terminalPayloadSha256", SampleJsonRedaction.hash(terminalPayload.toString())),
        )
    }

    private fun writeResult(context: Context, payload: JSONObject): Boolean =
        runCatching {
            val dir = context.getExternalFilesDir(null) ?: context.filesDir
            val result = File(dir, RESULT_FILE_NAME)
            val temporary = File(dir, "$RESULT_FILE_NAME.tmp")
            temporary.writeText(payload.toString(2))
            if (!temporary.renameTo(result)) {
                temporary.copyTo(result, overwrite = true)
                temporary.delete()
            }
            true
        }.getOrDefault(false)

    private fun reportingEndpointConfigured(): Boolean =
        BuildConfig.LEONA_REPORTING_ENDPOINT.isNotBlank()

    private fun apiKeyConfigured(): Boolean = BuildConfig.LEONA_API_KEY.isNotBlank()

    /**
     * The SDK fingerprint signal is already a derived value. Hash it again locally before this
     * cloud-test diagnostic leaves the process, retaining the full SHA-256 for stability checks.
     */
    private fun fingerprintDiagnosticSha256(value: String?): Any {
        val signal = value?.trim()?.takeIf { it.isNotEmpty() } ?: return JSONObject.NULL
        return sha256Hex(signal)
    }

    private fun sha256Hex(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    companion object {
        const val ACTION = "io.leonasec.leona.sample.CLOUD_TEST_SENSE"
        const val EXTRA_TOKEN = "io.leonasec.leona.sample.CLOUD_TEST_TOKEN"
        const val EXTRA_RUN_ID = "io.leonasec.leona.sample.CLOUD_TEST_RUN_ID"
        const val RESULT_FILE_NAME = "leona-cloudtest-sense-result.json"
        private const val LOG_TAG = "LeonaCloudTest"
    }
}
