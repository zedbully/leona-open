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
                val payload = JSONObject()
                    .put("boxId", boxId.toString())
                    .put("canonicalDeviceIdHint", SampleJsonRedaction.hint(diagnostic.canonicalDeviceId))
                    .put("canonicalDeviceIdSha256", SampleJsonRedaction.hash(diagnostic.canonicalDeviceId))
                    .put("durationMs", System.currentTimeMillis() - startedAt)
                    .put("reportingEndpointConfigured", reportingEndpointConfigured())
                    .put("apiKeyConfigured", apiKeyConfigured())
                    .put("runIdSha256", runIdSha256)
                persistAndEmit(context, "sense", payload, payload)
                emit("sense", payload)
            } catch (t: Throwable) {
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

    companion object {
        const val ACTION = "io.leonasec.leona.sample.CLOUD_TEST_SENSE"
        const val EXTRA_TOKEN = "io.leonasec.leona.sample.CLOUD_TEST_TOKEN"
        const val EXTRA_RUN_ID = "io.leonasec.leona.sample.CLOUD_TEST_RUN_ID"
        const val RESULT_FILE_NAME = "leona-cloudtest-sense-result.json"
        private const val LOG_TAG = "LeonaCloudTest"
    }
}
