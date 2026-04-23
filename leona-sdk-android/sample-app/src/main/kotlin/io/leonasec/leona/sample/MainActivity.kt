/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.material.button.MaterialButton
import io.leonasec.leona.BoxId
import io.leonasec.leona.Honeypot
import io.leonasec.leona.Leona
import io.leonasec.leona.LeonaDiagnosticSnapshot
import io.leonasec.leona.LeonaSecureTransportSnapshot
import io.leonasec.leona.LeonaSupportBundle
import io.leonasec.leona.sample.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val http = OkHttpClient()
    private var lastBoxId: BoxId? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.sdkVersion.text = getString(R.string.sdk_version_fmt, Leona.version)
        binding.serverMode.text = getString(R.string.server_mode_fmt, renderServerMode())
        refreshDeviceId()
        refreshDiagnostics()

        binding.buttonSense.setOnClickListener { runSense() }
        binding.buttonVerdict.setOnClickListener { queryDemoVerdict() }
        binding.buttonDecoy.setOnClickListener { runDecoy() }
        binding.buttonHoneypot.setOnClickListener { showHoneypotSample() }
        binding.buttonCopyDiagnosticJson.setOnClickListener { copyDiagnosticJson() }
        binding.buttonShareDiagnosticJson.setOnClickListener { shareDiagnosticJson() }
        binding.buttonCopyTransportJson.setOnClickListener { copyTransportJson() }
        binding.buttonShareTransportJson.setOnClickListener { shareTransportJson() }
        binding.buttonCopySupportBundle.setOnClickListener { copySupportBundleJson() }
        binding.buttonShareSupportBundle.setOnClickListener { shareSupportBundleJson() }
        binding.buttonCopyConsistencyJson.setOnClickListener { copyConsistencyJson() }
        binding.buttonShareConsistencyJson.setOnClickListener { shareConsistencyJson() }
        binding.buttonCopyVerdictJson.setOnClickListener { copyVerdictJson() }
        binding.buttonShareVerdictJson.setOnClickListener { shareVerdictJson() }
        installSectionToggle(
            button = binding.buttonToggleDiagnosticJson,
            target = binding.diagnosticJsonSection,
            showLabelRes = R.string.show_diagnostic_json,
            hideLabelRes = R.string.hide_diagnostic_json,
        )
        installSectionToggle(
            button = binding.buttonToggleTransportJson,
            target = binding.transportJsonSection,
            showLabelRes = R.string.show_transport_json,
            hideLabelRes = R.string.hide_transport_json,
        )
        installSectionToggle(
            button = binding.buttonToggleSupportBundle,
            target = binding.supportBundleSection,
            showLabelRes = R.string.show_support_bundle,
            hideLabelRes = R.string.hide_support_bundle,
        )
        installSectionToggle(
            button = binding.buttonToggleConsistencyJson,
            target = binding.consistencyJsonSection,
            showLabelRes = R.string.show_consistency_json,
            hideLabelRes = R.string.hide_consistency_json,
        )
        installSectionToggle(
            button = binding.buttonToggleVerdictJson,
            target = binding.verdictJsonSection,
            showLabelRes = R.string.show_verdict_json,
            hideLabelRes = R.string.hide_verdict_json,
        )
    }

    private fun runSense() {
        setBusy(true)
        binding.verdictResult.text = ""
        binding.verdictJson.text = getString(R.string.verdict_json_placeholder)
        lifecycleScope.launch {
            val boxId: BoxId? = runCatching { Leona.sense() }
                .onFailure {
                    binding.boxId.text =
                        getString(R.string.box_id_error_fmt, it.message ?: it.javaClass.simpleName)
                }
                .getOrNull()
            refreshDeviceId()
            refreshDiagnostics()

            if (boxId != null) {
                lastBoxId = boxId
                binding.boxId.text = getString(R.string.box_id_fmt, boxId.toString())
                binding.buttonVerdict.isEnabled = true
            }
            setBusy(false)
        }
    }

    private fun queryDemoVerdict() {
        val boxId = lastBoxId
        if (boxId == null) {
            binding.verdictResult.text = getString(R.string.verdict_need_box_id)
            return
        }

        val baseUrl = BuildConfig.LEONA_DEMO_BACKEND_BASE_URL
        if (baseUrl.isBlank()) {
            binding.verdictResult.text = getString(R.string.verdict_backend_not_configured)
            return
        }

        setBusy(true)
        lifecycleScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    val body = JSONObject()
                        .put("boxId", boxId.toString())
                        .toString()
                        .toRequestBody("application/json".toMediaType())
                    val request = Request.Builder()
                        .url(baseUrl.trimEnd('/') + "/demo/verdict")
                        .post(body)
                        .build()
                    http.newCall(request).execute().use { response ->
                        val payload = response.body?.string().orEmpty()
                        if (!response.isSuccessful) {
                            error("demo backend HTTP ${response.code}: $payload")
                        }
                        payload
                    }
                }
            }.onSuccess { payload ->
                val json = JSONObject(payload)
                val decision = sequenceOf(
                    json.optString("decision"),
                    json.optJSONObject("verdict")?.optString("decision"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "unknown"
                val action = sequenceOf(
                    json.optString("action"),
                    json.optJSONObject("verdict")?.optString("action"),
                    json.optJSONObject("risk")?.optString("action"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "-"
                val riskLevel = sequenceOf(
                    json.optString("riskLevel"),
                    json.optJSONObject("verdict")?.optString("riskLevel"),
                    json.optJSONObject("risk")?.optString("level"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "unknown"
                val riskScore = sequenceOf(
                    json.optInt("riskScore", Int.MIN_VALUE).takeUnless { it == Int.MIN_VALUE },
                    json.optJSONObject("verdict")?.optInt("riskScore", Int.MIN_VALUE)?.takeUnless { it == Int.MIN_VALUE },
                    json.optJSONObject("risk")?.optInt("score", Int.MIN_VALUE)?.takeUnless { it == Int.MIN_VALUE },
                ).firstOrNull() ?: -1
                val riskTags = buildSet {
                    json.optJSONArray("riskTags")?.let { array ->
                        for (index in 0 until array.length()) add(array.optString(index))
                    }
                    json.optJSONObject("verdict")?.optJSONArray("riskTags")?.let { array ->
                        for (index in 0 until array.length()) add(array.optString(index))
                    }
                    json.optJSONObject("risk")?.optJSONArray("tags")?.let { array ->
                        for (index in 0 until array.length()) add(array.optString(index))
                    }
                }.map { it.trim() }.filter { it.isNotEmpty() }.sorted()
                val canonicalDeviceId = sequenceOf(
                    json.optString("canonicalDeviceId"),
                    json.optJSONObject("device")?.optString("canonicalDeviceId"),
                    json.optJSONObject("device")?.optString("deviceId"),
                    json.optJSONObject("identity")?.optString("canonicalDeviceId"),
                    json.optJSONObject("identity")?.optString("deviceId"),
                    json.optJSONObject("deviceIdentity")?.optString("canonicalDeviceId"),
                    json.optJSONObject("deviceIdentity")?.optString("deviceId"),
                    json.optJSONObject("deviceIdentity")?.optString("resolvedDeviceId"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "-"
                binding.verdictResult.text = getString(
                    R.string.verdict_result_v2_fmt,
                    decision,
                    action,
                    riskLevel,
                    riskScore,
                    riskTags.joinToString(",").ifBlank { "-" },
                    canonicalDeviceId,
                )
                binding.verdictJson.text = Leona.getLastServerVerdictJson()
                    ?: payload
                lastBoxId = null
            }.onFailure {
                binding.verdictResult.text =
                    getString(R.string.verdict_error_fmt, it.message ?: it.javaClass.simpleName)
                binding.verdictJson.text =
                    getString(R.string.verdict_error_fmt, it.message ?: it.javaClass.simpleName)
            }
            setBusy(false)
        }
    }

    @Suppress("DEPRECATION") // Intentionally exercising the decoy API.
    private fun runDecoy() {
        val value = Leona.quickCheck()
        binding.decoyResult.text = getString(R.string.decoy_result_fmt, value.toString())
    }

    private fun showHoneypotSample() {
        val fake = Honeypot.fakeUser()
        binding.honeypotResult.text = getString(
            R.string.honeypot_result_fmt,
            fake.id,
            fake.email,
            fake.displayName,
        )
    }

    private fun setBusy(busy: Boolean) {
        binding.buttonSense.isEnabled = !busy
        binding.buttonVerdict.isEnabled = !busy && lastBoxId != null
        binding.progress.visibility = if (busy) View.VISIBLE else View.GONE
    }

    private fun refreshDeviceId() {
        binding.deviceId.text = runCatching {
            getString(R.string.device_id_fmt, Leona.getDeviceId())
        }.getOrElse {
            getString(R.string.device_id_error_fmt, it.message ?: it.javaClass.simpleName)
        }
    }

    private fun refreshDiagnostics() {
        runCatching {
            val snapshot = Leona.getDiagnosticSnapshot()
            val transport = Leona.getSecureTransportSnapshot()
            val supportBundle = Leona.getSupportBundle()
            val consistency = ConsistencyReport.from(
                diagnostic = snapshot,
                transport = transport,
                bundle = supportBundle,
                reportingEndpoint = BuildConfig.LEONA_REPORTING_ENDPOINT.ifBlank { null },
                cloudConfigEndpoint = BuildConfig.LEONA_CLOUD_CONFIG_ENDPOINT.ifBlank { null },
                demoBackendEndpoint = BuildConfig.LEONA_DEMO_BACKEND_BASE_URL.ifBlank { null },
            )
            binding.diagnosticSummary.text = renderDiagnostics(snapshot)
            binding.diagnosticJson.text = Leona.getDiagnosticSnapshotJson()
            binding.transportSummary.text = renderTransport(transport)
            binding.transportJson.text = Leona.getSecureTransportSnapshotJson()
            binding.supportBundleSummary.text = renderSupportBundle(supportBundle)
            binding.consistencySummary.text = renderConsistencySummary(consistency)
            binding.consistencyJson.text = consistency.toJson()
            binding.supportBundleJson.text = supportBundle.toJson()
        }.getOrElse {
            val message = getString(R.string.device_id_error_fmt, it.message ?: it.javaClass.simpleName)
            binding.diagnosticSummary.text = message
            binding.diagnosticJson.text = message
            binding.transportSummary.text = message
            binding.transportJson.text = message
            binding.supportBundleSummary.text = message
            binding.consistencySummary.text = message
            binding.consistencyJson.text = message
            binding.supportBundleJson.text = message
        }
    }

    private fun renderServerMode(): String {
        val reporting = BuildConfig.LEONA_REPORTING_ENDPOINT.ifBlank {
            getString(R.string.server_mode_stub)
        }
        val cloudConfig = BuildConfig.LEONA_CLOUD_CONFIG_ENDPOINT.ifBlank { "-" }
        val demoBackend = BuildConfig.LEONA_DEMO_BACKEND_BASE_URL.ifBlank { "-" }
        return "reporting=$reporting\ncloudConfig=$cloudConfig\ndemoBackend=$demoBackend"
    }

    private fun renderDiagnostics(snapshot: LeonaDiagnosticSnapshot): String =
        getString(
            R.string.diagnostic_fmt,
            snapshot.deviceId,
            snapshot.installId,
            snapshot.canonicalDeviceId ?: "-",
            snapshot.fingerprintHash,
            snapshot.localRiskSignals.toSortedSet().joinToString(",").ifBlank { "-" },
            snapshot.nativeRiskTags.toSortedSet().joinToString(",").ifBlank { "-" },
            snapshot.nativeHighestSeverity?.toString() ?: "-",
            snapshot.nativeFindingIds.joinToString(",").ifBlank { "-" },
            snapshot.serverDecision ?: "-",
            snapshot.serverAction ?: "-",
            snapshot.serverRiskLevel ?: "-",
            snapshot.serverRiskScore?.toString() ?: "-",
            snapshot.serverRiskTags.toSortedSet().joinToString(",").ifBlank { "-" },
            snapshot.lastBoxId ?: "-",
        )

    private fun renderTransport(snapshot: LeonaSecureTransportSnapshot): String =
        getString(
            R.string.transport_fmt,
            snapshot.engineAvailable.toString(),
            snapshot.deviceBinding?.present?.toString() ?: "-",
            snapshot.deviceBinding?.hardwareBacked?.toString() ?: "-",
            snapshot.deviceBinding?.publicKeySha256 ?: "-",
            snapshot.session?.sessionIdHint ?: "-",
            snapshot.session?.expiresAtMillis?.toString() ?: "-",
            snapshot.session?.canonicalDeviceId ?: "-",
            snapshot.lastAttestation?.format ?: "-",
            snapshot.lastAttestation?.tokenSha256 ?: "-",
            snapshot.lastHandshakeError ?: "-",
        )

    private fun renderSupportBundle(bundle: LeonaSupportBundle): String =
        getString(
            R.string.support_bundle_fmt,
            bundle.diagnosticSnapshot.canonicalDeviceId ?: "-",
            bundle.effectiveDisabledSignals.toSortedSet().joinToString(",").ifBlank { "-" },
            bundle.effectiveDisableCollectionWindowMs.toString(),
            bundle.cloudConfigFetchedAtMillis?.toString() ?: "-",
            if (bundle.cloudConfigRawJson.isNullOrBlank()) "false" else "true",
            bundle.secureTransport?.session?.canonicalDeviceId ?: "-",
            bundle.serverVerdict?.canonicalDeviceId ?: "-",
        )

    private fun renderConsistencySummary(report: ConsistencyReport): String {
        return getString(
            R.string.consistency_fmt,
            report.diagnosticCanonical ?: "-",
            report.transportCanonical ?: "-",
            report.verdictCanonical ?: "-",
            report.bundleCanonical ?: "-",
            report.aligned.toString(),
        )
    }

    private fun installSectionToggle(
        button: MaterialButton,
        target: View,
        showLabelRes: Int,
        hideLabelRes: Int,
        initiallyExpanded: Boolean = false,
    ) {
        fun update(expanded: Boolean) {
            target.visibility = if (expanded) View.VISIBLE else View.GONE
            button.setText(if (expanded) hideLabelRes else showLabelRes)
        }
        update(initiallyExpanded)
        button.setOnClickListener {
            update(target.visibility != View.VISIBLE)
        }
    }

    private fun copyDiagnosticJson() {
        val json = runCatching { Leona.getDiagnosticSnapshotJson() }.getOrNull() ?: return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("leona-diagnostic-json", json))
        Toast.makeText(this, R.string.copied_to_clipboard, Toast.LENGTH_SHORT).show()
    }

    private fun shareDiagnosticJson() {
        val json = runCatching { Leona.getDiagnosticSnapshotJson() }.getOrNull() ?: return
        val intent = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_diagnostic_title))
            .putExtra(Intent.EXTRA_TEXT, json)
        startActivity(Intent.createChooser(intent, getString(R.string.share_diagnostic_title)))
    }

    private fun copySupportBundleJson() {
        val json = runCatching { Leona.getSupportBundleJson() }.getOrNull() ?: return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("leona-support-bundle-json", json))
        Toast.makeText(this, R.string.copied_support_bundle, Toast.LENGTH_SHORT).show()
    }

    private fun shareSupportBundleJson() {
        val json = runCatching { Leona.getSupportBundleJson() }.getOrNull() ?: return
        val intent = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_support_bundle_title))
            .putExtra(Intent.EXTRA_TEXT, json)
        startActivity(Intent.createChooser(intent, getString(R.string.share_support_bundle_title)))
    }

    private fun copyConsistencyJson() {
        val json = binding.consistencyJson.text?.toString()?.takeIf { it.isNotBlank() } ?: return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("leona-consistency-json", json))
        Toast.makeText(this, R.string.copied_consistency_to_clipboard, Toast.LENGTH_SHORT).show()
    }

    private fun shareConsistencyJson() {
        val json = binding.consistencyJson.text?.toString()?.takeIf { it.isNotBlank() } ?: return
        val intent = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_consistency_title))
            .putExtra(Intent.EXTRA_TEXT, json)
        startActivity(Intent.createChooser(intent, getString(R.string.share_consistency_title)))
    }

    private fun copyTransportJson() {
        val json = runCatching { Leona.getSecureTransportSnapshotJson() }.getOrNull() ?: return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("leona-secure-transport-json", json))
        Toast.makeText(this, R.string.copied_transport_to_clipboard, Toast.LENGTH_SHORT).show()
    }

    private fun shareTransportJson() {
        val json = runCatching { Leona.getSecureTransportSnapshotJson() }.getOrNull() ?: return
        val intent = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_transport_title))
            .putExtra(Intent.EXTRA_TEXT, json)
        startActivity(Intent.createChooser(intent, getString(R.string.share_transport_title)))
    }

    private fun copyVerdictJson() {
        val json = runCatching { Leona.getLastServerVerdictJson() }.getOrNull() ?: return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("leona-server-verdict-json", json))
        Toast.makeText(this, R.string.copied_verdict_to_clipboard, Toast.LENGTH_SHORT).show()
    }

    private fun shareVerdictJson() {
        val json = runCatching { Leona.getLastServerVerdictJson() }.getOrNull() ?: return
        val intent = Intent(Intent.ACTION_SEND)
            .setType("application/json")
            .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_verdict_title))
            .putExtra(Intent.EXTRA_TEXT, json)
        startActivity(Intent.createChooser(intent, getString(R.string.share_verdict_title)))
    }
}
