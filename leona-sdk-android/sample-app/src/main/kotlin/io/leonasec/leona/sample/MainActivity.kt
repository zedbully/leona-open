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
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import io.leonasec.leona.BoxId
import io.leonasec.leona.Honeypot
import io.leonasec.leona.Leona
import io.leonasec.leona.LeonaDebugExportView
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
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID

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

        if (isAuthorizedLogcatE2E()) {
            binding.root.post { runLogcatE2E() }
        }
    }

    private fun isAuthorizedLogcatE2E(): Boolean {
        if (!BuildConfig.DEBUG || !intent.getBooleanExtra(EXTRA_E2E_AUTO_RUN, false)) {
            return false
        }
        val expectedToken = BuildConfig.LEONA_E2E_TOKEN.trim()
        val providedToken = intent.getStringExtra(EXTRA_E2E_TOKEN).orEmpty().trim()
        if (expectedToken.isEmpty() || providedToken.isEmpty() || expectedToken != providedToken) {
            Log.w(E2E_LOG_TAG, "Ignoring unauthorized logcat E2E request")
            return false
        }
        return true
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
                fetchDemoVerdictPayload(boxId)
            }.onSuccess { payload ->
                val json = JSONObject(payload)
                binding.verdictResult.text = renderVerdictSummary(summarizeVerdict(json))
                binding.verdictJson.text = runCatching { json.toString(2) }.getOrDefault(payload)
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

    private suspend fun fetchDemoVerdictPayload(boxId: BoxId): String = withContext(Dispatchers.IO) {
        val baseUrl = BuildConfig.LEONA_DEMO_BACKEND_BASE_URL
        if (baseUrl.isBlank()) {
            error(getString(R.string.verdict_backend_not_configured))
        }

        val currentDeviceIdHash = sampleHeaderHash(runCatching { Leona.getDeviceId() }.getOrNull())
        val canonicalDeviceIdHash = sampleHeaderHash(
            runCatching { Leona.getDiagnosticSnapshot().canonicalDeviceId }.getOrNull(),
        )
        val body = JSONObject()
            .put("boxId", boxId.toString())
            .toString()
            .toRequestBody("application/json".toMediaType())
        val request = Request.Builder()
            .url(baseUrl.trimEnd('/') + "/demo/verdict")
            .apply {
                header("X-Leona-Demo-App-Id", "sample-app")
                BuildConfig.LEONA_TENANT_ID.trim()
                    .ifEmpty { "sample" }
                    .let { header("X-Leona-Demo-Tenant", it) }
                if (currentDeviceIdHash.isNotEmpty()) {
                    header("X-Leona-Demo-Device-Id-Sha256", currentDeviceIdHash)
                }
                if (canonicalDeviceIdHash.isNotEmpty()) {
                    header("X-Leona-Demo-Canonical-Device-Id-Sha256", canonicalDeviceIdHash)
                }
            }
            .post(body)
            .build()
        http.newCall(request).execute().use { response ->
            val payload = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                error("demo backend HTTP ${response.code}")
            }
            payload
        }
    }

    private fun runLogcatE2E() {
        setBusy(true)
        binding.verdictResult.text = ""
        binding.verdictJson.text = getString(R.string.verdict_json_placeholder)

        lifecycleScope.launch {
            val runId = System.currentTimeMillis().toString(36) + "-" + UUID.randomUUID().toString()
            try {
                emitE2E(runId, "started", JSONObject().put("sdkVersion", Leona.version))
                emitE2E(runId, "pre", withContext(Dispatchers.IO) { captureE2ESurfaces() })

                val boxId = withContext(Dispatchers.IO) { Leona.sense() }
                lastBoxId = boxId
                binding.boxId.text = getString(R.string.box_id_fmt, boxId.toString())
                binding.buttonVerdict.isEnabled = true
                refreshDeviceId()
                refreshDiagnostics()
                emitE2E(runId, "sense", JSONObject().put("boxId", boxId.toString()))
                emitE2E(runId, "post", withContext(Dispatchers.IO) { captureE2ESurfaces(boxId) })

                val demoPayload = fetchDemoVerdictPayload(boxId)
                val demoJson = JSONObject(demoPayload)
                val demoSummary = summarizeVerdict(demoJson)
                binding.verdictResult.text = renderVerdictSummary(demoSummary)
                binding.verdictJson.text = runCatching { demoJson.toString(2) }.getOrDefault(demoPayload)
                lastBoxId = null
                refreshDiagnostics()
                emitE2E(
                    runId,
                    "demoVerdict",
                    JSONObject()
                        .put("summary", redactVerdictSummaryForE2E(demoSummary)),
                )
                emitE2E(runId, "postVerdict", withContext(Dispatchers.IO) { captureE2ESurfaces(boxId) })

                val formalBoxId = withContext(Dispatchers.IO) { Leona.sense() }
                refreshDeviceId()
                refreshDiagnostics()
                emitE2E(runId, "formalSense", JSONObject().put("boxId", formalBoxId.toString()))

                val canonicalDeviceId = runCatching { Leona.getDiagnosticSnapshot().canonicalDeviceId }
                    .getOrNull()
                    ?: runCatching { Leona.getDeviceId() }.getOrNull()
                    ?: ""
                emitE2E(
                    runId,
                    "complete",
                    JSONObject()
                        .put("boxId", boxId.toString())
                        .put("formalBoxId", formalBoxId.toString())
                        .put("canonicalDeviceIdHint", SampleJsonRedaction.hint(canonicalDeviceId))
                        .put("canonicalDeviceIdSha256", SampleJsonRedaction.hash(canonicalDeviceId)),
                )
            } catch (t: Throwable) {
                emitE2E(
                    runId,
                    "error",
                    JSONObject()
                        .put("class", t.javaClass.name)
                        .put("message", sanitizeE2EMessage(t.message ?: "")),
                )
                Log.e(E2E_LOG_TAG, "Leona logcat E2E failed: ${t.javaClass.name}: ${sanitizeE2EMessage(t.message ?: "")}")
            } finally {
                setBusy(false)
            }
        }
    }

    private fun captureE2ESurfaces(boxId: BoxId? = null): JSONObject {
        val diagnostic = Leona.getDiagnosticSnapshot()
        val transport = Leona.getSecureTransportSnapshot()
        val supportBundle = Leona.getSupportBundle()
        val consistency = ConsistencyReport.from(
            diagnostic = diagnostic,
            transport = transport,
            bundle = supportBundle,
            reportingEndpoint = BuildConfig.LEONA_REPORTING_ENDPOINT.ifBlank { null },
            cloudConfigEndpoint = BuildConfig.LEONA_CLOUD_CONFIG_ENDPOINT.ifBlank { null },
            demoBackendEndpoint = BuildConfig.LEONA_DEMO_BACKEND_BASE_URL.ifBlank { null },
        )
        return JSONObject()
            .put("boxId", boxId?.toString())
            .put("canonicalDeviceIdHint", SampleJsonRedaction.hint(diagnostic.canonicalDeviceId))
            .put("canonicalDeviceIdSha256", SampleJsonRedaction.hash(diagnostic.canonicalDeviceId))
            .put("diagnostic", diagnostic.toJsonObject(LeonaDebugExportView.REDACTED))
            .put("transport", transport.toJsonObject(LeonaDebugExportView.REDACTED))
            .put("supportBundle", supportBundle.toJsonObject(LeonaDebugExportView.REDACTED))
            .put("consistency", consistency.toJsonObject(LeonaDebugExportView.REDACTED))
    }

    private fun summarizeVerdict(json: JSONObject): JSONObject {
        val riskScore = sequenceOf(
            json.optInt("riskScore", Int.MIN_VALUE).takeUnless { it == Int.MIN_VALUE },
            json.optJSONObject("verdict")?.optInt("riskScore", Int.MIN_VALUE)?.takeUnless { it == Int.MIN_VALUE },
            json.optJSONObject("risk")?.optInt("score", Int.MIN_VALUE)?.takeUnless { it == Int.MIN_VALUE },
        ).firstOrNull() ?: -1
        return JSONObject()
            .put(
                "decision",
                sequenceOf(
                    json.optString("decision"),
                    json.optJSONObject("verdict")?.optString("decision"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "unknown",
            )
            .put(
                "action",
                sequenceOf(
                    json.optString("action"),
                    json.optJSONObject("verdict")?.optString("action"),
                    json.optJSONObject("risk")?.optString("action"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "-",
            )
            .put(
                "riskLevel",
                sequenceOf(
                    json.optString("riskLevel"),
                    json.optJSONObject("verdict")?.optString("riskLevel"),
                    json.optJSONObject("risk")?.optString("level"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "unknown",
            )
            .put("riskScore", riskScore)
            .put("riskTags", JSONArray(collectDetectionDetails(json)))
            .put(
                "canonicalDeviceId",
                sequenceOf(
                    json.optString("canonicalDeviceId"),
                    json.optJSONObject("device")?.optString("canonicalDeviceId"),
                    json.optJSONObject("device")?.optString("deviceId"),
                    json.optJSONObject("identity")?.optString("canonicalDeviceId"),
                    json.optJSONObject("identity")?.optString("deviceId"),
                    json.optJSONObject("deviceIdentity")?.optString("canonicalDeviceId"),
                    json.optJSONObject("deviceIdentity")?.optString("deviceId"),
                    json.optJSONObject("deviceIdentity")?.optString("resolvedDeviceId"),
                ).mapNotNull { it?.ifBlank { null } }.firstOrNull() ?: "-",
            )
    }

    private fun redactVerdictSummaryForE2E(summary: JSONObject): JSONObject {
        val canonical = summary.optString("canonicalDeviceId").takeIf { it.isNotBlank() && it != "-" }
        return JSONObject(summary.toString())
            .removeAndReturn("canonicalDeviceId")
            .put("canonicalDeviceIdHint", SampleJsonRedaction.hint(canonical))
            .put("canonicalDeviceIdSha256", SampleJsonRedaction.hash(canonical))
    }

    private fun collectDetectionDetails(json: JSONObject): List<String> = buildSet {
        json.optJSONArray("riskTags").asStringList().forEach(::add)
        json.optJSONArray("riskReasons").asStringList().forEach(::add)
        json.optJSONObject("verdict")?.optJSONArray("riskTags").asStringList().forEach(::add)
        json.optJSONObject("verdict")?.optJSONArray("riskReasons").asStringList().forEach(::add)
        json.optJSONObject("risk")?.optJSONArray("tags").asStringList().forEach(::add)
        json.optJSONObject("risk")?.optJSONArray("reasons").asStringList().forEach(::add)
        json.optJSONObject("policyExplanation")?.let { policy ->
            policy.optJSONArray("reasons").asStringList().forEach(::add)
            policy.optJSONArray("authoritativeEventIds").asStringList().forEach(::add)
            policy.optJSONArray("contributingEventIds").asStringList().forEach(::add)
        }
        json.optJSONArray("events")?.let { events ->
            for (index in 0 until events.length()) {
                events.optJSONObject(index)?.optString("id")?.takeIf { it.isNotBlank() }?.let(::add)
            }
        }
    }.map { it.trim() }.filter { it.isNotEmpty() }.sorted()

    private fun renderVerdictSummary(summary: JSONObject): String =
        getString(
            R.string.verdict_result_v2_fmt,
            translateDecision(summary.optString("decision", "unknown")),
            translateAction(summary.optString("action", "-")),
            formatTranslatedEvidenceDetails(summary.optJSONArray("riskTags").asStringList()),
            summary.optString("canonicalDeviceId", "-"),
        )

    private fun formatTranslatedEvidence(values: Collection<String>): String =
        values
            .map { translateEvidenceToken(it) }
            .filter { it.isNotBlank() }
            .distinct()
            .sorted()
            .joinToString("，")
            .ifBlank { "-" }

    private fun formatTranslatedEvidenceDetails(values: Collection<String>): String {
        val details = values
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
            .sorted()
        if (details.isEmpty()) {
            return "未返回具体检测项"
        }
        return details.joinToString("\n") { value ->
            "· ${translateEvidenceToken(value)}（$value）"
        }
    }

    private fun translateDecision(value: String?): String =
        when (value?.trim()?.lowercase(Locale.ROOT)) {
            "evidence_collected" -> "已采集环境信息"
            "allow", "challenge", "reject", "deny", "review" -> "旧版字段：仅作兼容展示"
            null, "", "-", "unknown" -> "尚未获取"
            else -> "已采集环境信息"
        }

    private fun translateAction(value: String?): String =
        when (value?.trim()?.lowercase(Locale.ROOT)) {
            "business_defined" -> "由业务调用方自行处理"
            "allow", "review", "block", "challenge", "reject", "deny" -> "旧版字段：业务方自行处理"
            null, "", "-", "unknown" -> "由业务调用方自行处理"
            else -> "由业务调用方自行处理"
        }

    private fun translateEvidenceLevel(value: String?): String =
        when (value?.trim()?.uppercase(Locale.ROOT)) {
            "CLEAN" -> "未见明显异常"
            "LOW" -> "低强度证据"
            "MEDIUM" -> "中等强度证据"
            "HIGH" -> "高强度证据"
            "CRITICAL" -> "严重强度证据"
            null, "", "-", "UNKNOWN" -> "未知"
            else -> "未知"
        }

    private fun translateNativeSeverity(value: Int?): String =
        when (value) {
            null -> "-"
            0 -> "无"
            1 -> "信息"
            2 -> "低"
            3 -> "中"
            4 -> "高"
            else -> "未知"
        }

    private fun translateEvidenceToken(raw: String): String {
        val value = raw.trim().lowercase(Locale.ROOT)
        if (value.isBlank()) return ""
        return when {
            value == "risk.clean" -> "【服务端汇总等级】clean：服务端将本次检测事件聚合为未见明显异常"
            value == "risk.low" -> "【服务端汇总等级】low：服务端按检测事件分值聚合出的低强度等级"
            value == "risk.medium" -> "【服务端汇总等级】medium：服务端按检测事件分值聚合出的中等强度等级"
            value == "risk.high" -> "【服务端汇总等级】high：服务端按检测事件分值聚合出的高强度等级；具体原因看同列表行为标签"
            value == "risk.critical" -> "【服务端汇总等级】critical：服务端按检测事件分值或即时严重规则聚合出的严重等级；具体原因看 Root/Hook/调试/ADB/安装来源等明细"
            value == "tamper.installer.missing" ->
                "【安装来源/测试姿态】installerPackage 缺失：Android 未提供可信安装来源，常见于 ADB、WeTest 或手动侧载；本项本身不等于 Root/Hook/篡改"
            value == "install.sideload_or_unknown" ->
                "【安装来源/测试姿态】侧载或未知来源：installerPackage 缺失或非标准商店来源；用于区分实验室安装和正式分发"
            value == "debug.adb_enabled" || value.contains("developer.adb_enabled") ->
                "【调试/ADB】ADB 调试已开启：设备全局 adb_enabled 或 developer.adb_enabled 为开启；云真机/实验室远程调试常见，业务方应按自身策略处理"
            value == "debug.app_debuggable" || value.contains("app.debuggable") ->
                "【调试/Debuggable】应用可调试：APK/Application debuggable 标志开启；debug sample 预期会出现，release 包不应出现"
            value == "debug.developer_options_enabled" || value.contains("developer.options_enabled") ->
                "【调试/开发者选项】开发者选项已开启：development_settings_enabled 为开启；表示设备处于开发/测试姿态"
            value == "debug.debugger_attached" || value.contains("debugger") || value.contains("ptrace") ->
                "【调试/Debugger】调试器或 ptrace 痕迹：运行时存在 debugger/ptrace 相关证据"
            value == "private.policy.escalated" ->
                "【服务端私有评分】额外加权：由本条记录 policyExplanation.authoritativeEventIds 中的权威事件触发；实际事件见同列表中的原始 event id"
            value == "private.policy.immediate_critical" ->
                "【服务端私有评分】即时严重：由本条记录 policyExplanation.authoritativeEventIds 中的权威事件触发 immediate critical；实际事件见同列表中的原始 event id"
            value == "private.policy.tenant_override" ->
                "【服务端租户配置】租户覆盖生效：当前 tenantId 在 PrivateRiskConfig.tenantOverrides 中存在独立策略"
            value.startsWith("private.policy.stage.") ->
                "【服务端评分阶段】stage=${value.substringAfterLast('.')}：来自 RiskScoringContext.stage，表示本次评分发生在 ingestion 或 worker 阶段"
            value.startsWith("private.policy.profile.") ->
                "【服务端部署配置】profile=${value.substringAfterLast('.')}：来自 PrivateRiskConfig.profile；production 默认 strict，staging 默认 elevated，development 默认 baseline"
            value.startsWith("private.policy.strictness.") ->
                "【服务端严格度】strictness=${value.substringAfterLast('.')}：由 PrivateRiskConfig.strictnessFor 计算；profile 默认值叠加 worker 阶段收紧、strict/relaxed tenant、tenant override"
            value.startsWith("server.policy.") ->
                "【服务端公共策略】公共评分层追加的 reason：来源于 shared rule-based scorer"
            value.startsWith("private.policy.") ->
                "【服务端私有评分】PrivateRiskScoringEngine 追加的 reason；需要结合原始检测事件和服务端配置解析"
            value == "environment.emulator.detected" || value.contains("emulator") ->
                "【模拟器】模拟器运行环境：服务端聚合到 emulator detected"
            value.contains("qemu") || value.contains("goldfish") || value.contains("ranchu") ->
                "【模拟器】QEMU/Goldfish/Ranchu 特征：Android 模拟器运行栈证据"
            value.contains("virtio") || value.contains("dummy-virt") || value.contains("vbox") ->
                "【模拟器/虚拟化】虚拟化设备特征：virtio、dummy-virt 或 vbox 相关证据"
            value.contains("mumu") || value.contains("nemu") ->
                "【模拟器/MuMu】MuMu/Nemu 运行环境证据"
            value.contains("bluestacks") || value.contains("genymotion") ||
                value.contains("ldplayer") || value.contains("nox") -> "【模拟器】第三方模拟器环境证据"
            value == "environment.risky" -> "【环境】环境异常聚合标签：请查看同列表中的具体行为明细"
            value.contains("magisk") || value.contains("zygisk") ->
                "【Root/Magisk】Magisk/Zygisk 痕迹：检测到面具或 Zygisk 相关证据"
            value.startsWith("root.") || value.contains("root") || value.contains("su.") ->
                "【Root】Root 痕迹：检测到 su/root 相关文件、包名、属性或运行环境证据"
            value.contains("frida") ->
                "【Hook/Frida】Frida 动态分析：检测到 frida 进程、库、memfd、trampoline 或相关运行时痕迹"
            value.contains("xposed") -> "【Hook/Xposed】Xposed 框架痕迹：检测到 Xposed 相关包、库或运行时特征"
            value.contains("substrate") -> "【Hook/Substrate】Substrate 注入框架痕迹"
            value.contains("hook") || value.contains("injection") ->
                "【Hook/注入】Hook 或代码注入行为：检测到 injection/hook 相关运行时证据"
            value == "integrity.ok" ->
                "【完整性】基础完整性检查通过：integrity.ok，本项不是风险"
            value.startsWith("app.tamper.signing_block_mismatch") ->
                "【完整性】APK 签名块不一致：APK Signing Block 哈希或 ID 对比不匹配"
            value == "tamper.detected" || value.contains("tamper") ->
                "【完整性/篡改】应用完整性或运行时篡改证据"
            value.startsWith("runtime.mapping.deleted_executable") ->
                "【运行时映射/事实】存在已删除可执行映射：/proc/self/maps 中有 deleted executable mapping；可能来自系统/JIT/测试工具，单独出现不等于 Hook"
            value.startsWith("runtime.mapping.memfd_executable") ->
                "【运行时映射/事实】存在内存文件可执行映射：/proc/self/maps 中有 memfd executable mapping；需结合 Frida/注入等具体标签判断"
            value.startsWith("runtime.mapping.anonymous_executable") ->
                "【运行时映射/事实】存在匿名可执行映射：/proc/self/maps 中有 anonymous executable mapping；属于采集事实，不直接代表业务风险"
            value.startsWith("runtime.mapping.") -> "【运行时映射/事实】运行时内存映射采集事实：用于辅助解释运行环境，不单独作为 Root/Hook 结论"
            value.startsWith("build.userdebug_or_eng") -> "【系统构建】系统构建类型为 userdebug/eng"
            value.startsWith("build.dev_keys") -> "【系统构建】系统使用开发签名 dev-keys"
            value.startsWith("build.tags.") -> "【系统构建】系统构建标签证据"
            value.startsWith("rom.custom") || value.startsWith("rom.") ->
                "【自定义 ROM】自定义 ROM/AOSP-like 相关证据"
            value.startsWith("gsi.") -> "【自定义 ROM/GSI】GSI 或 Treble 相关证据"
            value.startsWith("bootloader.unlocked") -> "【Bootloader】Bootloader 已解锁"
            value.startsWith("bootloader.") -> "【Bootloader】Bootloader 状态证据"
            value.startsWith("verified_boot.green") -> "【Verified Boot】绿色状态：设备启动链处于 locked/green 正常状态"
            value.startsWith("verified_boot.orange") -> "【Verified Boot】橙色状态：通常表示 bootloader 解锁或非完整验证启动"
            value.startsWith("verified_boot.red") -> "【Verified Boot】红色状态：启动链验证失败或存在严重完整性异常"
            value.startsWith("verified_boot.") -> "【Verified Boot】启动链验证状态证据"
            value.startsWith("treble.enabled") -> "【系统能力】Treble 支持已开启"
            value.startsWith("native.") -> "【Native】Native 采集事实"
            value.startsWith("device.") -> "【设备身份】设备身份采集事实"
            value.startsWith("integrity.") -> "【完整性】完整性采集事实"
            else -> "其他环境采集项"
        }
    }

    private fun JSONArray?.asStringList(): List<String> {
        if (this == null) return emptyList()
        return buildList {
            for (index in 0 until length()) {
                optString(index).trim().takeIf { it.isNotEmpty() }?.let(::add)
            }
        }
    }

    private fun sanitizeE2EMessage(message: String): String =
        message
            .replace(Regex("https?://[^\\s\\\"']+"), "http://<redacted>")
            .replace(Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}:\\d+\\b"), "<redacted-host>")
            .replace(Regex("(?i)(api[_-]?key|secret|token|bearer)(['\\\":= ]+)([^\\s,'\\\"}]+)")) {
                it.groupValues[1] + it.groupValues[2] + "<redacted>"
            }

    private fun sampleHeaderHash(value: String?): String =
        value?.trim()?.takeIf { it.isNotEmpty() }?.let(::sha256Hex).orEmpty()

    private fun emitE2E(runId: String, event: String, payload: JSONObject) {
        val envelope = JSONObject()
            .put("marker", "leona-e2e")
            .put("runId", runId)
            .put("event", event)
            .put("payload", payload)
        val encoded = Base64.encodeToString(
            envelope.toString().toByteArray(Charsets.UTF_8),
            Base64.NO_WRAP,
        )
        val total = (encoded.length + E2E_CHUNK_SIZE - 1) / E2E_CHUNK_SIZE
        for (index in 0 until total) {
            val start = index * E2E_CHUNK_SIZE
            val end = minOf(encoded.length, start + E2E_CHUNK_SIZE)
            Log.i(
                E2E_LOG_TAG,
                JSONObject()
                    .put("marker", "leona-e2e-chunk")
                    .put("runId", runId)
                    .put("event", event)
                    .put("index", index)
                    .put("total", total)
                    .put("data", encoded.substring(start, end))
                    .toString(),
            )
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
        return "上报端点=$reporting\n云配置=$cloudConfig\n演示后端=$demoBackend"
    }

    private fun renderDiagnostics(snapshot: LeonaDiagnosticSnapshot): String =
        getString(
            R.string.diagnostic_fmt,
            snapshot.deviceId,
            snapshot.installId,
            snapshot.canonicalDeviceId ?: "-",
            snapshot.fingerprintHash,
            snapshot.fingerprintSchemaVersion.toString(),
            snapshot.fingerprintSource,
            snapshot.identityAnchorSource,
            snapshot.canonicalDeviceIdSource,
            formatTranslatedEvidence(snapshot.evidenceSignals),
            formatTranslatedEvidence(snapshot.nativeFactTags),
            translateNativeSeverity(snapshot.nativeHighestSeverity),
            formatTranslatedEvidence(snapshot.nativeFindingIds),
            translateDecision(snapshot.serverDecision),
            translateAction(snapshot.serverAction),
            translateEvidenceLevel(snapshot.serverRiskLevel),
            snapshot.serverRiskScore?.toString() ?: "-",
            formatTranslatedEvidence(snapshot.serverRiskTags),
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
            snapshot.session?.deviceBindingStatus ?: "-",
            snapshot.session?.serverAttestation?.provider ?: "-",
            snapshot.session?.serverAttestation?.status ?: "-",
            snapshot.session?.serverAttestation?.code ?: "-",
            snapshot.session?.serverAttestation?.retryable?.toString() ?: "-",
            snapshot.lastAttestation?.format ?: "-",
            snapshot.lastAttestation?.tokenSha256 ?: "-",
            snapshot.lastHandshakeError ?: "-",
            snapshot.lastHandshakeErrorCode ?: "-",
            snapshot.lastHandshakeErrorProvider ?: "-",
            snapshot.lastHandshakeRetryable?.toString() ?: "-",
        )

    private fun renderSupportBundle(bundle: LeonaSupportBundle): String =
        getString(
            R.string.support_bundle_fmt,
            bundle.diagnosticSnapshot.canonicalDeviceId ?: "-",
            bundle.diagnosticSnapshot.fingerprintSchemaVersion.toString(),
            bundle.diagnosticSnapshot.fingerprintSource,
            bundle.diagnosticSnapshot.identityAnchorSource,
            bundle.diagnosticSnapshot.canonicalDeviceIdSource,
            bundle.effectiveDisabledSignals.toSortedSet().joinToString(",").ifBlank { "-" },
            bundle.effectiveDisableCollectionWindowMs.toString(),
            bundle.cloudConfigFetchedAtMillis?.toString() ?: "-",
            if (bundle.cloudConfigRawJson.isNullOrBlank()) "false" else "true",
            bundle.secureTransport?.session?.canonicalDeviceId ?: "-",
            bundle.serverVerdict?.canonicalDeviceId ?: "-",
            bundle.secureTransport?.session?.deviceBindingStatus ?: "-",
            bundle.secureTransport?.session?.serverAttestation?.provider ?: "-",
            bundle.secureTransport?.session?.serverAttestation?.status ?: "-",
            bundle.secureTransport?.session?.serverAttestation?.code ?: "-",
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
        button: Button,
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
        clipboard.setPrimaryClip(ClipData.newPlainText("leona-verdict-json", json))
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

    companion object {
        private const val E2E_LOG_TAG = "LeonaE2E"
        private const val E2E_CHUNK_SIZE = 3000
        private const val EXTRA_E2E_AUTO_RUN = "io.leonasec.leona.sample.extra.E2E_AUTO_RUN"
        private const val EXTRA_E2E_TOKEN = "io.leonasec.leona.sample.extra.E2E_TOKEN"
    }
}

private fun JSONObject.removeAndReturn(name: String): JSONObject {
    remove(name)
    return this
}

private fun sha256Hex(value: String): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
    return digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
