/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

internal object NativePayloadInspector {

    data class NativeFinding(
        val id: String,
        val severity: Int,
        val category: Int,
        val message: String,
    )

    data class NativeRiskSummary(
        val findings: List<NativeFinding>,
        val riskTags: Set<String>,
        val highestSeverity: Int?,
    ) {
        val findingIds: List<String> = findings.map(NativeFinding::id)
        val eventCount: Int = findings.size

        companion object {
            val EMPTY = NativeRiskSummary(
                findings = emptyList(),
                riskTags = emptySet(),
                highestSeverity = null,
            )
        }
    }

    fun inspect(payload: ByteArray): NativeRiskSummary {
        if (payload.isEmpty()) return NativeRiskSummary.EMPTY
        val decoded = unscramble(payload)
        if (!decoded.hasHeader()) return NativeRiskSummary.EMPTY

        return runCatching {
            var offset = HEADER_SIZE
            val eventCount = decoded.u16(EVENT_COUNT_OFFSET)
            val findings = buildList {
                repeat(eventCount) {
                    val id = decoded.readString(offset)
                    offset = id.nextOffset
                    val severity = decoded.u8(offset)
                    offset += 1
                    val category = decoded.u8(offset)
                    offset += 1
                    val message = decoded.readString(offset)
                    offset = message.nextOffset
                    val evidence = decoded.readString(offset)
                    offset = evidence.nextOffset
                    add(
                        NativeFinding(
                            id = id.value,
                            severity = severity,
                            category = category,
                            message = message.value,
                        ),
                    )
                }
            }
            NativeRiskSummary(
                findings = findings,
                riskTags = findings.flatMapTo(linkedSetOf(), ::riskTagsFor),
                highestSeverity = findings.maxOfOrNull { it.severity },
            )
        }.getOrDefault(NativeRiskSummary.EMPTY)
    }

    private fun unscramble(payload: ByteArray): ByteArray {
        val copy = payload.copyOf()
        var k = 0x5C
        for (i in copy.indices) {
            copy[i] = (copy[i].toInt() xor k).toByte()
            k = (k * 31 + 17) and 0xFF
        }
        return copy
    }

    private fun ByteArray.hasHeader(): Boolean =
        size >= HEADER_SIZE &&
            this[0] == 'L'.code.toByte() &&
            this[1] == 'N'.code.toByte() &&
            this[2] == 'A'.code.toByte() &&
            this[3] == '1'.code.toByte() &&
            this[VERSION_OFFSET] == 0x01.toByte()

    private fun ByteArray.u8(offset: Int): Int =
        getOrNull(offset)?.toInt()?.and(0xFF)
            ?: error("Invalid payload offset=$offset")

    private fun ByteArray.u16(offset: Int): Int {
        val b0 = u8(offset)
        val b1 = u8(offset + 1)
        return b0 or (b1 shl 8)
    }

    private data class ParsedString(
        val value: String,
        val nextOffset: Int,
    )

    private fun ByteArray.readString(offset: Int): ParsedString {
        val len = u16(offset)
        val start = offset + 2
        val end = start + len
        if (start < 0 || end > size) error("Malformed payload string")
        return ParsedString(
            value = decodeToString(start, end),
            nextOffset = end,
        )
    }

    private fun riskTagsFor(finding: NativeFinding): Set<String> {
        val id = finding.id
        return buildSet {
            when {
                id.startsWith("injection.frida.") || id.startsWith("frida.") -> {
                    add("hook.frida.native")
                    add("hook.injection.native")
                }

                id.startsWith("injection.ptrace.") -> {
                    add("debugger.native_ptrace")
                    add("hook.injection.native")
                }

                id.startsWith("injection.") -> add("hook.injection.native")
                id.startsWith("xposed.") -> {
                    add("hook.xposed.native")
                    add("hook.injection.native")
                }

                id.startsWith("root.") -> add("root.native")
                id.startsWith("environment.emulator.") ||
                    id == "environment.emulator" ||
                    id.startsWith("env.emulator.") ||
                    id == "env.emulator" -> add("environment.emulator.native")
                id.startsWith("unidbg.") -> add("environment.unidbg.native")
                id.startsWith("tamper.") -> {
                    add("tamper.native")
                    when {
                        ".installer." in id -> add("installer.untrusted.native")
                        ".signature." in id -> add("signature.untrusted.native")
                        ".package_name." in id -> add("package.name_mismatch.native")
                        ".debuggable." in id -> add("app.debuggable.native")
                        ".apk_" in id ||
                            ".dex_" in id ||
                            ".elf_" in id ||
                            ".split_" in id ||
                            ".manifest_" in id ||
                            ".component_" in id ||
                            ".intent_filter_" in id ||
                            ".provider_" in id ||
                            ".permission_" in id ||
                            ".metadata." in id ||
                            ".grant_uri_permission_" in id -> add("tamper.code_or_manifest.native")
                    }
                }
            }
        }
    }

    private const val VERSION_OFFSET = 4
    private const val EVENT_COUNT_OFFSET = 6
    private const val HEADER_SIZE = 8
}
