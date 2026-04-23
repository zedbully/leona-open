/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path

class TamperJvmParityTest {

    @Test
    fun `tamper baseline fields stay aligned across config policy parser and integrity snapshot`() {
        val repoRoot = resolveRepoRoot()
        val configFields = extract(
            repoRoot.resolve("sdk/src/main/kotlin/io/leonasec/leona/config/LeonaConfig.kt"),
            Regex("""val\s+(expected[A-Z][A-Za-z0-9]+|allowed[A-Z][A-Za-z0-9]+):"""),
        )
        val policyFields = extract(
            repoRoot.resolve("sdk/src/main/kotlin/io/leonasec/leona/internal/TamperPolicy.kt"),
            Regex("""val\s+(expected[A-Z][A-Za-z0-9]+|allowed[A-Z][A-Za-z0-9]+):"""),
        )
        val parsedBySecureChannel = extract(
            repoRoot.resolve("sdk/src/main/kotlin/io/leonasec/leona/internal/SecureChannel.kt"),
            Regex("""\b(expected[A-Z][A-Za-z0-9]+|allowed[A-Z][A-Za-z0-9]+)\s*="""),
        )
        val referencedByAppIntegrity = extract(
            repoRoot.resolve("sdk/src/main/kotlin/io/leonasec/leona/internal/AppIntegrity.kt"),
            Regex("""policy\.(expected[A-Z][A-Za-z0-9]+|allowed[A-Z][A-Za-z0-9]+)"""),
        )

        assertEquals("LeonaConfig/TamperPolicy fields diverged", configFields, policyFields)
        assertEquals("SecureChannel.parseServerTamperPolicy is missing fields", policyFields, parsedBySecureChannel)
        assertEquals("AppIntegrity capture/capturePolicy is missing fields", policyFields, referencedByAppIntegrity)
    }

    private fun resolveRepoRoot(): Path {
        var current = Path.of("").toAbsolutePath()
        repeat(8) {
            if (Files.exists(current.resolve("settings.gradle.kts")) &&
                Files.exists(current.resolve("sdk/src/main/kotlin/io/leonasec/leona/config/LeonaConfig.kt"))
            ) {
                return current
            }
            current = current.parent ?: return@repeat
        }
        error("Unable to resolve leona-sdk-android repo root from ${Path.of("").toAbsolutePath()}")
    }

    private fun extract(path: Path, regex: Regex): Set<String> =
        regex.findAll(path.readText())
            .map { it.groupValues[1] }
            .toSet()

    private fun Path.readText(): String = String(Files.readAllBytes(this))
}
