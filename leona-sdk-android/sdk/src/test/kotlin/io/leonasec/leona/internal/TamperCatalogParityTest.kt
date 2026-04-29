/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.file.Files
import java.nio.file.Path

class TamperCatalogParityTest {

    @Test
    fun `public and private tamper catalogs stay aligned with detector usage`() {
        val repoRoot = resolveRepoRoot()
        val publicCatalog = repoRoot.resolve("sdk/src/main/cpp/detection/tamper_catalog.h")
        val privateCatalog = repoRoot.resolve("private/sdk-private-core/src/main/cpp/private_tamper_catalog.h")
        val detector = repoRoot.resolve("sdk/src/main/cpp/detection/tamper_detector.cpp")

        val publicFields = extractCatalogFields(publicCatalog)
        val detectorFields = extractDetectorFields(detector)

        assertEquals("detector references fields missing from catalog", publicFields, detectorFields)

        assumeTrue(
            "private tamper catalog not present; skipping public/private parity check",
            Files.exists(privateCatalog),
        )
        val privateFields = extractPrivateOverrideFields(privateCatalog)
        assertEquals("public/private tamper catalogs diverged", publicFields, privateFields)
    }

    private fun resolveRepoRoot(): Path {
        var current = Path.of("").toAbsolutePath()
        repeat(8) {
            if (Files.exists(current.resolve("settings.gradle.kts")) &&
                Files.exists(current.resolve("sdk/src/main/cpp/detection/tamper_catalog.h"))
            ) {
                return current
            }
            current = current.parent ?: return@repeat
        }
        error("Unable to resolve leona-sdk-android repo root from ${Path.of("").toAbsolutePath()}")
    }

    private fun extractCatalogFields(path: Path): Set<String> =
        Regex("""bool\s+(expected_[a-z0-9_]+|allowed_[a-z0-9_]+)\s*=\s*false;""")
            .findAll(path.readText())
            .map { it.groupValues[1] }
            .toSet()

    private fun extractDetectorFields(path: Path): Set<String> =
        Regex("""catalog\.(expected_[a-z0-9_]+|allowed_[a-z0-9_]+)""")
            .findAll(path.readText())
            .map { it.groupValues[1] }
            .toSet()

    private fun extractPrivateOverrideFields(path: Path): Set<String> =
        Regex("""catalog\.(expected_[a-z0-9_]+|allowed_[a-z0-9_]+)\s*=\s*true;""")
            .findAll(path.readText())
            .map { it.groupValues[1] }
            .toSet()

    private fun Path.readText(): String = String(Files.readAllBytes(this))
}
