/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

/**
 * Build-time constants. In a production pipeline these are substituted by
 * Gradle at compile time (BuildConfig). For now we hardcode — cheap to fix
 * later, avoids pulling in another plugin just to expose a version string.
 */
internal object BuildConstants {
    const val VERSION_NAME = "0.1.0-alpha.1"
}
