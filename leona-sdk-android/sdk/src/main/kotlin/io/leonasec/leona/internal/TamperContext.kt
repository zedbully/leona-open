/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

data class TamperContext(
    val integritySnapshot: String,
    val policySnapshot: String,
)
