/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

internal data class CollectionPolicy(
    val disabledSignals: Set<String> = emptySet(),
    val disableCollectionWindowMs: Long = -1L,
)
