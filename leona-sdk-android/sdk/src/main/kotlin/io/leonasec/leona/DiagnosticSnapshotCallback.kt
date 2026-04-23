/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

/** Callback for [Leona.getDiagnosticSnapshot]. */
interface DiagnosticSnapshotCallback {
    fun onResult(snapshot: LeonaDiagnosticSnapshot)
    fun onError(cause: Throwable)
}
