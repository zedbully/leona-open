/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

/** Callback for [Leona.getDiagnosticSnapshotJson]. */
interface DiagnosticJsonCallback {
    fun onResult(snapshotJson: String)
    fun onError(cause: Throwable)
}
