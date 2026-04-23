/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

/** Callback for [Leona.getSecureTransportSnapshot]. */
interface SecureTransportSnapshotCallback {
    fun onResult(snapshot: LeonaSecureTransportSnapshot)
    fun onError(cause: Throwable)
}
