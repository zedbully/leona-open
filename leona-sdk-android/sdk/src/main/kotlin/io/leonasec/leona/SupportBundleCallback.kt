/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

/** Callback for [Leona.getSupportBundle]. */
interface SupportBundleCallback {
    fun onResult(bundle: LeonaSupportBundle)
    fun onError(cause: Throwable)
}
