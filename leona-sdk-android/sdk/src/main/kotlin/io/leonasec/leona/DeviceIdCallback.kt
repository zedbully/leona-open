/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona

/** Callback for [Leona.getDeviceId]. */
interface DeviceIdCallback {
    fun onResult(deviceId: String)
    fun onError(cause: Throwable)
}
