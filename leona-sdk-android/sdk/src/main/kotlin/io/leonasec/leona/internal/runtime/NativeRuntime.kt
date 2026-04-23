/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.runtime

import android.content.Context

/**
 * Internal runtime boundary for the sensitive detection engine.
 *
 * Public/open-source code talks only to this interface. A closed-source
 * Android library can provide its own implementation and package it beside
 * the public SDK, while the OSS build falls back to [OssNativeRuntime].
 */
interface NativeRuntime {
    fun load()
    fun init(
        context: Context,
        configFlags: Long,
        integritySnapshot: String,
        tamperPolicySnapshot: String,
    )

    fun updateTamperContext(
        integritySnapshot: String,
        tamperPolicySnapshot: String,
    )

    fun collect(): ByteArray
    fun decoyCheck(): Boolean
    fun honeypotFakeKey(lengthBytes: Int): ByteArray
    fun honeypotFakeToken(salt: ByteArray, tokenLengthBytes: Int): ByteArray
}
