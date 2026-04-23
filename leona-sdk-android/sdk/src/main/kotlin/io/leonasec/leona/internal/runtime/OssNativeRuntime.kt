/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.runtime

import android.content.Context
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Default open-source runtime.
 *
 * Internal/private distributions can override this at runtime by shipping a
 * class named `io.leonasec.leona.privatecore.PrivateNativeRuntime` that
 * implements [NativeRuntime].
 */
object OssNativeRuntime : NativeRuntime {

    private val loaded = AtomicBoolean(false)

    override fun load() {
        if (!loaded.compareAndSet(false, true)) return
        System.loadLibrary("leona")
    }

    override external fun init(
        context: Context,
        configFlags: Long,
        integritySnapshot: String,
        tamperPolicySnapshot: String,
    )

    override external fun updateTamperContext(
        integritySnapshot: String,
        tamperPolicySnapshot: String,
    )

    override external fun collect(): ByteArray

    override external fun decoyCheck(): Boolean

    override external fun honeypotFakeKey(lengthBytes: Int): ByteArray

    override external fun honeypotFakeToken(salt: ByteArray, tokenLengthBytes: Int): ByteArray
}
