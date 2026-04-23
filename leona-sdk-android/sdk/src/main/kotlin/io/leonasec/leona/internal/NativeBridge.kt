/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import io.leonasec.leona.internal.runtime.NativeRuntime
import io.leonasec.leona.internal.runtime.OssNativeRuntime

/**
 * Single JNI boundary.
 *
 * Design principle (supports architectural principle #A): the JVM side never
 * receives typed detection events. The native layer runs all detectors,
 * aggregates them, and returns a single opaque byte payload. A reverse
 * engineer hooking a method on this class sees only bytes they can't decode.
 */
internal object NativeBridge {

    private const val PRIVATE_RUNTIME_CLASS =
        "io.leonasec.leona.privatecore.PrivateNativeRuntime"

    private val runtime: NativeRuntime by lazy(::resolveRuntime)

    private fun resolveRuntime(): NativeRuntime =
        runCatching {
            val clazz = Class.forName(PRIVATE_RUNTIME_CLASS)
            val instance = clazz.getDeclaredConstructor().newInstance()
            check(instance is NativeRuntime) {
                "$PRIVATE_RUNTIME_CLASS must implement NativeRuntime"
            }
            instance
        }.getOrElse { OssNativeRuntime }

    fun load() {
        runtime.load()
    }

    /** One-time native initialization. Stores config flags for later use. */
    fun init(
        context: Context,
        configFlags: Long,
        integritySnapshot: String,
        tamperPolicySnapshot: String,
    ) = runtime.init(context, configFlags, integritySnapshot, tamperPolicySnapshot)

    fun updateTamperContext(
        integritySnapshot: String,
        tamperPolicySnapshot: String,
    ) = runtime.updateTamperContext(integritySnapshot, tamperPolicySnapshot)

    /**
     * Runs all enabled detectors and returns an opaque payload blob.
     *
     * The blob format is intentionally unspecified here; only the native
     * collector and the matching [SecureChannel] understand it. Do not parse
     * this on the JVM side — it's the first layer of the onion.
     */
    fun collect(): ByteArray = runtime.collect()

    /**
     * Backing for [io.leonasec.leona.Leona.quickCheck] — the decoy API.
     * Keeps its own implementation separate so patching this does not affect
     * [collect]. This is a key tenet of architectural principle #C.
     */
    fun decoyCheck(): Boolean = runtime.decoyCheck()

    // --- Honeypot primitives -----------------------------------------------
    // Deterministic-looking but server-verifiable fake data. See
    // io.leonasec.leona.Honeypot for the public API that wraps these.

    fun honeypotFakeKey(lengthBytes: Int): ByteArray = runtime.honeypotFakeKey(lengthBytes)

    fun honeypotFakeToken(salt: ByteArray, tokenLengthBytes: Int): ByteArray =
        runtime.honeypotFakeToken(salt, tokenLengthBytes)
}
