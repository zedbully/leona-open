/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.runtime

import android.os.Build
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.MessageDigest
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Project-owned native runtime smoke only. This does not initialize the public
 * reporting channel or contact a provider/server; it proves the packaged OSS
 * JNI library can load, initialize, and return a bounded opaque collection.
 */
@RunWith(AndroidJUnit4::class)
class NativeRuntimeSmokeTest {

    @Test
    fun packagedNativeRuntimeLoadsInitializesAndCollects() {
        val context = InstrumentationRegistry.getInstrumentation().context
        val runtime = OssNativeRuntime

        runtime.load()
        runtime.init(context, 0L, "", "")
        val payload = runtime.collect()

        assertTrue("native payload exceeds bounded smoke cap", payload.size <= MAX_PAYLOAD_BYTES)
        val digest = MessageDigest.getInstance("SHA-256").digest(payload).toHex()
        Log.i(
            TAG,
            "LEONA_NATIVE_SMOKE_RESULT api=${Build.VERSION.SDK_INT} " +
                "abi=${Build.SUPPORTED_ABIS.firstOrNull().orEmpty()} " +
                "payloadBytes=${payload.size} payloadSha256=$digest",
        )
    }

    private fun ByteArray.toHex(): String =
        joinToString(separator = "") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private companion object {
        const val MAX_PAYLOAD_BYTES = 131_072
        const val TAG = "LeonaNativeSmoke"
    }
}
