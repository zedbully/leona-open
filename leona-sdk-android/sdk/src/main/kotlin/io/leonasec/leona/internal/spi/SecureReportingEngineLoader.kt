/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.spi

import android.content.Context
import io.leonasec.leona.config.LeonaConfig

internal object SecureReportingEngineLoader {

    private const val IMPLEMENTATION_CLASS = "io.leonasec.leona.privatecore.DefaultSecureReportingEngine"

    fun load(context: Context, config: LeonaConfig, sdkVersion: String): SecureReportingEngine? =
        runCatching {
            val clazz = Class.forName(IMPLEMENTATION_CLASS)
            val ctor = clazz.getConstructor(Context::class.java, LeonaConfig::class.java, String::class.java)
            ctor.newInstance(context.applicationContext, config, sdkVersion) as SecureReportingEngine
        }.getOrNull()
}
