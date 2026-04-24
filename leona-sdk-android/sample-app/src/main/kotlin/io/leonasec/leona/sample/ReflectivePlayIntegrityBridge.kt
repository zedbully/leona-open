/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.Context
import io.leonasec.leona.config.PlayIntegrityTokenRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Optional reflection-based StandardIntegrityManager bridge.
 *
 * This lets the sample app auto-wire a real Play Integrity bridge when the app
 * adds the Google dependency, without forcing the dependency in this repo.
 *
 * Based on Android's standard request flow:
 * - IntegrityManagerFactory.createStandard(...)
 * - prepareIntegrityToken(PrepareIntegrityTokenRequest)
 * - StandardIntegrityTokenProvider.request(StandardIntegrityTokenRequest)
 *
 * Official refs:
 * - https://developer.android.com/google/play/integrity/standard
 * - https://developer.android.com/google/play/integrity/reference/com/google/android/play/core/integrity/StandardIntegrityManager
 */
class ReflectivePlayIntegrityBridge private constructor(
    context: Context,
    private val cloudProjectNumber: Long,
) : SamplePlayIntegrity.Bridge {

    private val appContext = context.applicationContext
    private val api = ReflectionApi.load()

    @Volatile
    private var tokenProvider: Any? = null

    override suspend fun requestToken(request: PlayIntegrityTokenRequest): String? = withContext(Dispatchers.IO) {
        val provider = tokenProvider ?: synchronized(this@ReflectivePlayIntegrityBridge) {
            tokenProvider ?: prepareTokenProvider().also { tokenProvider = it }
        }

        runCatching {
            requestToken(provider, request)
        }.recoverCatching {
            synchronized(this@ReflectivePlayIntegrityBridge) { tokenProvider = null }
            val refreshed = prepareTokenProvider()
            synchronized(this@ReflectivePlayIntegrityBridge) { tokenProvider = refreshed }
            requestToken(refreshed, request)
        }.getOrThrow()
    }

    private fun prepareTokenProvider(): Any {
        val manager = api.createStandardManager(appContext)
        val prepareRequest = api.buildPrepareRequest(cloudProjectNumber)
        val task = api.prepareIntegrityToken(manager, prepareRequest)
        return api.awaitTask(task)
    }

    private fun requestToken(
        provider: Any,
        request: PlayIntegrityTokenRequest,
    ): String {
        val tokenRequest = api.buildTokenRequest(request.requestHash)
        val task = api.request(provider, tokenRequest)
        val token = api.awaitTask(task)
        return api.extractToken(token)
    }

    companion object {
        fun createIfAvailable(
            context: Context,
            cloudProjectNumber: Long?,
        ): SamplePlayIntegrity.Bridge? {
            val projectNumber = cloudProjectNumber ?: return null
            return runCatching {
                ReflectivePlayIntegrityBridge(context, projectNumber)
            }.getOrNull()
        }
    }

    private class ReflectionApi private constructor(
        private val taskClass: Class<*>,
        private val tasksClass: Class<*>,
        private val integrityManagerFactoryClass: Class<*>,
        private val standardIntegrityManagerClass: Class<*>,
        private val prepareRequestClass: Class<*>,
        private val tokenRequestClass: Class<*>,
        private val tokenProviderClass: Class<*>,
        private val tokenClass: Class<*>,
    ) {
        fun createStandardManager(context: Context): Any =
            integrityManagerFactoryClass
                .getMethod("createStandard", Context::class.java)
                .invoke(null, context)
                ?: error("createStandard returned null")

        fun buildPrepareRequest(cloudProjectNumber: Long): Any {
            val builder = prepareRequestClass.getMethod("builder").invoke(null)
            builder.javaClass
                .getMethod("setCloudProjectNumber", Long::class.javaPrimitiveType)
                .invoke(builder, cloudProjectNumber)
            return builder.javaClass.getMethod("build").invoke(builder)
                ?: error("PrepareIntegrityTokenRequest.build returned null")
        }

        fun prepareIntegrityToken(
            manager: Any,
            request: Any,
        ): Any = standardIntegrityManagerClass
            .getMethod("prepareIntegrityToken", prepareRequestClass)
            .invoke(manager, request)
            ?: error("prepareIntegrityToken returned null")

        fun buildTokenRequest(requestHash: String): Any {
            val builder = tokenRequestClass.getMethod("builder").invoke(null)
            builder.javaClass
                .getMethod("setRequestHash", String::class.java)
                .invoke(builder, requestHash)
            return builder.javaClass.getMethod("build").invoke(builder)
                ?: error("StandardIntegrityTokenRequest.build returned null")
        }

        fun request(
            provider: Any,
            request: Any,
        ): Any = tokenProviderClass
            .getMethod("request", tokenRequestClass)
            .invoke(provider, request)
            ?: error("StandardIntegrityTokenProvider.request returned null")

        fun extractToken(token: Any): String =
            tokenClass.getMethod("token").invoke(token) as String

        fun awaitTask(task: Any): Any = tasksClass
            .getMethod("await", taskClass)
            .invoke(null, task)
            ?: error("Tasks.await returned null")

        companion object {
            fun load(): ReflectionApi {
                val taskClass = Class.forName("com.google.android.gms.tasks.Task")
                val tasksClass = Class.forName("com.google.android.gms.tasks.Tasks")
                val integrityManagerFactoryClass =
                    Class.forName("com.google.android.play.core.integrity.IntegrityManagerFactory")
                val standardIntegrityManagerClass =
                    Class.forName("com.google.android.play.core.integrity.StandardIntegrityManager")
                val prepareRequestClass =
                    Class.forName("com.google.android.play.core.integrity.StandardIntegrityManager\$PrepareIntegrityTokenRequest")
                val tokenRequestClass =
                    Class.forName("com.google.android.play.core.integrity.StandardIntegrityManager\$StandardIntegrityTokenRequest")
                val tokenProviderClass =
                    Class.forName("com.google.android.play.core.integrity.StandardIntegrityManager\$StandardIntegrityTokenProvider")
                val tokenClass =
                    Class.forName("com.google.android.play.core.integrity.StandardIntegrityManager\$StandardIntegrityToken")

                return ReflectionApi(
                    taskClass = taskClass,
                    tasksClass = tasksClass,
                    integrityManagerFactoryClass = integrityManagerFactoryClass,
                    standardIntegrityManagerClass = standardIntegrityManagerClass,
                    prepareRequestClass = prepareRequestClass,
                    tokenRequestClass = tokenRequestClass,
                    tokenProviderClass = tokenProviderClass,
                    tokenClass = tokenClass,
                )
            }
        }
    }
}
