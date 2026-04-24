/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.sample

import android.content.Context
import io.leonasec.leona.config.AttestationException
import io.leonasec.leona.config.AttestationFailureCodes
import io.leonasec.leona.config.AttestationFormats
import io.leonasec.leona.config.PlayIntegrityTokenRequest
import java.lang.reflect.InvocationTargetException
import java.util.concurrent.ExecutionException
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
        try {
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
        } catch (error: Throwable) {
            throw normalizePlayIntegrityFailure(error)
        }
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

    private fun normalizePlayIntegrityFailure(error: Throwable): Throwable {
        if (error is AttestationException) return error
        val root = unwrapWrapper(error)
        if (root.javaClass.name != STANDARD_INTEGRITY_EXCEPTION_CLASS) return root
        val errorCode = runCatching {
            root.javaClass.getMethod("getErrorCode").invoke(root) as? Int
        }.getOrNull()
        return AttestationException(
            provider = AttestationFormats.PLAY_INTEGRITY,
            code = mapPlayIntegrityErrorCode(errorCode),
            retryable = isRetryablePlayIntegrityError(errorCode),
            message = root.message ?: root.javaClass.name,
            cause = root,
        )
    }

    private fun unwrapWrapper(error: Throwable): Throwable = when (error) {
        is InvocationTargetException -> error.targetException ?: error.cause ?: error
        is ExecutionException -> error.cause ?: error
        else -> error
    }.let { unwrapped ->
        if (unwrapped === error) error else unwrapWrapper(unwrapped)
    }

    private fun mapPlayIntegrityErrorCode(errorCode: Int?): String = when (errorCode) {
        0 -> AttestationFailureCodes.PLAY_INTEGRITY_NO_ERROR
        -1 -> AttestationFailureCodes.PLAY_INTEGRITY_API_NOT_AVAILABLE
        -2 -> AttestationFailureCodes.PLAY_INTEGRITY_PLAY_STORE_NOT_FOUND
        -3 -> AttestationFailureCodes.PLAY_INTEGRITY_NETWORK_ERROR
        -5 -> AttestationFailureCodes.PLAY_INTEGRITY_APP_NOT_INSTALLED
        -6 -> AttestationFailureCodes.PLAY_INTEGRITY_PLAY_SERVICES_NOT_FOUND
        -7 -> AttestationFailureCodes.PLAY_INTEGRITY_APP_UID_MISMATCH
        -8 -> AttestationFailureCodes.PLAY_INTEGRITY_TOO_MANY_REQUESTS
        -9 -> AttestationFailureCodes.PLAY_INTEGRITY_CANNOT_BIND_TO_SERVICE
        -12 -> AttestationFailureCodes.PLAY_INTEGRITY_GOOGLE_SERVER_UNAVAILABLE
        -14 -> AttestationFailureCodes.PLAY_INTEGRITY_PLAY_STORE_VERSION_OUTDATED
        -15 -> AttestationFailureCodes.PLAY_INTEGRITY_PLAY_SERVICES_VERSION_OUTDATED
        -16 -> AttestationFailureCodes.PLAY_INTEGRITY_CLOUD_PROJECT_NUMBER_IS_INVALID
        -17 -> AttestationFailureCodes.PLAY_INTEGRITY_REQUEST_HASH_TOO_LONG
        -18 -> AttestationFailureCodes.PLAY_INTEGRITY_CLIENT_TRANSIENT_ERROR
        -19 -> AttestationFailureCodes.PLAY_INTEGRITY_INTEGRITY_TOKEN_PROVIDER_INVALID
        -100 -> AttestationFailureCodes.PLAY_INTEGRITY_INTERNAL_ERROR
        else -> AttestationFailureCodes.PLAY_INTEGRITY_UNKNOWN
    }

    private fun isRetryablePlayIntegrityError(errorCode: Int?): Boolean = when (errorCode) {
        -8, -9, -12, -18, -19, -100 -> true
        else -> false
    }

    companion object {
        private const val STANDARD_INTEGRITY_EXCEPTION_CLASS =
            "com.google.android.play.core.integrity.StandardIntegrityException"

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

        fun awaitTask(task: Any): Any = try {
            tasksClass
                .getMethod("await", taskClass)
                .invoke(null, task)
                ?: error("Tasks.await returned null")
        } catch (error: InvocationTargetException) {
            throw (error.targetException ?: error.cause ?: error)
        }

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
