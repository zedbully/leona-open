/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal

import android.content.Context
import android.content.SharedPreferences
import io.leonasec.leona.config.LeonaConfig
import io.leonasec.leona.internal.spi.SecureDeviceContext
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock

class SecureChannelTest {

    @Test
    fun `upload returns a non-empty BoxId for alpha stub`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(ctx, LeonaConfig.Builder().build())

        val id = channel.upload(byteArrayOf(1, 2, 3, 4), deviceContext())
        assertNotNull(id)
        assertTrue(id.boxId.toString().isNotEmpty())
    }

    @Test
    fun `each upload returns a unique BoxId`() = runBlocking {
        val ctx = mockContext()
        val channel = SecureChannel(ctx, LeonaConfig.Builder().build())

        val id1 = channel.upload(byteArrayOf(), deviceContext())
        val id2 = channel.upload(byteArrayOf(), deviceContext())
        assertNotEquals(id1, id2)
    }

    @Test
    fun `server tamper parser keeps component provider and application semantic baselines`() {
        val policy = parseServerTamperPolicy(
            """
            {
              "expectedQueriesPackageSemanticsSha256": "11AB",
              "expectedQueriesProviderSemanticsSha256": "22BC",
              "expectedQueriesIntentSemanticsSha256": "33CD",
              "expectedSigningCertificateLineageSha256": "66FA",
              "expectedApkSigningBlockSha256": "88BC",
              "expectedApkSigningBlockIdSha256": {
                "0x7109871a": "99CD"
              },
              "expectedResourcesArscSha256": "44DE",
              "expectedResourceInventorySha256": "77AB",
              "expectedResourceEntrySha256": {
                "res/raw/leona.bin": "55EF"
              },
              "expectedComponentAccessSemanticsSha256": {
                "activity:com.example.MainActivity": "AA11"
              },
              "expectedComponentOperationalSemanticsSha256": {
                "service:com.example.SyncService": "BB22"
              },
              "expectedProviderAccessSemanticsSha256": {
                "provider:com.example.DataProvider": "CC33"
              },
              "expectedProviderOperationalSemanticsSha256": {
                "provider:com.example.DataProvider": "DD44"
              },
              "expectedIntentFilterSemanticsSha256": {
                "activity:com.example.MainActivity": "ABCD"
              },
              "expectedGrantUriPermissionSemanticsSha256": {
                "provider:com.example.DataProvider": "DCBA"
              },
              "expectedMetaDataType": {
                "channel": "STRING"
              },
              "expectedMetaDataValueSha256": {
                "channel": "A1B2"
              },
              "expectedManifestMetaDataEntrySha256": {
                "channel": "B1C2"
              },
              "expectedManifestMetaDataSemanticsSha256": {
                "channel": "C1D2"
              },
              "expectedUsesFeatureFieldValues": {
                "uses-feature:android.hardware.camera#required": "false"
              },
              "expectedUsesSdkFieldValues": {
                "uses-sdk#targetSdkVersion": "34"
              },
              "expectedUsesLibraryFieldValues": {
                "uses-library:org.apache.http.legacy#required": "true"
              },
              "expectedUsesNativeLibraryFieldValues": {
                "uses-native-library:com.example.sec#required": "false"
              },
              "expectedApplicationSecuritySemanticsSha256": "EE55",
              "expectedApplicationRuntimeSemanticsSha256": "FF66",
              "expectedApplicationFieldValues": {
                "application#usesCleartextTraffic": "false"
              }
            }
            """.trimIndent(),
        )

        assertEquals(
            mapOf("activity:com.example.MainActivity" to "aa11"),
            policy.expectedComponentAccessSemanticsSha256,
        )
        assertEquals("11ab", policy.expectedQueriesPackageSemanticsSha256)
        assertEquals("22bc", policy.expectedQueriesProviderSemanticsSha256)
        assertEquals("33cd", policy.expectedQueriesIntentSemanticsSha256)
        assertEquals("66fa", policy.expectedSigningCertificateLineageSha256)
        assertEquals("88bc", policy.expectedApkSigningBlockSha256)
        assertEquals(mapOf("0x7109871a" to "99cd"), policy.expectedApkSigningBlockIdSha256)
        assertEquals("44de", policy.expectedResourcesArscSha256)
        assertEquals("77ab", policy.expectedResourceInventorySha256)
        assertEquals(mapOf("res/raw/leona.bin" to "55ef"), policy.expectedResourceEntrySha256)
        assertEquals(
            mapOf("service:com.example.SyncService" to "bb22"),
            policy.expectedComponentOperationalSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "cc33"),
            policy.expectedProviderAccessSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "dd44"),
            policy.expectedProviderOperationalSemanticsSha256,
        )
        assertEquals(
            mapOf("activity:com.example.MainActivity" to "abcd"),
            policy.expectedIntentFilterSemanticsSha256,
        )
        assertEquals(
            mapOf("provider:com.example.DataProvider" to "dcba"),
            policy.expectedGrantUriPermissionSemanticsSha256,
        )
        assertEquals(mapOf("channel" to "string"), policy.expectedMetaDataType)
        assertEquals(mapOf("channel" to "a1b2"), policy.expectedMetaDataValueSha256)
        assertEquals(mapOf("channel" to "b1c2"), policy.expectedManifestMetaDataEntrySha256)
        assertEquals(mapOf("channel" to "c1d2"), policy.expectedManifestMetaDataSemanticsSha256)
        assertEquals(
            mapOf("uses-feature:android.hardware.camera#required" to "false"),
            policy.expectedUsesFeatureFieldValues,
        )
        assertEquals(mapOf("uses-sdk#targetSdkVersion" to "34"), policy.expectedUsesSdkFieldValues)
        assertEquals(
            mapOf("uses-library:org.apache.http.legacy#required" to "true"),
            policy.expectedUsesLibraryFieldValues,
        )
        assertEquals(
            mapOf("uses-native-library:com.example.sec#required" to "false"),
            policy.expectedUsesNativeLibraryFieldValues,
        )
        assertEquals("ee55", policy.expectedApplicationSecuritySemanticsSha256)
        assertEquals("ff66", policy.expectedApplicationRuntimeSemanticsSha256)
        assertEquals(
            mapOf("application#usesCleartextTraffic" to "false"),
            policy.expectedApplicationFieldValues,
        )
    }

    private fun deviceContext(): SecureDeviceContext = SecureDeviceContext(
        installId = "install-1",
        resolvedDeviceId = "Tdevice-1",
        fingerprintHash = "fingerprint-1",
    )

    private fun parseServerTamperPolicy(json: String): TamperPolicy {
        val companion = SecureChannel::class.java.getDeclaredField("Companion").get(null)
        val method = companion.javaClass.getDeclaredMethod("parseServerTamperPolicy", String::class.java)
        method.isAccessible = true
        return method.invoke(companion, json) as TamperPolicy
    }

    private fun mockContext(): Context {
        val ctx = mock(Context::class.java)
        val prefs = mock(SharedPreferences::class.java)
        val editor = mock(SharedPreferences.Editor::class.java)
        `when`(ctx.getSharedPreferences("io.leonasec.leona.session", Context.MODE_PRIVATE))
            .thenReturn(prefs)
        `when`(prefs.edit()).thenReturn(editor)
        `when`(editor.putString(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString()))
            .thenReturn(editor)
        `when`(editor.remove(org.mockito.ArgumentMatchers.anyString())).thenReturn(editor)
        return ctx
    }
}
