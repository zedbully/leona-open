/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.leona.internal.identity

import android.content.Context
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import java.io.File
import java.nio.file.Files
import java.util.concurrent.Executors

/** Executable JVM coverage for legacy migration failure boundaries. */
class IdentityStoreMigrationFaultInjectionTest {

    @Test
    fun `install encryption failure rejects legacy plaintext`() = assertEncryptionFailure(IdentityRecord.INSTALL_ID)

    @Test
    fun `canonical encryption failure rejects legacy plaintext`() =
        assertEncryptionFailure(IdentityRecord.CANONICAL_DEVICE_ID)

    @Test
    fun `snapshot encryption failure rejects legacy plaintext`() = assertEncryptionFailure(IdentityRecord.SNAPSHOT)

    @Test
    fun `install commit false quarantines legacy plaintext`() =
        assertCommitFailure(IdentityRecord.INSTALL_ID, CommitOutcome.False)

    @Test
    fun `canonical commit false quarantines legacy plaintext`() =
        assertCommitFailure(IdentityRecord.CANONICAL_DEVICE_ID, CommitOutcome.False)

    @Test
    fun `snapshot commit false quarantines legacy plaintext`() =
        assertCommitFailure(IdentityRecord.SNAPSHOT, CommitOutcome.False)

    @Test
    fun `install commit exception quarantines legacy plaintext`() =
        assertCommitFailure(IdentityRecord.INSTALL_ID, CommitOutcome.Throw)

    @Test
    fun `canonical commit exception quarantines legacy plaintext`() =
        assertCommitFailure(IdentityRecord.CANONICAL_DEVICE_ID, CommitOutcome.Throw)

    @Test
    fun `snapshot commit exception quarantines legacy plaintext`() =
        assertCommitFailure(IdentityRecord.SNAPSHOT, CommitOutcome.Throw)

    @Test
    fun `wrong preference types are quarantined per record without crashing`() {
        IdentityRecord.values().forEach { record ->
            val values = initialValues().toMutableMap().apply {
                this[record.preferenceKey] = 7
            }
            val prefs = FaultInjectingPreferences(values)
            val store = newStore(prefs, legacyHooks())

            assertNull(load(store, record))
            assertEquals(IdentityProtectionLevel.CORRUPT_OR_MISSING, store.protectionStatus().level)
            assertFalse(prefs.contains(record.preferenceKey))
            assertUnrelatedRecordsUntouched(prefs, record)
        }
    }

    @Test
    fun `successful legacy migration returns plaintext only after v2 commit`() {
        IdentityRecord.values().forEach { record ->
            val prefs = FaultInjectingPreferences(initialValues())
            val store = newStore(prefs, legacyHooks())

            assertEquals(expectedLoadedValue(record), load(store, record))
            assertEquals(v2Envelope(record), prefs.getString(record.preferenceKey, null))
            assertTrue(store.protectionStatus().durable)
        }
    }

    private fun assertEncryptionFailure(record: IdentityRecord) {
        val prefs = FaultInjectingPreferences(initialValues())
        val store = newStore(
            prefs = prefs,
            hooks = IdentityStoreCryptoHooks(
                decrypt = legacyDecryptor(),
                encrypt = { _, _ -> throw IllegalStateException("synthetic keystore failure") },
                probe = { IdentityProtectionStatus.READY },
            ),
        )

        assertNull(load(store, record))
        assertEquals(IdentityProtectionLevel.KEYSTORE_UNAVAILABLE, store.protectionStatus().level)
        assertFalse(store.protectionStatus().durable)
        assertTrue(prefs.contains(record.preferenceKey))
        assertUnrelatedRecordsUntouched(prefs, record)

        assertNull(load(store, record))
        assertTrue(prefs.contains(record.preferenceKey))
    }

    private fun assertCommitFailure(record: IdentityRecord, firstOutcome: CommitOutcome) {
        val prefs = FaultInjectingPreferences(
            initialValues(),
            commitOutcomes = ArrayDeque(listOf(firstOutcome, CommitOutcome.Success)),
        )
        val store = newStore(prefs, legacyHooks())

        assertNull(load(store, record))
        assertEquals(IdentityProtectionLevel.EPHEMERAL_MEMORY_ONLY, store.protectionStatus().level)
        assertEquals(IdentityProtectionCode.STORAGE_WRITE_FAILED, store.protectionStatus().code)
        assertFalse(store.protectionStatus().durable)
        assertFalse(prefs.contains(record.preferenceKey))
        assertUnrelatedRecordsUntouched(prefs, record)

        assertNull(load(store, record))
        assertFalse(prefs.contains(record.preferenceKey))

        when (record) {
            IdentityRecord.INSTALL_ID -> store.replaceInstallIdAndClearSnapshot(LOCAL_INSTALL_ID)
            IdentityRecord.CANONICAL_DEVICE_ID -> store.persistCanonicalDeviceId(CANONICAL_ID)
            IdentityRecord.SNAPSHOT -> store.persistLastSnapshot(validSnapshot())
        }
        store.beginResolution()
        assertEquals(IdentityProtectionStatus.READY, store.protectionStatus())
    }

    @Test
    fun `missing marker clears restored dependencies before creating a new epoch`() {
        val prefs = FaultInjectingPreferences(
            mapOf(
                IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID),
                IdentityRecord.SNAPSHOT.preferenceKey to legacyEnvelope(IdentityRecord.SNAPSHOT),
            ),
        )
        val fixture = newFixture(prefs, legacyHooks(), markerExists = false)

        assertFalse(prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey))
        assertFalse(prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey))
        assertTrue(fixture.marker.exists())
        assertEquals(IdentityProtectionStatus.READY, fixture.store.protectionStatus())
    }

    @Test
    fun `missing marker with corrupt install clears all dependent records`() {
        val prefs = FaultInjectingPreferences(initialValues())
        val hooks = legacyHooks().copy(
            decrypt = { record, stored ->
                if (record == IdentityRecord.INSTALL_ID) null else legacyDecryptor()(record, stored)
            },
            probe = { IdentityProtectionStatus.CORRUPT_OR_MISSING },
        )
        val fixture = newFixture(prefs, hooks, markerExists = false)

        IdentityRecord.values().forEach { record ->
            assertFalse(prefs.contains(record.preferenceKey))
        }
        assertTrue(fixture.marker.exists())
    }

    @Test
    fun `missing marker preserves ciphertext when keystore is temporarily unavailable`() {
        val prefs = FaultInjectingPreferences(initialValues())
        val fixture = newFixture(
            prefs,
            IdentityStoreCryptoHooks(
                decrypt = legacyDecryptor(),
                encrypt = { _, _ -> throw IllegalStateException("synthetic keystore failure") },
                probe = { IdentityProtectionStatus.KEYSTORE_UNAVAILABLE },
            ),
            markerExists = false,
        )

        assertTrue(prefs.contains(IdentityRecord.INSTALL_ID.preferenceKey))
        assertTrue(prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey))
        assertTrue(prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey))
        assertFalse(fixture.marker.exists())
        assertEquals(IdentityProtectionLevel.KEYSTORE_UNAVAILABLE, fixture.store.protectionStatus().level)
    }

    @Test
    fun `missing marker preserves ciphertext when migration storage fails`() {
        val prefs = FaultInjectingPreferences(
            initialValues(),
            commitOutcomes = ArrayDeque(listOf(CommitOutcome.False, CommitOutcome.False)),
        )
        val fixture = newFixture(prefs, legacyHooks(), markerExists = false)

        IdentityRecord.values().forEach { record ->
            assertTrue(prefs.contains(record.preferenceKey))
        }
        assertFalse(fixture.marker.exists())
        assertFalse(fixture.store.protectionStatus().durable)
        assertEquals(IdentityProtectionCode.STORAGE_WRITE_FAILED, fixture.store.protectionStatus().code)
    }

    @Test
    fun `dependency clear failure leaves old epoch and marker absent`() {
        val prefs = FaultInjectingPreferences(
            mapOf(
                IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID),
                IdentityRecord.SNAPSHOT.preferenceKey to legacyEnvelope(IdentityRecord.SNAPSHOT),
            ),
            commitOutcomes = ArrayDeque(listOf(CommitOutcome.False)),
        )
        val failed = newFixture(prefs, legacyHooks(), markerExists = false)

        assertFalse(failed.marker.exists())
        assertTrue(prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey))
        assertTrue(prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey))
        assertEquals(IdentityProtectionCode.STORAGE_WRITE_FAILED, failed.store.protectionStatus().code)

        val retry = newFixture(prefs, legacyHooks(), markerExists = false)
        assertTrue(retry.marker.exists())
        assertFalse(prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey))
        assertFalse(prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey))
    }

    @Test
    fun `dependency clear exception leaves old epoch and marker absent`() {
        val prefs = FaultInjectingPreferences(
            mapOf(
                IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID),
                IdentityRecord.SNAPSHOT.preferenceKey to legacyEnvelope(IdentityRecord.SNAPSHOT),
            ),
            commitOutcomes = ArrayDeque(listOf(CommitOutcome.Throw)),
        )
        val failed = newFixture(prefs, legacyHooks(), markerExists = false)

        assertFalse(failed.marker.exists())
        assertTrue(prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey))
        assertTrue(prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey))
        assertEquals(IdentityProtectionCode.STORAGE_WRITE_FAILED, failed.store.protectionStatus().code)
    }

    @Test
    fun `marker creation failure occurs only after dependency clear`() {
        val prefs = FaultInjectingPreferences(
            mapOf(
                IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID),
                IdentityRecord.SNAPSHOT.preferenceKey to legacyEnvelope(IdentityRecord.SNAPSHOT),
            ),
        )
        val fixture = newFixture(
            prefs,
            legacyHooks().copy(createLifecycleMarker = { false }),
            markerExists = false,
        )

        assertFalse(fixture.marker.exists())
        assertFalse(prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey))
        assertFalse(prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey))
        assertEquals(IdentityProtectionCode.STORAGE_WRITE_FAILED, fixture.store.protectionStatus().code)
    }

    @Test
    fun `canonical quarantine is not consumed by an unrelated snapshot rewrite`() {
        val prefs = FaultInjectingPreferences(
            mapOf(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID)),
        )
        val store = newStore(
            prefs,
            fixedHooks(canonical = IdentityStoreDecryptedRecord("invalid", legacy = false)),
        )

        assertNull(store.loadCanonicalDeviceId())
        store.persistLastSnapshot(validSnapshot())
        store.beginResolution()
        assertFalse(store.protectionStatus().durable)
        assertEquals(IdentityProtectionLevel.CORRUPT_OR_MISSING, store.protectionStatus().level)

        store.persistCanonicalDeviceId(CANONICAL_ID)
        store.beginResolution()
        assertEquals(IdentityProtectionStatus.READY, store.protectionStatus())
    }

    @Test
    fun `quarantine clear failure is recoverable only by the same record rewrite`() {
        val prefs = FaultInjectingPreferences(
            mapOf(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID)),
            commitOutcomes = ArrayDeque(listOf(CommitOutcome.False, CommitOutcome.Success)),
        )
        val store = newStore(
            prefs,
            fixedHooks(canonical = IdentityStoreDecryptedRecord("invalid", legacy = false)),
        )

        assertNull(store.loadCanonicalDeviceId())
        assertTrue(prefs.contains(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey))
        assertFalse(store.protectionStatus().durable)

        store.persistCanonicalDeviceId(CANONICAL_ID)
        store.beginResolution()
        assertEquals(IdentityProtectionStatus.READY, store.protectionStatus())
    }

    @Test
    fun `snapshot quarantine is explicitly resolved by atomic install rotation`() {
        val prefs = FaultInjectingPreferences(
            mapOf(IdentityRecord.SNAPSHOT.preferenceKey to legacyEnvelope(IdentityRecord.SNAPSHOT)),
        )
        val store = newStore(
            prefs,
            fixedHooks(snapshot = IdentityStoreDecryptedRecord("not-a-snapshot", legacy = false)),
        )

        assertNull(store.loadLastSnapshot())
        assertFalse(store.protectionStatus().durable)
        store.replaceInstallIdAndClearSnapshot(LOCAL_INSTALL_ID)
        store.beginResolution()
        assertEquals(IdentityProtectionStatus.READY, store.protectionStatus())
        assertFalse(prefs.contains(IdentityRecord.SNAPSHOT.preferenceKey))
    }

    @Test
    fun `multiple damaged records remain degraded until each target is rewritten`() {
        val prefs = FaultInjectingPreferences(
            mapOf(
                IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID),
                IdentityRecord.SNAPSHOT.preferenceKey to legacyEnvelope(IdentityRecord.SNAPSHOT),
            ),
        )
        val store = newStore(
            prefs,
            fixedHooks(
                canonical = IdentityStoreDecryptedRecord("invalid", legacy = false),
                snapshot = IdentityStoreDecryptedRecord("not-a-snapshot", legacy = false),
            ),
        )

        assertNull(store.loadCanonicalDeviceId())
        assertNull(store.loadLastSnapshot())
        store.persistLastSnapshot(validSnapshot())
        store.beginResolution()
        assertFalse(store.protectionStatus().durable)

        store.persistCanonicalDeviceId(CANONICAL_ID)
        store.beginResolution()
        assertEquals(IdentityProtectionStatus.READY, store.protectionStatus())
    }

    @Test
    fun `serialized store operations cannot consume another record quarantine`() {
        val prefs = FaultInjectingPreferences(
            mapOf(IdentityRecord.CANONICAL_DEVICE_ID.preferenceKey to legacyEnvelope(IdentityRecord.CANONICAL_DEVICE_ID)),
        )
        val store = newStore(
            prefs,
            fixedHooks(canonical = IdentityStoreDecryptedRecord("invalid", legacy = false)),
        )
        assertNull(store.loadCanonicalDeviceId())

        val pool = Executors.newFixedThreadPool(3)
        try {
            val futures = (0 until 30).map { index ->
                pool.submit {
                    when (index % 3) {
                        0 -> store.beginResolution()
                        1 -> store.loadCanonicalDeviceId()
                        else -> store.persistLastSnapshot(validSnapshot())
                    }
                }
            }
            futures.forEach { it.get() }
        } finally {
            pool.shutdown()
            pool.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)
        }
        assertFalse(store.protectionStatus().durable)
        assertEquals(IdentityProtectionLevel.CORRUPT_OR_MISSING, store.protectionStatus().level)
    }

    @Test
    fun `cache admission fails closed after install rotation or non durable persistence`() {
        val cached = validSnapshot()
        assertTrue(
            IdentityCacheAdmission.isAdmissible(
                cached,
                currentInstallId = LOCAL_INSTALL_ID,
                persistedCanonicalDeviceId = null,
                currentProtectionStatus = IdentityProtectionStatus.READY,
            ),
        )
        assertFalse(
            IdentityCacheAdmission.isAdmissible(
                cached,
                currentInstallId = "123e4567-e89b-12d3-a456-426614174001",
                persistedCanonicalDeviceId = null,
                currentProtectionStatus = IdentityProtectionStatus.READY,
            ),
        )
        assertFalse(
            IdentityCacheAdmission.isAdmissible(
                cached,
                currentInstallId = LOCAL_INSTALL_ID,
                persistedCanonicalDeviceId = null,
                currentProtectionStatus = IdentityProtectionStatus.STORAGE_WRITE_FAILED,
            ),
        )
    }

    private data class Fixture(
        val store: LeonaIdentityStore,
        val prefs: FaultInjectingPreferences,
        val marker: File,
    )

    private fun newStore(
        prefs: FaultInjectingPreferences,
        hooks: IdentityStoreCryptoHooks,
    ): LeonaIdentityStore = newFixture(prefs, hooks).store

    private fun newFixture(
        prefs: FaultInjectingPreferences,
        hooks: IdentityStoreCryptoHooks,
        markerExists: Boolean = true,
    ): Fixture {
        val context = mock(Context::class.java)
        val noBackupDir = Files.createTempDirectory("leona-identity-migration").toFile()
        val marker = File(noBackupDir, "leona-install-lifecycle-v1")
        if (markerExists) marker.createNewFile()
        `when`(context.applicationContext).thenReturn(context)
        `when`(context.packageName).thenReturn(PACKAGE_NAME)
        `when`(context.noBackupFilesDir).thenReturn(noBackupDir)
        `when`(context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)).thenReturn(prefs)
        return Fixture(LeonaIdentityStore(context, hooks), prefs, marker)
    }

    private fun legacyHooks(): IdentityStoreCryptoHooks = IdentityStoreCryptoHooks(
        decrypt = legacyDecryptor(),
        encrypt = { record, _ -> v2Envelope(record) },
        probe = { IdentityProtectionStatus.READY },
    )

    private fun fixedHooks(
        install: IdentityStoreDecryptedRecord? = null,
        canonical: IdentityStoreDecryptedRecord? = null,
        snapshot: IdentityStoreDecryptedRecord? = null,
    ): IdentityStoreCryptoHooks = IdentityStoreCryptoHooks(
        decrypt = { record, _ ->
            when (record) {
                IdentityRecord.INSTALL_ID -> install
                IdentityRecord.CANONICAL_DEVICE_ID -> canonical
                IdentityRecord.SNAPSHOT -> snapshot
            }
        },
        encrypt = { record, _ -> v2Envelope(record) },
        probe = { IdentityProtectionStatus.READY },
    )

    private fun legacyDecryptor(): (IdentityRecord, String?) -> IdentityStoreDecryptedRecord? =
        { record, stored ->
            assertTrue(IdentityEnvelopePolicy.inspect(stored, expectedRecord = record)?.legacy == true)
            IdentityStoreDecryptedRecord(decryptedPlaintext(record), legacy = true)
        }

    private fun load(store: LeonaIdentityStore, record: IdentityRecord): String? = when (record) {
        IdentityRecord.INSTALL_ID -> store.loadInstallId()
        IdentityRecord.CANONICAL_DEVICE_ID -> store.loadCanonicalDeviceId()
        IdentityRecord.SNAPSHOT -> store.loadLastSnapshot()?.installId
    }

    private fun initialValues(): Map<String, Any> =
        IdentityRecord.values().associate { it.preferenceKey to legacyEnvelope(it) }

    private fun assertUnrelatedRecordsUntouched(prefs: FaultInjectingPreferences, target: IdentityRecord) {
        IdentityRecord.values()
            .filterNot { it == target }
            .forEach { record ->
                assertEquals(legacyEnvelope(record), prefs.getString(record.preferenceKey, null))
            }
    }

    private fun expectedLoadedValue(record: IdentityRecord): String = when (record) {
        IdentityRecord.INSTALL_ID -> LOCAL_INSTALL_ID
        IdentityRecord.CANONICAL_DEVICE_ID -> CANONICAL_ID
        IdentityRecord.SNAPSHOT -> LOCAL_INSTALL_ID
    }

    private fun decryptedPlaintext(record: IdentityRecord): String = when (record) {
        IdentityRecord.INSTALL_ID -> LOCAL_INSTALL_ID
        IdentityRecord.CANONICAL_DEVICE_ID -> CANONICAL_ID
        IdentityRecord.SNAPSHOT -> snapshotJson()
    }

    private fun legacyEnvelope(record: IdentityRecord): String =
        """{"mode":"keystore","iv":"${BASE64_IV}","ct":"${BASE64_CT}"}"""

    private fun v2Envelope(record: IdentityRecord): String =
        """{"version":2,"mode":"keystore","record":"${record.wireName}","iv":"${BASE64_IV}","ct":"${BASE64_CT}"}"""

    private fun snapshotJson(): String = DeviceFingerprintSnapshot(
        generatedAtMillis = 1L,
        installId = LOCAL_INSTALL_ID,
        canonicalDeviceId = null,
        resolvedDeviceId = "T" + "a".repeat(43),
        fingerprintHash = "a".repeat(64),
        packageName = PACKAGE_NAME,
        appVersionName = "1",
        appVersionCode = 1L,
        installerPackage = null,
        androidId = null,
        signingCertSha256 = emptyList(),
        brand = "brand",
        model = "model",
        manufacturer = "manufacturer",
        sdkInt = 23,
        abis = listOf("arm64-v8a"),
        localeTag = "en-US",
        timeZoneId = "UTC",
        screenSummary = null,
        riskSignals = emptySet(),
        sessionId = "",
        identityProtectionStatus = IdentityProtectionStatus.READY,
    ).toJson()

    private fun validSnapshot(): DeviceFingerprintSnapshot = DeviceFingerprintSnapshot.fromJson(snapshotJson())!!

    private enum class CommitOutcome {
        Success,
        False,
        Throw,
    }

    private class FaultInjectingPreferences(
        initialValues: Map<String, Any>,
        private val commitOutcomes: ArrayDeque<CommitOutcome> = ArrayDeque(),
    ) : SharedPreferences {
        private val values = initialValues.toMutableMap()

        override fun getAll(): Map<String, *> = values.toMap()
        override fun getString(key: String?, defValue: String?): String? = when (val value = key?.let(values::get)) {
            null -> defValue
            is String -> value
            else -> throw ClassCastException("preference value is not a String")
        }
        override fun getStringSet(key: String?, defValues: Set<String>?): Set<String>? =
            key?.let(values::get) as? Set<String> ?: defValues
        override fun getInt(key: String?, defValue: Int): Int = key?.let(values::get) as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = key?.let(values::get) as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = key?.let(values::get) as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = key?.let(values::get) as? Boolean ?: defValue
        override fun contains(key: String?): Boolean = key?.let(values::containsKey) ?: false
        override fun edit(): SharedPreferences.Editor = Editor()
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) = Unit

        private inner class Editor : SharedPreferences.Editor {
            private val updates = mutableMapOf<String, Any?>()
            private val removals = mutableSetOf<String>()

            override fun putString(key: String?, value: String?): SharedPreferences.Editor = apply {
                if (key != null) updates[key] = value
            }

            override fun putStringSet(key: String?, values: Set<String>?): SharedPreferences.Editor = apply {
                if (key != null) updates[key] = values
            }

            override fun putInt(key: String?, value: Int): SharedPreferences.Editor = apply {
                if (key != null) updates[key] = value
            }

            override fun putLong(key: String?, value: Long): SharedPreferences.Editor = apply {
                if (key != null) updates[key] = value
            }

            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor = apply {
                if (key != null) updates[key] = value
            }

            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor = apply {
                if (key != null) updates[key] = value
            }

            override fun remove(key: String?): SharedPreferences.Editor = apply {
                if (key != null) removals += key
            }

            override fun clear(): SharedPreferences.Editor = apply {
                values.clear()
            }

            override fun commit(): Boolean {
                val outcome = if (commitOutcomes.isEmpty()) CommitOutcome.Success else commitOutcomes.removeFirst()
                if (outcome == CommitOutcome.Throw) throw IllegalStateException("synthetic commit failure")
                if (outcome == CommitOutcome.False) return false
                updates.forEach { (key, value) ->
                    if (value == null) values.remove(key) else values[key] = value
                }
                removals.forEach(values::remove)
                return true
            }

            override fun apply() {
                updates.forEach { (key, value) ->
                    if (value == null) values.remove(key) else values[key] = value
                }
                removals.forEach(values::remove)
            }
        }
    }

    companion object {
        private const val PACKAGE_NAME = "io.leonasec.test"
        private const val PREFS_NAME = "io.leonasec.leona.identity"
        private const val LOCAL_INSTALL_ID = "123e4567-e89b-12d3-a456-426614174000"
        private val CANONICAL_ID = "L${"a".repeat(32)}"
        private const val BASE64_IV = "AAAAAAAAAAAAAAAA"
        private const val BASE64_CT = "AAAAAAAAAAAAAAAAAAAAAA"
    }
}
