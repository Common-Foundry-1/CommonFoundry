package org.commonfoundry.wallet.android

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SecureWalletStoreInstrumentedTest {
    private val suffix = System.nanoTime().toString()
    private val alias = "cmfd.wallet.test.$suffix"
    private val fileName = "wallet-test-$suffix.cmfd-keystore"
    private val context = InstrumentationRegistry.getInstrumentation().context
    private lateinit var store: SecureWalletStore

    @Before
    fun setUp() {
        store = SecureWalletStore(context, alias, fileName)
    }

    @After
    fun tearDown() {
        context.noBackupFilesDir
            .listFiles { file -> file.name.startsWith(fileName) }
            ?.forEach { file -> file.delete() }
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(alias)) deleteEntry(alias)
        }
    }

    @Test
    fun wrapsWithNonExportableKeystoreKeyAndRefusesOverwrite() {
        val syntheticBackup = syntheticBackup()
        store.store(syntheticBackup)

        assertTrue(store.exists())
        assertTrue(store.isAccessible())
        assertArrayEquals(syntheticBackup, store.load())
        assertThrows(IllegalStateException::class.java) { store.store(syntheticBackup) }
        assertThrows(IllegalStateException::class.java) {
            store.replaceInaccessible(syntheticBackup)
        }

        val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null)
        assertFalse(key.encoded?.isNotEmpty() == true)
        syntheticBackup.fill(0)
    }

    @Test
    fun persistsAcrossStoreInstances() {
        val syntheticBackup = syntheticBackup(17)
        store.store(syntheticBackup)

        val reopenedStore = SecureWalletStore(context, alias, fileName)
        assertTrue(reopenedStore.exists())
        assertTrue(reopenedStore.isAccessible())
        val reopenedBackup = reopenedStore.load()
        try {
            assertArrayEquals(syntheticBackup, reopenedBackup)
        } finally {
            syntheticBackup.fill(0)
            reopenedBackup.fill(0)
        }
    }

    @Test
    fun rejectsInvalidSizesWithoutCreatingAKeyOrFile() {
        val shortBackup = ByteArray(SecureWalletStore.OFFICIAL_BACKUP_BYTES - 1)
        val longBackup = ByteArray(SecureWalletStore.OFFICIAL_BACKUP_BYTES + 1)

        try {
            assertThrows(IllegalArgumentException::class.java) { store.store(shortBackup) }
            assertThrows(IllegalArgumentException::class.java) { store.store(longBackup) }
            assertFalse(store.exists())
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            assertFalse(keyStore.containsAlias(alias))
        } finally {
            shortBackup.fill(0)
            longBackup.fill(0)
        }
    }

    @Test
    fun detectsCorruptionAndReplacesOnlyTheInaccessibleBlob() {
        val originalBackup = syntheticBackup(31)
        val replacementBackup = syntheticBackup(93)
        store.store(originalBackup)

        val target = context.noBackupFilesDir.resolve(fileName)
        val corrupted = target.readBytes()
        corrupted[corrupted.lastIndex] = (corrupted.last().toInt() xor 0x01).toByte()
        target.writeBytes(corrupted)
        corrupted.fill(0)

        assertTrue(store.exists())
        assertFalse(store.isAccessible())
        assertThrows(Exception::class.java) { store.load() }

        store.replaceInaccessible(replacementBackup)
        assertTrue(store.isAccessible())
        val recovered = store.load()
        try {
            assertArrayEquals(replacementBackup, recovered)
            val archives = context.noBackupFilesDir
                .listFiles { file -> file.name.startsWith("$fileName.unavailable-") }
                .orEmpty()
            assertEquals(1, archives.size)
            assertTrue(archives.single().length() > 0)
        } finally {
            originalBackup.fill(0)
            replacementBackup.fill(0)
            recovered.fill(0)
        }
    }

    @Test
    fun missingKeystoreKeyMakesBlobInaccessibleAndAllowsExplicitRecovery() {
        val originalBackup = syntheticBackup(47)
        val replacementBackup = syntheticBackup(121)
        store.store(originalBackup)

        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            deleteEntry(alias)
        }

        assertTrue(store.exists())
        assertFalse(store.isAccessible())
        assertThrows(IllegalStateException::class.java) { store.load() }

        store.replaceInaccessible(replacementBackup)
        val recovered = store.load()
        try {
            assertArrayEquals(replacementBackup, recovered)
            val replacementKey = KeyStore.getInstance("AndroidKeyStore")
                .apply { load(null) }
                .getKey(alias, null)
            assertFalse(replacementKey.encoded?.isNotEmpty() == true)
        } finally {
            originalBackup.fill(0)
            replacementBackup.fill(0)
            recovered.fill(0)
        }
    }

    private fun syntheticBackup(seed: Int = 0): ByteArray =
        ByteArray(SecureWalletStore.OFFICIAL_BACKUP_BYTES) { index ->
            ((index + seed) and 0xff).toByte()
        }
}
