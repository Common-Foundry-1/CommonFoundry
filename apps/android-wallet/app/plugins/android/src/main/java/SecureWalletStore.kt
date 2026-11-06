package org.commonfoundry.wallet.android

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class SecureWalletStore(
    private val context: Context,
    private val keyAlias: String = DEFAULT_KEY_ALIAS,
    private val fileName: String = DEFAULT_FILE_NAME,
) {
    companion object {
        const val OFFICIAL_BACKUP_BYTES = 176
        private const val DEFAULT_KEY_ALIAS = "cmfd.wallet.local.v1"
        private const val DEFAULT_FILE_NAME = "wallet.cmfd-keystore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val MAGIC = "CMFDKS01".toByteArray(Charsets.US_ASCII)
        private const val GCM_TAG_BITS = 128
        private const val EXPECTED_IV_BYTES = 12
        private const val MAX_WRAPPED_BYTES = 512
    }

    private val walletFile: File
        get() = File(context.noBackupFilesDir, fileName)

    fun exists(): Boolean = walletFile.isFile

    @Synchronized
    fun isAccessible(): Boolean {
        if (!exists()) return false
        return try {
            val backup = load()
            backup.fill(0)
            true
        } catch (_: Exception) {
            false
        }
    }

    @Synchronized
    fun store(officialBackup: ByteArray) {
        require(officialBackup.size == OFFICIAL_BACKUP_BYTES) { "invalid_wallet_size" }
        val target = walletFile
        if (target.exists()) {
            throw IllegalStateException("wallet_already_exists")
        }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        require(iv.size == EXPECTED_IV_BYTES) { "invalid_keystore_iv" }
        val ciphertext = cipher.doFinal(officialBackup)

        val pending = File.createTempFile("wallet-", ".pending", context.noBackupFilesDir)
        try {
            FileOutputStream(pending, false).use { output ->
                DataOutputStream(output).use { data ->
                    data.write(MAGIC)
                    data.writeInt(iv.size)
                    data.write(iv)
                    data.write(ciphertext)
                    data.flush()
                    output.fd.sync()
                }
            }
            Files.move(pending.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
            if (pending.exists()) pending.delete()
        }
    }

    /**
     * Replaces only a local blob that can no longer be opened by Android
     * Keystore. The previous encrypted bytes are preserved for diagnostics and
     * rollback; an accessible wallet is never overwritten.
     */
    @Synchronized
    fun replaceInaccessible(officialBackup: ByteArray) {
        require(officialBackup.size == OFFICIAL_BACKUP_BYTES) { "invalid_wallet_size" }
        val target = walletFile
        if (!target.isFile) throw IllegalStateException("wallet_missing")
        if (isAccessible()) throw IllegalStateException("wallet_still_accessible")

        val archive = File(
            context.noBackupFilesDir,
            "$fileName.unavailable-${System.currentTimeMillis()}",
        )
        if (!target.renameTo(archive)) {
            throw IllegalStateException("wallet_archive_failed")
        }
        try {
            store(officialBackup)
        } catch (error: Exception) {
            if (!target.exists()) archive.renameTo(target)
            throw error
        }
    }

    @Synchronized
    fun load(): ByteArray {
        val target = walletFile
        if (!target.isFile || target.length() <= MAGIC.size || target.length() > MAX_WRAPPED_BYTES) {
            throw IllegalStateException("wallet_missing_or_corrupt")
        }
        val all = target.readBytes()
        var magic = ByteArray(0)
        var iv = ByteArray(0)
        var ciphertext = ByteArray(0)
        try {
            val input = DataInputStream(ByteArrayInputStream(all))
            magic = ByteArray(MAGIC.size)
            input.readFully(magic)
            if (!magic.contentEquals(MAGIC)) {
                throw IllegalStateException("wallet_corrupt")
            }
            val ivSize = input.readInt()
            if (ivSize != EXPECTED_IV_BYTES) {
                throw IllegalStateException("wallet_corrupt")
            }
            iv = ByteArray(ivSize)
            input.readFully(iv)
            ciphertext = input.readBytes()
            if (ciphertext.size != OFFICIAL_BACKUP_BYTES + GCM_TAG_BITS / 8) {
                throw IllegalStateException("wallet_corrupt")
            }

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, existingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            val officialBackup = cipher.doFinal(ciphertext)
            if (officialBackup.size != OFFICIAL_BACKUP_BYTES) {
                officialBackup.fill(0)
                throw IllegalStateException("wallet_corrupt")
            }
            return officialBackup
        } finally {
            all.fill(0)
            magic.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    private fun existingKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return keyStore.getKey(keyAlias, null) as? SecretKey
            ?: throw IllegalStateException("keystore_key_unavailable")
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val specification = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        generator.init(specification)
        return generator.generateKey()
    }
}
