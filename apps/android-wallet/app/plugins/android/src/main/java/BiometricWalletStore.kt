package org.commonfoundry.wallet.android

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** A separate, revocable biometric credential; never replaces the recovery wallet. */
internal class BiometricWalletStore(
    context: Context,
    private val alias: String = "cmfd.wallet.biometric.v1",
    fileName: String = "wallet.cmfd-biometric",
) {
    companion object {
        const val MAX_SECRET_BYTES = 4096
        private const val IV_BYTES = 12
        private const val TAG_BITS = 128
        private const val BINDING_BYTES = 32
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val MAGIC = "CMFDBIO1".toByteArray(Charsets.US_ASCII)
    }

    private val file = AtomicFile(File(context.noBackupFilesDir, fileName))

    fun isUsable(walletBinding: ByteArray): Boolean = try {
        beginUnlock(walletBinding)
        true
    } catch (_: Exception) {
        false
    }

    fun beginEnrollment(walletBinding: ByteArray): Cipher {
        require(walletBinding.size == BINDING_BYTES)
        // Re-enrollment intentionally revokes the previous biometric key only.
        disable()
        val builder = KeyGenParameterSpec.Builder(
            alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= 30) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(builder.build()) }.generateKey()
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
    }

    fun finishEnrollment(cipher: Cipher, secret: ByteArray, walletBinding: ByteArray) {
        require(secret.size in 12..MAX_SECRET_BYTES)
        require(walletBinding.size == BINDING_BYTES)
        require(cipher.iv.size == IV_BYTES)
        // Auth-per-use Keystore keys require authentication before updateAAD,
        // as well as before doFinal. Initialization alone can precede the prompt.
        cipher.updateAAD(walletBinding)
        val encrypted = cipher.doFinal(secret) // Requires this operation's biometric authorization.
        val output = file.startWrite()
        try {
            output.write(MAGIC)
            output.write(cipher.iv)
            output.write(walletBinding)
            output.write(encrypted)
            file.finishWrite(output)
        } catch (error: Exception) {
            file.failWrite(output)
            throw error
        } finally {
            encrypted.fill(0)
        }
    }

    fun beginUnlock(walletBinding: ByteArray): Cipher {
        val blob = readBlob()
        try {
            requireBinding(blob, walletBinding)
            val key = keyStore().getKey(alias, null) as? SecretKey
                ?: throw IllegalStateException("biometric_key_unavailable")
            return Cipher.getInstance(TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, blob.copyOfRange(MAGIC.size, MAGIC.size + IV_BYTES)))
            }
        } finally {
            blob.fill(0)
        }
    }

    fun finishUnlock(cipher: Cipher, walletBinding: ByteArray): ByteArray {
        val blob = readBlob()
        try {
            requireBinding(blob, walletBinding)
            cipher.updateAAD(walletBinding)
            val headerBytes = MAGIC.size + IV_BYTES + BINDING_BYTES
            val secret = cipher.doFinal(blob, headerBytes, blob.size - headerBytes)
            if (secret.size !in 12..MAX_SECRET_BYTES) {
                secret.fill(0)
                throw IllegalStateException("biometric_credential_corrupt")
            }
            return secret
        } finally {
            blob.fill(0)
        }
    }

    fun disable() {
        keyStore().apply { if (containsAlias(alias)) deleteEntry(alias) }
        file.delete()
    }

    private fun readBlob(): ByteArray {
        file.openRead().use { input ->
            val headerBytes = MAGIC.size + IV_BYTES + BINDING_BYTES
            val maximum = headerBytes + MAX_SECRET_BYTES + TAG_BITS / 8
            require(input.channel.size() <= maximum) { "biometric_credential_corrupt" }
            val blob = input.readBytes()
            if (blob.size !in (headerBytes + 12 + TAG_BITS / 8)..maximum ||
                !blob.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)
            ) {
                blob.fill(0)
                throw IllegalStateException("biometric_credential_corrupt")
            }
            return blob
        }
    }

    private fun requireBinding(blob: ByteArray, walletBinding: ByteArray) {
        require(walletBinding.size == BINDING_BYTES)
        check(MessageDigest.isEqual(blob.copyOfRange(MAGIC.size + IV_BYTES, MAGIC.size + IV_BYTES + BINDING_BYTES), walletBinding)) {
            "biometric_wallet_changed"
        }
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
}
