package org.commonfoundry.wallet.android

import android.app.Activity
import android.content.Intent
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyInfo
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

class BiometricTestActivity : Activity()

/** Run on an enrolled emulator/device. Each prompt needs a matching biometric. */
@RunWith(AndroidJUnit4::class)
class BiometricWalletStoreInstrumentedTest {
    @Test
    fun biometricCredentialRequiresAuthenticationAndIsBoundToTheWallet() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.context
        assumeTrue(android.os.Build.VERSION.SDK_INT >= 30)
        assumeTrue(context.getSystemService(BiometricManager::class.java)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS)
        val suffix = System.nanoTime().toString()
        val alias = "cmfd.biometric.test.$suffix"
        val fileName = "wallet-biometric-test-$suffix"
        val store = BiometricWalletStore(context, alias, fileName)
        val local = SecureWalletStore(context, "$alias.local", "$fileName.local")
        val localBytes = ByteArray(SecureWalletStore.OFFICIAL_BACKUP_BYTES) { it.toByte() }
        val secret = "synthetic biometric test passphrase".toByteArray()
        val binding = java.security.MessageDigest.getInstance("SHA-256").digest(localBytes)
        val activity = instrumentation.startActivitySync(
            Intent(context, BiometricTestActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
        )
        try {
            local.store(localBytes)
            assertFalse(store.isUsable(binding))
            val unauthorized = store.beginEnrollment(binding)
            val key = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null) as SecretKey
            val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            assertTrue(info.isUserAuthenticationRequired)
            assertEquals(0, info.userAuthenticationValidityDurationSeconds)
            assertTrue(info.isInvalidatedByBiometricEnrollment)
            assertEquals(android.security.keystore.KeyProperties.AUTH_BIOMETRIC_STRONG, info.userAuthenticationType)
            assertNull(key.encoded)
            assertThrows(Exception::class.java) { store.finishEnrollment(unauthorized, secret, binding) }
            assertFalse(store.isUsable(binding))

            val encryption = store.beginEnrollment(binding)
            authenticate(activity, encryption)
            store.finishEnrollment(encryption, secret, binding)
            assertTrue(store.isUsable(binding))
            assertThrows(Exception::class.java) { store.finishUnlock(store.beginUnlock(binding), binding) }

            val decryption = store.beginUnlock(binding)
            authenticate(activity, decryption)
            val recovered = store.finishUnlock(decryption, binding)
            try { assertArrayEquals(secret, recovered) } finally { recovered.fill(0) }

            assertThrows(Exception::class.java) { store.beginUnlock(ByteArray(32) { 0x7f }) }
            // Tamper the public binding header too: the GCM authentication tag
            // must still reject a different wallet even after a valid biometric.
            val wrongBinding = ByteArray(32) { 0x7f }
            val target = context.noBackupFilesDir.resolve(fileName)
            val tampered = target.readBytes()
            wrongBinding.copyInto(tampered, 8 + 12)
            target.writeBytes(tampered)
            tampered.fill(0)
            val wrongWallet = store.beginUnlock(wrongBinding)
            authenticate(activity, wrongWallet)
            assertThrows(Exception::class.java) { store.finishUnlock(wrongWallet, wrongBinding) }
            store.disable()
            assertFalse(store.isUsable(binding))
            assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(alias))
            val unchanged = local.load()
            try { assertArrayEquals(localBytes, unchanged) } finally { unchanged.fill(0) }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
            store.disable()
            secret.fill(0)
            binding.fill(0)
            localBytes.fill(0)
            context.noBackupFilesDir.listFiles { file -> file.name.startsWith(fileName) }?.forEach { it.delete() }
            KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry("$alias.local") }
        }
    }

    private fun authenticate(activity: Activity, cipher: Cipher) {
        val done = CountDownLatch(1)
        var authenticated = false
        val signal = CancellationSignal()
        activity.runOnUiThread {
            BiometricPrompt.Builder(activity)
                .setTitle("Synthetic Common Foundry biometric test")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .setNegativeButton("Cancel", activity.mainExecutor) { _, _ -> done.countDown() }
                .build().authenticate(BiometricPrompt.CryptoObject(cipher), signal, activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            authenticated = result.cryptoObject?.cipher === cipher
                            done.countDown()
                        }
                        override fun onAuthenticationError(code: Int, message: CharSequence) { done.countDown() }
                    },
                )
        }
        try {
            assertTrue("Timed out waiting for test biometric", done.await(30, TimeUnit.SECONDS))
            assertTrue("Test biometric was not authenticated", authenticated)
        } finally {
            signal.cancel()
        }
    }
}
