package org.commonfoundry.wallet.android

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.content.Intent
import android.net.Uri
import android.util.Base64
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.io.ByteArrayOutputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import javax.crypto.Cipher

@InvokeArg
class BiometricArgs {
    var language: String = "en"
    var dataBase64: String = ""
}

@InvokeArg
class EncodedWalletArgs {
    lateinit var dataBase64: String
}

@InvokeArg
class SaveDocumentArgs {
    lateinit var dataBase64: String
    lateinit var suggestedName: String
}

@TauriPlugin
class CmfdAndroidPlugin(private val activity: Activity) : Plugin(activity) {
    private val secureStore = SecureWalletStore(activity.applicationContext)
    private val biometricStore = BiometricWalletStore(activity.applicationContext)
    private var foreground = true
    private var biometricOperation: BiometricOperation? = null

    private class BiometricOperation(
        val invoke: Invoke,
        val cipher: Cipher,
        val binding: ByteArray,
        val secret: ByteArray?,
        val signal: CancellationSignal = CancellationSignal(),
    ) {
        fun clear() {
            binding.fill(0)
            secret?.fill(0)
        }
    }

    override fun onResume() {
        foreground = true
    }

    override fun onPause() {
        foreground = false
        cancelBiometricOperation()
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override fun onDestroy() {
        cancelBiometricOperation()
    }

    private fun cancelBiometricOperation() {
        val operation = biometricOperation ?: return
        biometricOperation = null
        operation.signal.cancel()
        operation.clear()
        operation.invoke.reject("biometric_cancelled")
    }

    @Suppress("DEPRECATION")
    private fun biometricsAvailable(): Boolean = when {
        Build.VERSION.SDK_INT >= 30 -> activity.getSystemService(BiometricManager::class.java)
            ?.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        Build.VERSION.SDK_INT >= 29 -> activity.getSystemService(BiometricManager::class.java)
            ?.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS
        else -> activity.getSystemService(android.hardware.fingerprint.FingerprintManager::class.java)?.let {
            it.isHardwareDetected && it.hasEnrolledFingerprints()
        } == true
    }

    private fun walletBinding(): ByteArray {
        val local = secureStore.load()
        return try {
            MessageDigest.getInstance("SHA-256").digest(local)
        } finally {
            local.fill(0)
        }
    }

    @Command
    fun biometricStatus(invoke: Invoke) {
        try {
            val binding = if (secureStore.exists()) walletBinding() else ByteArray(0)
            try {
                val result = JSObject()
                result.put("available", biometricsAvailable())
                result.put("enabled", binding.isNotEmpty() && biometricStore.isUsable(binding))
                invoke.resolve(result)
            } finally {
                binding.fill(0)
            }
        } catch (_: Exception) {
            invoke.reject("biometric_unavailable")
        }
    }

    @Command
    fun disableBiometrics(invoke: Invoke) {
        activity.runOnUiThread {
            try {
                cancelBiometricOperation()
                biometricStore.disable()
                invoke.resolve()
            } catch (_: Exception) {
                invoke.reject("biometric_disable_failed")
            }
        }
    }

    @Command
    fun enableBiometrics(invoke: Invoke) = startBiometricOperation(invoke, true)

    @Command
    fun unlockBiometrics(invoke: Invoke) = startBiometricOperation(invoke, false)

    private fun startBiometricOperation(invoke: Invoke, enrolling: Boolean) {
        activity.runOnUiThread {
            if (!foreground || activity.isFinishing || activity.isDestroyed || biometricOperation != null) {
                invoke.reject("biometric_unavailable")
                return@runOnUiThread
            }
            var secret: ByteArray? = null
            var binding = ByteArray(0)
            try {
                val args = invoke.parseArgs(BiometricArgs::class.java)
                if (!biometricsAvailable()) throw IllegalStateException("biometric_unavailable")
                binding = walletBinding()
                if (enrolling) {
                    require(args.dataBase64.length <= (BiometricWalletStore.MAX_SECRET_BYTES + 2) / 3 * 4)
                    secret = Base64.decode(args.dataBase64, Base64.NO_WRAP)
                    args.dataBase64 = ""
                    require(secret.size in 12..BiometricWalletStore.MAX_SECRET_BYTES)
                }
                val cipher = if (enrolling) biometricStore.beginEnrollment(binding) else biometricStore.beginUnlock(binding)
                val operation = BiometricOperation(invoke, cipher, binding, secret)
                biometricOperation = operation
                val french = args.language == "fr"
                val builder = BiometricPrompt.Builder(activity)
                    .setTitle(if (french) "Common Foundry — biométrie" else "Common Foundry — biometrics")
                    .setSubtitle(if (enrolling) {
                        if (french) "Activer le déverrouillage biométrique" else "Enable biometric unlock"
                    } else {
                        if (french) "Déverrouiller votre portefeuille" else "Unlock your wallet"
                    })
                    .setNegativeButton(if (french) "Annuler" else "Cancel", activity.mainExecutor) { _, _ ->
                        if (biometricOperation === operation) cancelBiometricOperation()
                    }
                if (Build.VERSION.SDK_INT >= 30) {
                    builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                }
                builder.build().authenticate(
                    BiometricPrompt.CryptoObject(cipher), operation.signal, activity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            if (biometricOperation !== operation) return
                            biometricOperation = null
                            operation.clear()
                            invoke.reject("biometric_authentication_failed")
                        }

                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (biometricOperation !== operation) return
                            biometricOperation = null
                            var credential = ByteArray(0)
                            var currentBinding = ByteArray(0)
                            try {
                                check(foreground && !activity.isFinishing && !activity.isDestroyed)
                                check(result.cryptoObject?.cipher === operation.cipher)
                                currentBinding = walletBinding()
                                check(MessageDigest.isEqual(operation.binding, currentBinding))
                                if (enrolling) {
                                    biometricStore.finishEnrollment(operation.cipher, operation.secret!!, operation.binding)
                                    invoke.resolve()
                                } else {
                                    credential = biometricStore.finishUnlock(operation.cipher, operation.binding)
                                    val response = JSObject()
                                    response.put("dataBase64", Base64.encodeToString(credential, Base64.NO_WRAP))
                                    invoke.resolve(response) // Internal Rust bridge only; never returned to the WebView.
                                }
                            } catch (_: Exception) {
                                invoke.reject("biometric_authentication_failed")
                            } finally {
                                credential.fill(0)
                                currentBinding.fill(0)
                                operation.clear()
                            }
                        }
                    },
                )
            } catch (_: Exception) {
                biometricOperation = null
                secret?.fill(0)
                binding.fill(0)
                invoke.reject("biometric_unavailable")
            }
        }
    }

    @Command
    fun localStatus(invoke: Invoke) {
        val result = JSObject()
        result.put("exists", secureStore.exists())
        result.put("accessible", secureStore.isAccessible())
        invoke.resolve(result)
    }

    @Command
    fun storeLocal(invoke: Invoke) {
        var bytes = ByteArray(0)
        try {
            val args = invoke.parseArgs(EncodedWalletArgs::class.java)
            bytes = decodeOfficialBackup(args.dataBase64)
            secureStore.store(bytes)
            invoke.resolve()
        } catch (_: Exception) {
            invoke.reject("secure_local_store_failed")
        } finally {
            bytes.fill(0)
        }
    }

    @Command
    fun replaceInaccessibleLocal(invoke: Invoke) {
        var bytes = ByteArray(0)
        try {
            val args = invoke.parseArgs(EncodedWalletArgs::class.java)
            bytes = decodeOfficialBackup(args.dataBase64)
            secureStore.replaceInaccessible(bytes)
            invoke.resolve()
        } catch (_: Exception) {
            invoke.reject("secure_local_recovery_failed")
        } finally {
            bytes.fill(0)
        }
    }

    @Command
    fun loadLocal(invoke: Invoke) {
        var bytes = ByteArray(0)
        try {
            bytes = secureStore.load()
            val result = JSObject()
            result.put("dataBase64", Base64.encodeToString(bytes, Base64.NO_WRAP))
            invoke.resolve(result)
        } catch (_: Exception) {
            invoke.reject("keystore_unavailable_or_wallet_corrupt")
        } finally {
            bytes.fill(0)
        }
    }

    @Command
    fun saveDocument(invoke: Invoke) {
        var bytes = ByteArray(0)
        try {
            val args = invoke.parseArgs(SaveDocumentArgs::class.java)
            bytes = decodeOfficialBackup(args.dataBase64)
            requireValidFilename(args.suggestedName)
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_TITLE, args.suggestedName)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            }
            startActivityForResult(invoke, intent, "saveDocumentResult")
        } catch (_: Exception) {
            invoke.reject("invalid_backup_export_request")
        } finally {
            bytes.fill(0)
        }
    }

    @ActivityCallback
    fun saveDocumentResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK) {
            invoke.reject("document_selection_cancelled")
            return
        }
        val uri = result.data?.data
        if (uri == null) {
            invoke.reject("document_provider_failed")
            return
        }
        var bytes = ByteArray(0)
        try {
            val args = invoke.parseArgs(SaveDocumentArgs::class.java)
            bytes = decodeOfficialBackup(args.dataBase64)
            writeAndVerify(uri, bytes)
            val response = JSObject()
            response.put("uri", uri.toString())
            response.put("bytesWritten", bytes.size)
            invoke.resolve(response)
        } catch (_: Exception) {
            invoke.reject("document_write_or_verification_failed")
        } finally {
            bytes.fill(0)
        }
    }

    @Command
    fun openDocument(invoke: Invoke) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivityForResult(invoke, intent, "openDocumentResult")
    }

    @ActivityCallback
    fun openDocumentResult(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode != Activity.RESULT_OK) {
            invoke.reject("document_selection_cancelled")
            return
        }
        val uri = result.data?.data
        if (uri == null) {
            invoke.reject("document_provider_failed")
            return
        }
        var bytes = ByteArray(0)
        try {
            bytes = readOfficialBackup(uri)
            val response = JSObject()
            response.put("dataBase64", Base64.encodeToString(bytes, Base64.NO_WRAP))
            invoke.resolve(response)
        } catch (_: Exception) {
            invoke.reject("invalid_or_unreadable_backup")
        } finally {
            bytes.fill(0)
        }
    }

    private fun writeAndVerify(uri: Uri, bytes: ByteArray) {
        val descriptor = activity.contentResolver.openFileDescriptor(uri, "rwt")
            ?: throw IllegalStateException("document_provider_failed")
        descriptor.use { parcel ->
            FileOutputStream(parcel.fileDescriptor).use { output ->
                output.write(bytes)
                output.flush()
                output.fd.sync()
            }
        }
        val verified = readOfficialBackup(uri)
        try {
            if (!verified.contentEquals(bytes)) {
                throw IllegalStateException("document_verification_failed")
            }
        } finally {
            verified.fill(0)
        }
    }

    private fun readOfficialBackup(uri: Uri): ByteArray {
        val input = activity.contentResolver.openInputStream(uri)
            ?: throw IllegalStateException("document_provider_failed")
        input.use { stream ->
            val output = ByteArrayOutputStream(SecureWalletStore.OFFICIAL_BACKUP_BYTES)
            val buffer = ByteArray(256)
            try {
                var total = 0
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > SecureWalletStore.OFFICIAL_BACKUP_BYTES) {
                        throw IllegalArgumentException("wallet_backup_too_large")
                    }
                    output.write(buffer, 0, count)
                }
                val bytes = output.toByteArray()
                if (bytes.size != SecureWalletStore.OFFICIAL_BACKUP_BYTES) {
                    bytes.fill(0)
                    throw IllegalArgumentException("invalid_wallet_size")
                }
                return bytes
            } finally {
                buffer.fill(0)
            }
        }
    }

    private fun decodeOfficialBackup(value: String): ByteArray {
        val bytes = Base64.decode(value, Base64.NO_WRAP)
        if (bytes.size != SecureWalletStore.OFFICIAL_BACKUP_BYTES) {
            throw IllegalArgumentException("invalid_wallet_size")
        }
        return bytes
    }

    private fun requireValidFilename(value: String) {
        if (value.isBlank() || value.length > 128 || value.any { it == '/' || it == '\\' || it == '\u0000' }) {
            throw IllegalArgumentException("invalid_filename")
        }
    }
}
