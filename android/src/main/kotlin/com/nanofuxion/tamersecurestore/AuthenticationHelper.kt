package com.nanofuxion.tamersecurestore

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher

class AuthenticationHelper(private val context: Context) {

    private var isAuthenticating = false

    companion object {
        const val REQUIRE_AUTHENTICATION_PROPERTY = "requireAuthentication"

        @Volatile
        internal var hostView: android.view.View? = null

        fun attachHostView(view: android.view.View?) {
            hostView = view
        }
    }

    fun authenticateCipher(cipher: Cipher, requiresAuthentication: Boolean, title: String): Cipher {
        if (!requiresAuthentication) return cipher
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            throw AuthenticationException("Biometric authentication requires Android API 23")
        }
        if (isAuthenticating) {
            throw AuthenticationException("Authentication is already in progress")
        }
        isAuthenticating = true
        try {
            assertBiometricsSupport()
            val fragmentActivity = getCurrentActivity()
                ?: throw AuthenticationException("Cannot display biometric prompt when the app is not in the foreground")
            val latch = CountDownLatch(1)
            val resultRef = AtomicReference<BiometricPrompt.AuthenticationResult?>()
            val errorRef = AtomicReference<Throwable?>()
            val executor = ContextCompat.getMainExecutor(context)
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText(context.getString(android.R.string.cancel))
                .build()
            executor.execute {
                BiometricPrompt(
                    fragmentActivity,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                            errorRef.set(AuthenticationException("$errorCode: $errString"))
                            latch.countDown()
                        }
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            resultRef.set(result)
                            latch.countDown()
                        }
                    }
                ).authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
            }
            latch.await(60, TimeUnit.SECONDS)
            errorRef.get()?.let { throw it }
            return resultRef.get()?.cryptoObject?.cipher
                ?: throw AuthenticationException("Couldn't get cipher from authentication result")
        } finally {
            isAuthenticating = false
        }
    }

    @SuppressLint("SwitchIntDef")
    fun assertBiometricsSupport() {
        val biometricManager = BiometricManager.from(context)
        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                throw AuthenticationException("No hardware available for biometric authentication")
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                throw AuthenticationException("No biometrics are currently enrolled")
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED ->
                throw AuthenticationException("An update is required before the biometrics can be used")
            BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED ->
                throw AuthenticationException("Biometric authentication is unsupported")
            BiometricManager.BIOMETRIC_STATUS_UNKNOWN ->
                throw AuthenticationException("Biometric authentication status is unknown")
        }
    }

    private fun getCurrentActivity(): FragmentActivity? {
        val view = hostView ?: return null
        var ctx: android.content.Context? = view.context
        while (ctx != null) {
            if (ctx is FragmentActivity) return ctx
            ctx = if (ctx is android.content.ContextWrapper) ctx.baseContext else null
        }
        return null
    }
}

internal class AuthenticationException(message: String?, cause: Throwable? = null) :
    Exception("Could not Authenticate the user: ${message ?: "unknown"}", cause)
