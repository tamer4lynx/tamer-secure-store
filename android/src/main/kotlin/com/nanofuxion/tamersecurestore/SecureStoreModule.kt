package com.nanofuxion.tamersecurestore

import android.content.Context
import android.content.SharedPreferences
import android.preference.PreferenceManager
import android.security.keystore.KeyPermanentlyInvalidatedException
import com.lynx.jsbridge.LynxMethod
import com.lynx.jsbridge.LynxModule
import com.lynx.react.bridge.Callback
import org.json.JSONException
import org.json.JSONObject
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.KeyStore.SecretKeyEntry
import javax.crypto.BadPaddingException

class SecureStoreModule(context: Context) : LynxModule(context) {

    private val mAESEncryptor = AESEncryptor()
    private lateinit var keyStore: KeyStore
    private lateinit var authenticationHelper: AuthenticationHelper

    init {
        keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        authenticationHelper = AuthenticationHelper(mContext)
    }

    @LynxMethod
    fun getValueWithKeyAsync(key: String, optionsJson: String, callback: Callback) {
        Thread {
            try {
                val options = SecureStoreOptions.fromJson(optionsJson)
                val value = getItemImpl(key, options)
                callback.invoke(JSONObject().apply { put("value", value) }.toString())
            } catch (e: Exception) {
                callback.invoke(JSONObject().apply { put("error", e.message ?: "Unknown error") }.toString())
            }
        }.start()
    }

    @LynxMethod
    fun setValueWithKeyAsync(key: String, value: String, optionsJson: String, callback: Callback) {
        Thread {
            try {
                val options = SecureStoreOptions.fromJson(optionsJson)
                setItemImpl(key, value, options, false)
                callback.invoke("{}")
            } catch (e: Exception) {
                callback.invoke(JSONObject().apply { put("error", e.message ?: "Unknown error") }.toString())
            }
        }.start()
    }

    @LynxMethod
    fun deleteValueWithKeyAsync(key: String, optionsJson: String, callback: Callback) {
        Thread {
            try {
                val options = SecureStoreOptions.fromJson(optionsJson)
                deleteItemImpl(key, options)
                callback.invoke("{}")
            } catch (e: Exception) {
                callback.invoke(JSONObject().apply { put("error", e.message ?: "Unknown error") }.toString())
            }
        }.start()
    }

    @LynxMethod
    fun getValueWithKeySync(key: String, optionsJson: String): String? {
        val options = SecureStoreOptions.fromJson(optionsJson)
        return getItemImpl(key, options)
    }

    @LynxMethod
    fun setValueWithKeySync(key: String, value: String, optionsJson: String) {
        val options = SecureStoreOptions.fromJson(optionsJson)
        setItemImpl(key, value, options, false)
    }

    @LynxMethod
    fun canUseBiometricAuthentication(): Boolean {
        return try {
            authenticationHelper.assertBiometricsSupport()
            true
        } catch (e: AuthenticationException) {
            false
        }
    }

    private fun getItemImpl(key: String, options: SecureStoreOptions): String? {
        val prefs = getSharedPreferences()
        val keychainAwareKey = createKeychainAwareKey(key, options.keychainService)
        val encryptedItemString = prefs.getString(keychainAwareKey, null) ?: prefs.getString(key, null) ?: return null
        val encryptedItem = try {
            JSONObject(encryptedItemString)
        } catch (e: JSONException) {
            throw RuntimeException("Could not parse encrypted item: ${e.message}")
        }
        val scheme = encryptedItem.optString(SCHEME_PROPERTY).takeIf { it.isNotEmpty() }
            ?: return null
        val requireAuthentication = encryptedItem.optBoolean(AuthenticationHelper.REQUIRE_AUTHENTICATION_PROPERTY, false)
        val usesKeystoreSuffix = encryptedItem.optBoolean(USES_KEYSTORE_SUFFIX_PROPERTY, false)
        if (scheme != AESEncryptor.NAME) return null
        try {
            val secretKeyEntry = getKeyEntryCompat(mAESEncryptor, options, requireAuthentication, usesKeystoreSuffix)
                ?: run {
                    deleteItemImpl(key, options)
                    return null
                }
            return mAESEncryptor.decryptItem(key, encryptedItem, secretKeyEntry, options, authenticationHelper)
        } catch (e: KeyPermanentlyInvalidatedException) {
            return null
        } catch (e: BadPaddingException) {
            deleteItemImpl(key, options)
            return null
        } catch (e: GeneralSecurityException) {
            throw RuntimeException("Decrypt failed: ${e.message}")
        }
    }

    private fun setItemImpl(key: String, value: String?, options: SecureStoreOptions, keyIsInvalidated: Boolean) {
        val keychainAwareKey = createKeychainAwareKey(key, options.keychainService)
        val prefs = getSharedPreferences()
        if (value == null) {
            prefs.edit().remove(keychainAwareKey).remove(key).commit()
            return
        }
        try {
            if (keyIsInvalidated) {
                val alias = mAESEncryptor.getExtendedKeyStoreAlias(options, options.requireAuthentication)
                keyStore.deleteEntry(alias)
            }
            val secretKeyEntry = getOrCreateKeyEntry(mAESEncryptor, options, options.requireAuthentication)
            val encryptedItem = mAESEncryptor.createEncryptedItem(value, secretKeyEntry, options.requireAuthentication, options.authenticationPrompt, authenticationHelper)
            encryptedItem.put(SCHEME_PROPERTY, AESEncryptor.NAME)
            encryptedItem.put(USES_KEYSTORE_SUFFIX_PROPERTY, true)
            encryptedItem.put(KEYSTORE_ALIAS_PROPERTY, options.keychainService)
            encryptedItem.put(AuthenticationHelper.REQUIRE_AUTHENTICATION_PROPERTY, options.requireAuthentication)
            prefs.edit().putString(keychainAwareKey, encryptedItem.toString()).commit()
            prefs.edit().remove(key).apply()
        } catch (e: KeyPermanentlyInvalidatedException) {
            if (!keyIsInvalidated) setItemImpl(key, value, options, true)
            else throw RuntimeException("Key invalidated: ${e.message}")
        } catch (e: GeneralSecurityException) {
            throw RuntimeException("Encrypt failed: ${e.message}")
        }
    }

    private fun deleteItemImpl(key: String, options: SecureStoreOptions) {
        val prefs = getSharedPreferences()
        val keychainAwareKey = createKeychainAwareKey(key, options.keychainService)
        val legacyPrefs = PreferenceManager.getDefaultSharedPreferences(mContext)
        prefs.edit().remove(keychainAwareKey).remove(key).commit()
        legacyPrefs.edit().remove(key).commit()
    }

    private fun getKeyEntry(encryptor: AESEncryptor, options: SecureStoreOptions, requireAuthentication: Boolean): SecretKeyEntry? {
        val keystoreAlias = encryptor.getExtendedKeyStoreAlias(options, requireAuthentication)
        return if (keyStore.containsAlias(keystoreAlias)) {
            keyStore.getEntry(keystoreAlias, null) as? SecretKeyEntry
        } else null
    }

    private fun getLegacyKeyEntry(encryptor: AESEncryptor, options: SecureStoreOptions): SecretKeyEntry? {
        val keystoreAlias = encryptor.getKeyStoreAlias(options)
        return if (keyStore.containsAlias(keystoreAlias)) {
            keyStore.getEntry(keystoreAlias, null) as? SecretKeyEntry
        } else null
    }

    private fun getKeyEntryCompat(
        encryptor: AESEncryptor,
        options: SecureStoreOptions,
        requireAuthentication: Boolean,
        usesKeystoreSuffix: Boolean
    ): SecretKeyEntry? {
        return if (usesKeystoreSuffix) {
            getKeyEntry(encryptor, options, requireAuthentication)
        } else {
            getLegacyKeyEntry(encryptor, options)
        }
    }

    private fun getOrCreateKeyEntry(
        encryptor: AESEncryptor,
        options: SecureStoreOptions,
        requireAuthentication: Boolean
    ): SecretKeyEntry {
        return getKeyEntry(encryptor, options, requireAuthentication)
            ?: run {
                if (requireAuthentication) authenticationHelper.assertBiometricsSupport()
                encryptor.initializeKeyStoreEntry(keyStore, options)
            }
    }

    private fun getSharedPreferences(): SharedPreferences {
        return mContext.getSharedPreferences(SHARED_PREFERENCES_NAME, Context.MODE_PRIVATE)
    }

    private fun createKeychainAwareKey(key: String, keychainService: String) = "$keychainService-$key"

    companion object {
        private const val TAG = "SecureStoreModule"

        fun attachHostView(view: android.view.View?) {
            AuthenticationHelper.attachHostView(view)
        }
        private const val SHARED_PREFERENCES_NAME = "SecureStore"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val SCHEME_PROPERTY = "scheme"
        private const val KEYSTORE_ALIAS_PROPERTY = "keystoreAlias"
        const val USES_KEYSTORE_SUFFIX_PROPERTY = "usesKeystoreSuffix"
        const val AUTHENTICATED_KEYSTORE_SUFFIX = "keystoreAuthenticated"
        const val UNAUTHENTICATED_KEYSTORE_SUFFIX = "keystoreUnauthenticated"
    }
}
