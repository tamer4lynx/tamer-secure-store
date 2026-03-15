package com.nanofuxion.tamersecurestore

import android.annotation.TargetApi
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.UnrecoverableEntryException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class AESEncryptor {

    fun getKeyStoreAlias(options: SecureStoreOptions): String {
        return "$AES_CIPHER:${options.keychainService}"
    }

    fun getExtendedKeyStoreAlias(options: SecureStoreOptions, requireAuthentication: Boolean): String {
        val suffix = if (requireAuthentication) {
            SecureStoreModule.AUTHENTICATED_KEYSTORE_SUFFIX
        } else {
            SecureStoreModule.UNAUTHENTICATED_KEYSTORE_SUFFIX
        }
        return "${getKeyStoreAlias(options)}:$suffix"
    }

    @TargetApi(23)
    @Throws(GeneralSecurityException::class)
    fun initializeKeyStoreEntry(keyStore: KeyStore, options: SecureStoreOptions): KeyStore.SecretKeyEntry {
        if (Build.VERSION.SDK_INT < 23) {
            throw GeneralSecurityException("SecureStore requires Android API 23+")
        }
        val extendedKeystoreAlias = getExtendedKeyStoreAlias(options, options.requireAuthentication)
        val keyPurposes = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT

        val algorithmSpec: AlgorithmParameterSpec = KeyGenParameterSpec.Builder(extendedKeystoreAlias, keyPurposes)
            .setKeySize(AES_KEY_SIZE_BITS)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(options.requireAuthentication)
            .build()

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, keyStore.provider)
        keyGenerator.init(algorithmSpec)
        keyGenerator.generateKey()
        return keyStore.getEntry(extendedKeystoreAlias, null) as? KeyStore.SecretKeyEntry
            ?: throw UnrecoverableEntryException("Could not retrieve the newly generated secret key entry")
    }

    @Throws(GeneralSecurityException::class)
    fun createEncryptedItem(
        plaintextValue: String,
        keyStoreEntry: KeyStore.SecretKeyEntry,
        requireAuthentication: Boolean,
        authenticationPrompt: String,
        authenticationHelper: AuthenticationHelper
    ): JSONObject {
        val secretKey = keyStoreEntry.secretKey
        val cipher = Cipher.getInstance(AES_CIPHER)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val gcmSpec = cipher.parameters.getParameterSpec(GCMParameterSpec::class.java)
        val authenticatedCipher = authenticationHelper.authenticateCipher(cipher, requireAuthentication, authenticationPrompt)
        return createEncryptedItemWithCipher(plaintextValue, authenticatedCipher, gcmSpec)
    }

    internal fun createEncryptedItemWithCipher(
        plaintextValue: String,
        cipher: Cipher,
        gcmSpec: GCMParameterSpec
    ): JSONObject {
        val plaintextBytes = plaintextValue.toByteArray(StandardCharsets.UTF_8)
        val ciphertextBytes = cipher.doFinal(plaintextBytes)
        val ciphertext = Base64.encodeToString(ciphertextBytes, Base64.NO_WRAP)
        val ivString = Base64.encodeToString(gcmSpec.iv, Base64.NO_WRAP)
        return JSONObject()
            .put(CIPHERTEXT_PROPERTY, ciphertext)
            .put(IV_PROPERTY, ivString)
            .put(GCM_AUTHENTICATION_TAG_LENGTH_PROPERTY, gcmSpec.tLen)
    }

    @Throws(GeneralSecurityException::class)
    fun decryptItem(
        key: String,
        encryptedItem: JSONObject,
        keyStoreEntry: KeyStore.SecretKeyEntry,
        options: SecureStoreOptions,
        authenticationHelper: AuthenticationHelper
    ): String {
        val ciphertext = encryptedItem.getString(CIPHERTEXT_PROPERTY)
        val ivString = encryptedItem.getString(IV_PROPERTY)
        val authenticationTagLength = encryptedItem.getInt(GCM_AUTHENTICATION_TAG_LENGTH_PROPERTY)
        val ciphertextBytes = Base64.decode(ciphertext, Base64.DEFAULT)
        val ivBytes = Base64.decode(ivString, Base64.DEFAULT)
        val gcmSpec = GCMParameterSpec(authenticationTagLength, ivBytes)
        val cipher = Cipher.getInstance(AES_CIPHER)
        val requiresAuthentication = encryptedItem.optBoolean(AuthenticationHelper.REQUIRE_AUTHENTICATION_PROPERTY)
        if (authenticationTagLength < MIN_GCM_AUTHENTICATION_TAG_LENGTH) {
            throw GeneralSecurityException("Authentication tag length must be at least $MIN_GCM_AUTHENTICATION_TAG_LENGTH bits long")
        }
        cipher.init(Cipher.DECRYPT_MODE, keyStoreEntry.secretKey, gcmSpec)
        val unlockedCipher = authenticationHelper.authenticateCipher(cipher, requiresAuthentication, options.authenticationPrompt)
        return String(unlockedCipher.doFinal(ciphertextBytes), StandardCharsets.UTF_8)
    }

    companion object {
        const val NAME = "aes"
        const val AES_CIPHER = "AES/GCM/NoPadding"
        const val AES_KEY_SIZE_BITS = 256
        private const val CIPHERTEXT_PROPERTY = "ct"
        const val IV_PROPERTY = "iv"
        private const val GCM_AUTHENTICATION_TAG_LENGTH_PROPERTY = "tlen"
        private const val MIN_GCM_AUTHENTICATION_TAG_LENGTH = 96
    }
}
