package com.nanofuxion.tamersecurestore

import org.json.JSONObject

data class SecureStoreOptions(
    val keychainService: String = DEFAULT_KEYSTORE_ALIAS,
    val requireAuthentication: Boolean = false,
    val authenticationPrompt: String = " ",
) {
    companion object {
        const val DEFAULT_KEYSTORE_ALIAS = "key_v1"

        fun fromJson(json: String): SecureStoreOptions {
            return try {
                val obj = JSONObject(json)
                SecureStoreOptions(
                    keychainService = obj.optString("keychainService", DEFAULT_KEYSTORE_ALIAS),
                    requireAuthentication = obj.optBoolean("requireAuthentication", false),
                    authenticationPrompt = obj.optString("authenticationPrompt", " ").ifEmpty { " " },
                )
            } catch (_: Exception) {
                SecureStoreOptions()
            }
        }
    }
}
