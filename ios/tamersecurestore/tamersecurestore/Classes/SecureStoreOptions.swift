import Foundation

struct SecureStoreOptions {
    var keychainService: String
    var requireAuthentication: Bool
    var authenticationPrompt: String
    var keychainAccessible: SecureStoreAccessible
    var accessGroup: String?

    static let defaultKeychainService = "key_v1"

    init(
        keychainService: String = defaultKeychainService,
        requireAuthentication: Bool = false,
        authenticationPrompt: String = " ",
        keychainAccessible: SecureStoreAccessible = .whenUnlocked,
        accessGroup: String? = nil
    ) {
        self.keychainService = keychainService
        self.requireAuthentication = requireAuthentication
        self.authenticationPrompt = authenticationPrompt.isEmpty ? " " : authenticationPrompt
        self.keychainAccessible = keychainAccessible
        self.accessGroup = accessGroup
    }

    static func from(json: String) -> SecureStoreOptions {
        guard let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return SecureStoreOptions()
        }
        let keychainService = obj["keychainService"] as? String ?? defaultKeychainService
        let requireAuthentication = obj["requireAuthentication"] as? Bool ?? false
        let authenticationPrompt = obj["authenticationPrompt"] as? String ?? " "
        let keychainAccessibleRaw = obj["keychainAccessible"] as? Int ?? SecureStoreAccessible.whenUnlocked.rawValue
        let keychainAccessible = SecureStoreAccessible(rawValue: keychainAccessibleRaw) ?? .whenUnlocked
        let accessGroup = obj["accessGroup"] as? String
        return SecureStoreOptions(
            keychainService: keychainService,
            requireAuthentication: requireAuthentication,
            authenticationPrompt: authenticationPrompt,
            keychainAccessible: keychainAccessible,
            accessGroup: accessGroup
        )
    }
}
