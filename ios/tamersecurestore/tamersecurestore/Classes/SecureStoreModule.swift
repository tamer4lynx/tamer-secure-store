import Foundation
import Lynx
#if !os(tvOS)
import LocalAuthentication
#endif
import Security

@objcMembers
public final class SecureStoreModule: NSObject, LynxModule {

    @objc public static var name: String { "SecureStoreModule" }

    @objc public static var methodLookup: [String: String] {
        [
            "getValueWithKeyAsync": NSStringFromSelector(#selector(getValueWithKeyAsync(_:optionsJson:callback:))),
            "setValueWithKeyAsync": NSStringFromSelector(#selector(setValueWithKeyAsync(_:value:optionsJson:callback:))),
            "deleteValueWithKeyAsync": NSStringFromSelector(#selector(deleteValueWithKeyAsync(_:optionsJson:callback:))),
            "getValueWithKeySync": NSStringFromSelector(#selector(getValueWithKeySync(_:optionsJson:))),
            "setValueWithKeySync": NSStringFromSelector(#selector(setValueWithKeySync(_:value:optionsJson:))),
            "canUseBiometricAuthentication": NSStringFromSelector(#selector(canUseBiometricAuthentication))
        ]
    }

    @objc public init(param: Any) { super.init() }
    @objc public override init() { super.init() }

    @objc func getValueWithKeyAsync(_ key: String, optionsJson: String, callback: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let options = SecureStoreOptions.from(json: optionsJson)
                let value = try self.get(with: key, options: options)
                callback(self.createJSONString(["value": value ?? NSNull()]))
            } catch {
                callback(self.createJSONString(["error": error.localizedDescription]))
            }
        }
    }

    @objc func setValueWithKeyAsync(_ key: String, value: String, optionsJson: String, callback: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let options = SecureStoreOptions.from(json: optionsJson)
                _ = try self.set(value: value, with: key, options: options)
                callback("{}")
            } catch {
                callback(self.createJSONString(["error": error.localizedDescription]))
            }
        }
    }

    @objc func deleteValueWithKeyAsync(_ key: String, optionsJson: String, callback: @escaping (String) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let options = SecureStoreOptions.from(json: optionsJson)
                let noAuth = self.query(with: key, options: options, requireAuthentication: false)
                let auth = self.query(with: key, options: options, requireAuthentication: true)
                let legacy = self.query(with: key, options: options)
                SecItemDelete(legacy as CFDictionary)
                SecItemDelete(auth as CFDictionary)
                SecItemDelete(noAuth as CFDictionary)
                callback("{}")
            } catch {
                callback(self.createJSONString(["error": error.localizedDescription]))
            }
        }
    }

    @objc func getValueWithKeySync(_ key: String, optionsJson: String) -> String? {
        let options = SecureStoreOptions.from(json: optionsJson)
        return try? get(with: key, options: options)
    }

    @objc func setValueWithKeySync(_ key: String, value: String, optionsJson: String) {
        let options = SecureStoreOptions.from(json: optionsJson)
        _ = try? set(value: value, with: key, options: options)
    }

    @objc func canUseBiometricAuthentication() -> Bool {
        #if os(tvOS)
        return false
        #else
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) && error == nil
        #endif
    }

    private func get(with key: String, options: SecureStoreOptions) throws -> String? {
        if let data = try searchKeyChain(with: key, options: options, requireAuthentication: false) {
            return String(data: data, encoding: .utf8)
        }
        if let data = try searchKeyChain(with: key, options: options, requireAuthentication: true) {
            return String(data: data, encoding: .utf8)
        }
        if let data = try searchKeyChain(with: key, options: options) {
            return String(data: data, encoding: .utf8)
        }
        return nil
    }

    private func set(value: String, with key: String, options: SecureStoreOptions) throws -> Bool {
        var setItemQuery = query(with: key, options: options, requireAuthentication: options.requireAuthentication)
        setItemQuery[kSecValueData as String] = value.data(using: .utf8)
        let accessibility = attributeWith(options: options)

        if !options.requireAuthentication {
            setItemQuery[kSecAttrAccessible as String] = accessibility
        } else {
            guard Bundle.main.infoDictionary?["NSFaceIDUsageDescription"] as? String != nil else {
                throw NSError(domain: "SecureStore", code: -1, userInfo: [NSLocalizedDescriptionKey: "NSFaceIDUsageDescription required in Info.plist for requireAuthentication"])
            }
            var error: Unmanaged<CFError>?
            guard let accessOptions = SecAccessControlCreateWithFlags(kCFAllocatorDefault, accessibility, .biometryCurrentSet, &error) else {
                throw NSError(domain: "SecureStore", code: -1, userInfo: [NSLocalizedDescriptionKey: "SecAccessControlCreateWithFlags failed"])
            }
            setItemQuery[kSecAttrAccessControl as String] = accessOptions
        }

        let status = SecItemAdd(setItemQuery as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            SecItemDelete(query(with: key, options: options) as CFDictionary)
            SecItemDelete(query(with: key, options: options, requireAuthentication: !options.requireAuthentication) as CFDictionary)
            return true
        case errSecDuplicateItem:
            return try update(value: value, with: key, options: options)
        default:
            throw NSError(domain: "SecureStore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error"])
        }
    }

    private func update(value: String, with key: String, options: SecureStoreOptions) throws -> Bool {
        var q = query(with: key, options: options, requireAuthentication: options.requireAuthentication)
        if !options.authenticationPrompt.isEmpty {
            q[kSecUseOperationPrompt as String] = options.authenticationPrompt
        }
        let updateDict = [kSecValueData as String: value.data(using: .utf8)!]
        let status = SecItemUpdate(q as CFDictionary, updateDict as CFDictionary)
        if status == errSecSuccess { return true }
        throw NSError(domain: "SecureStore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error"])
    }

    private func searchKeyChain(with key: String, options: SecureStoreOptions, requireAuthentication: Bool? = nil) throws -> Data? {
        var q = query(with: key, options: options, requireAuthentication: requireAuthentication)
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecReturnData as String] = kCFBooleanTrue
        if !options.authenticationPrompt.isEmpty {
            q[kSecUseOperationPrompt as String] = options.authenticationPrompt
        }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return item as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw NSError(domain: "SecureStore", code: Int(status), userInfo: [NSLocalizedDescriptionKey: (SecCopyErrorMessageString(status, nil) as String?) ?? "Keychain error"])
        }
    }

    private func query(with key: String, options: SecureStoreOptions, requireAuthentication: Bool? = nil) -> [String: Any] {
        var service = options.keychainService
        if let req = requireAuthentication {
            service += ":\(req ? "auth" : "no-auth")"
        }
        let encodedKey = Data(key.utf8)
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrGeneric as String: encodedKey,
            kSecAttrAccount as String: encodedKey
        ]
        if let accessGroup = options.accessGroup {
            q[kSecAttrAccessGroup as String] = accessGroup
        }
        return q
    }

    private func attributeWith(options: SecureStoreOptions) -> CFString {
        switch options.keychainAccessible {
        case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock
        case .afterFirstUnlockThisDeviceOnly: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .always: return kSecAttrAccessibleAlways
        case .whenPasscodeSetThisDeviceOnly: return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked
        case .alwaysThisDeviceOnly: return kSecAttrAccessibleAlwaysThisDeviceOnly
        case .whenUnlockedThisDeviceOnly: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
    }

    private func createJSONString(_ dict: [String: Any]) -> String {
        (try? JSONSerialization.data(withJSONObject: dict)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }
}
