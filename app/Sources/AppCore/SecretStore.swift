import Foundation
import Security

public protocol SecretStoring: AnyObject {
    func token() -> String?
    func setToken(_ token: String) throws
    func deleteToken()
}

public struct KeychainError: Error { public let status: OSStatus }

/// The bearer token in the login keychain (legacy, not the data-protection
/// keychain), a generic password, not synchronizable (owner decision A5-fix).
public final class KeychainSecretStore: SecretStoring {
    private let service: String
    private let account: String

    public init(service: String = "se.klippel.sendndes", account: String = "bearer-token") {
        self.service = service
        self.account = account
    }

    private var base: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    public func token() -> String? {
        var q = base
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    public func setToken(_ token: String) throws {
        deleteToken()
        var q = base
        q[kSecValueData as String] = Data(token.utf8)
        let s = SecItemAdd(q as CFDictionary, nil)
        if s != errSecSuccess { throw KeychainError(status: s) }
    }

    public func deleteToken() {
        SecItemDelete(base as CFDictionary)
    }
}
