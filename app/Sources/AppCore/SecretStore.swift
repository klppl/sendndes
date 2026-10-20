import Foundation
import Security

/// The bearer token together with the server it was saved for (M3): the canonical scheme+host+port.
/// `server` is nil for an item saved before the binding existed; such a token is never sent.
public struct StoredCredential: Equatable {
    public let token: String
    public let server: String?
    public init(token: String, server: String?) { self.token = token; self.server = server }
}

public protocol SecretStoring: AnyObject {
    func credential() -> StoredCredential?
    func setCredential(token: String, server: String) throws
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

    private struct Payload: Codable { let v: Int; let server: String; let token: String }

    public func credential() -> StoredCredential? {
        var q = base
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        if let p = try? JSONDecoder().decode(Payload.self, from: d), p.v == 1 {
            return StoredCredential(token: p.token, server: p.server)
        }
        // An older item: the raw token with no server. It stays visible as "saved" but is never sent.
        return String(data: d, encoding: .utf8).map { StoredCredential(token: $0, server: nil) }
    }

    public func setCredential(token: String, server: String) throws {
        deleteToken()
        var q = base
        q[kSecValueData as String] = try JSONEncoder().encode(Payload(v: 1, server: server, token: token))
        let s = SecItemAdd(q as CFDictionary, nil)
        if s != errSecSuccess { throw KeychainError(status: s) }
    }

    public func deleteToken() {
        SecItemDelete(base as CFDictionary)
    }
}
