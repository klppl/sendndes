import Foundation
import Security

/// The bearer token together with the server it was saved for (M3): the canonical scheme+host+port,
/// and optionally the vault's ServerKeys (inbox_pub and K_auth) for client-sealed uploads.
/// `server` is nil for an item saved before the binding existed; such a token is never sent.
public struct StoredCredential: Equatable {
    public let token: String
    public let server: String?
    public let serverKeys: ServerKeys?
    public init(token: String, server: String?, serverKeys: ServerKeys? = nil) {
        self.token = token
        self.server = server
        self.serverKeys = serverKeys
    }
}

public protocol SecretStoring: AnyObject {
    func credential() -> StoredCredential?
    func setCredential(token: String, server: String, serverKeys: ServerKeys?) throws
    func deleteToken()
    /// Scopes the credential to a vault: each vault has its own server address, token and keys.
    /// `adoptLegacy` moves the old single (unscoped) credential to this vault if it has none yet.
    func select(vault: String, adoptLegacy: Bool)
}

extension SecretStoring {
    public func select(vault: String, adoptLegacy: Bool) {}
    public func setCredential(token: String, server: String) throws {
        try setCredential(token: token, server: server, serverKeys: nil)
    }
}

public struct KeychainError: Error { public let status: OSStatus }

/// The bearer token and server keys in the login keychain (legacy, not the data-protection
/// keychain), a generic password, not synchronizable (owner decision A5-fix).
public final class KeychainSecretStore: SecretStoring {
    private let service: String
    private let legacyAccount: String
    private var account: String

    public init(service: String = "se.klippel.sendndes", account: String = "bearer-token") {
        self.service = service
        self.legacyAccount = account
        self.account = account
    }

    public func select(vault: String, adoptLegacy: Bool) {
        let scoped = vault.isEmpty ? legacyAccount : legacyAccount + ":" + vault
        guard scoped != legacyAccount else { account = scoped; return }
        account = scoped
        guard adoptLegacy, credential() == nil else { return }
        var q = base
        q[kSecAttrAccount as String] = legacyAccount
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return }
        var add = base
        add[kSecValueData as String] = d
        if SecItemAdd(add as CFDictionary, nil) == errSecSuccess {
            SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                           kSecAttrService as String: service,
                           kSecAttrAccount as String: legacyAccount,
                           kSecAttrSynchronizable as String: false] as CFDictionary)
        }
    }

    private var base: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    private struct Payload: Codable {
        let v: Int
        let server: String
        let token: String
        var inboxPub: String?
        var kAuth: String?
    }

    public func credential() -> StoredCredential? {
        var q = base
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        if let p = try? JSONDecoder().decode(Payload.self, from: d), p.v == 1 {
            let keys: ServerKeys?
            if let pub = p.inboxPub, let auth = p.kAuth {
                keys = ServerKeys(inboxPub: pub, kAuth: auth)
            } else {
                keys = nil
            }
            return StoredCredential(token: p.token, server: p.server, serverKeys: keys)
        }
        // An older item: the raw token with no server. It stays visible as "saved" but is never sent.
        return String(data: d, encoding: .utf8).map { StoredCredential(token: $0, server: nil) }
    }

    public func setCredential(token: String, server: String, serverKeys: ServerKeys? = nil) throws {
        deleteToken()
        var q = base
        let payload = Payload(v: 1, server: server, token: token, inboxPub: serverKeys?.inboxPub, kAuth: serverKeys?.kAuth)
        q[kSecValueData as String] = try JSONEncoder().encode(payload)
        let s = SecItemAdd(q as CFDictionary, nil)
        if s != errSecSuccess { throw KeychainError(status: s) }
    }

    public func deleteToken() {
        SecItemDelete(base as CFDictionary)
    }
}
