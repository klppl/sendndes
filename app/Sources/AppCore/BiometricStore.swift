import Foundation
import LocalAuthentication
import Security
import CryptoKit

/// Optional "unlock with Touch ID": the vault passphrase is kept in the login keychain and only released after
/// the user passes a Touch ID (or Mac password) check.
public protocol BiometricUnlocking: AnyObject {
    var isAvailable: Bool { get }
    func hasPassphrase(vault: String) -> Bool
    func save(passphrase: String, vault: String) throws
    /// Prompts for Touch ID; nil when cancelled or failed.
    func load(vault: String, reason: String) async -> String?
    func remove(vault: String)
}

/// The passphrase item is an ordinary login-keychain generic password (not synchronizable). The Touch ID check is
/// enforced by this app (LocalAuthentication), not by the keychain: this build is ad-hoc signed and cannot use a
/// biometry-bound keychain item. Anything that can read the login keychain as you can read the item.
public final class KeychainBiometricStore: BiometricUnlocking {
    private let service: String

    public init(service: String = "se.klippel.sendndes.vault-passphrase") { self.service = service }

    public var isAvailable: Bool {
        var err: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
    }

    private func base(_ vault: String) -> [String: Any] {
        let id = SHA256.hash(data: Data(vault.utf8)).prefix(8).map { String(format: "%02x", $0) }.joined()
        return [kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: id,
                kSecAttrSynchronizable as String: false]
    }

    public func hasPassphrase(vault: String) -> Bool {
        var q = base(vault)
        let quiet = LAContext()
        quiet.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = quiet
        let s = SecItemCopyMatching(q as CFDictionary, nil)
        return s == errSecSuccess || s == errSecInteractionNotAllowed
    }

    public func save(passphrase: String, vault: String) throws {
        remove(vault: vault)
        var q = base(vault)
        q[kSecValueData as String] = Data(passphrase.utf8)
        let s = SecItemAdd(q as CFDictionary, nil)
        if s != errSecSuccess { throw KeychainError(status: s) }
    }

    public func load(vault: String, reason: String) async -> String? {
        let ctx = LAContext()
        do { guard try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else { return nil } }
        catch { return nil }
        var q = base(vault)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }

    public func remove(vault: String) { SecItemDelete(base(vault) as CFDictionary) }
}
