import Foundation
import Security

/// Where the three secrets of a pairing live. Behind a protocol so the logic is tested with a fake.
public protocol SecretStoring: AnyObject, Sendable {
    func read(_ item: SecretItem) throws -> Data?
    func write(_ item: SecretItem, _ data: Data) throws
    func deleteAll() throws
}

public enum SecretItem: String, CaseIterable, Sendable {
    case token, kAuth = "k_auth", inboxPub = "inbox_pub"
}

public struct SecretStoreError: Error, Equatable, Sendable { public let status: Int32 }

/// Keychain items in the shared access group: never synchronizable, never leaving this device.
/// The token is readable after the first unlock (a background upload may start while the phone is locked);
/// the keys that seal files only while the phone is unlocked (the share extension runs in front of the owner).
public final class KeychainSecrets: SecretStoring, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?

    public init(service: String = "se.klippel.sendndes.ios", accessGroup: String?) {
        self.service = service
        self.accessGroup = accessGroup
    }

    static func accessibility(for item: SecretItem) -> CFString {
        item == .token ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }

    private func query(_ item: SecretItem) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                kSecAttrService as String: service,
                                kSecAttrAccount as String: item.rawValue,
                                kSecAttrSynchronizable as String: false]
        if let g = accessGroup { q[kSecAttrAccessGroup as String] = g }
        return q
    }

    public func read(_ item: SecretItem) throws -> Data? {
        var q = query(item)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound { return nil }
        guard st == errSecSuccess, let d = out as? Data else { throw SecretStoreError(status: st) }
        return d
    }

    public func write(_ item: SecretItem, _ data: Data) throws {
        let del = SecItemDelete(query(item) as CFDictionary)
        guard del == errSecSuccess || del == errSecItemNotFound else { throw SecretStoreError(status: del) }
        var add = query(item)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = Self.accessibility(for: item)
        let st = SecItemAdd(add as CFDictionary, nil)
        guard st == errSecSuccess else { throw SecretStoreError(status: st) }
    }

    public func deleteAll() throws {
        for i in SecretItem.allCases {
            let st = SecItemDelete(query(i) as CFDictionary)
            guard st == errSecSuccess || st == errSecItemNotFound else { throw SecretStoreError(status: st) }
        }
    }
}

/// A fake for tests and previews.
public final class MemorySecrets: SecretStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [SecretItem: Data] = [:]
    public init() {}
    public func read(_ item: SecretItem) throws -> Data? { lock.lock(); defer { lock.unlock() }; return items[item] }
    public func write(_ item: SecretItem, _ data: Data) throws { lock.lock(); items[item] = data; lock.unlock() }
    public func deleteAll() throws { lock.lock(); items = [:]; lock.unlock() }
    public var isEmpty: Bool { lock.lock(); defer { lock.unlock() }; return items.isEmpty }
}
