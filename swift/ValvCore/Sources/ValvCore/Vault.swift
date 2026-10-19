import CryptoKit
import Foundation

/// Passphrase encoding (SPEC 3): valid UTF-8, then NFC, then its UTF-8 bytes.
/// No trimming, no case folding.
enum Passphrase {
    static let minimumCodePoints = 12

    static func normalizedUTF8(_ s: String) -> [UInt8] {
        // A Swift String is always valid Unicode, so only NFC is needed here.
        Array(s.precomposedStringWithCanonicalMapping.utf8)
    }

    static func normalizedUTF8<D: DataProtocol>(bytes d: D) throws -> [UInt8] {
        var raw = [UInt8](d)
        defer { wipe(&raw) }
        guard isValidUTF8(raw) else { throw ValvError.malformed("passphrase is not valid UTF-8") }
        return normalizedUTF8(String(decoding: raw, as: UTF8.self))
    }

    /// Code points counted after NFC.
    static func isLongEnough(normalized: [UInt8]) -> Bool {
        String(decoding: normalized, as: UTF8.self).unicodeScalars.count >= minimumCodePoints
    }
}

/// An unlocked vault: VK and the keys derived from it (SPEC 3).
///
/// `Vault.unlock`, `Vault.create` and `makeVaultJSON` run Argon2id. Nothing
/// else does: `Vault(vk:)` takes raw VK bytes (for example from the Keychain
/// in a File Provider extension, SPEC 9), and every object and inbox
/// operation works from an existing `Vault`.
public final class Vault: Sendable {
    let vk: SymmetricKey
    let kWrap: SymmetricKey
    let kAuth: SymmetricKey
    let inboxPrivateKey: Curve25519.KeyAgreement.PrivateKey
    /// `inbox_pub` = X25519(inbox private key, 9).
    public let inboxPublicKey: [UInt8]

    init(vkKey: SymmetricKey) throws {
        guard vkKey.bitCount == 256 else { throw ValvError.malformed("VK must be 32 bytes") }
        vk = vkKey
        kWrap = hkdf32(vkKey, info: Label.wrap)
        kAuth = hkdf32(vkKey, info: Label.inboxAuth)
        var priv = keyBytes(hkdf32(vkKey, info: Label.inboxX25519))
        X25519.clamp(&priv)
        inboxPrivateKey = try X25519.privateKey(&priv)
        inboxPublicKey = [UInt8](inboxPrivateKey.publicKey.rawRepresentation)
    }

    /// Opens a vault from raw VK bytes without running Argon2 (SPEC 9).
    /// Pass `vaultJSON` to also check `inbox_pub` (SPEC 4.3 step 3).
    public convenience init<K: ContiguousBytes>(vk raw: K, vaultJSON: Data? = nil) throws {
        let key = raw.withUnsafeBytes { SymmetricKey(data: $0) }
        try self.init(vkKey: key)
        if let vaultJSON {
            try checkInboxPublicKey(VaultConfig.parse(vaultJSON))
        }
    }

    /// The raw VK, for storing in the Keychain. Wipe the returned buffer after use.
    public func exportVK() -> [UInt8] {
        keyBytes(vk)
    }

    /// SPEC 4.3 step 3: constant-time comparison with the stored `inbox_pub`.
    public func checkInboxPublicKey(_ config: VaultConfig) throws {
        guard constantTimeEqual(inboxPublicKey, config.inboxPublicKey) else {
            throw ValvError.inboxKeyMismatch
        }
    }

    // MARK: Passphrase unlock (SPEC 4.3)

    public static func unlock<D: DataProtocol>(vaultJSON: D, passphrase: String) throws -> Vault {
        let config = try VaultConfig.parse(vaultJSON)  // before the KDF runs
        var pw = Passphrase.normalizedUTF8(passphrase)
        defer { wipe(&pw) }
        return try unlock(config: config, normalizedPassphrase: pw)
    }

    /// For passphrases read as bytes (stdin): rejects invalid UTF-8, then NFC.
    public static func unlock<D: DataProtocol, P: DataProtocol>(vaultJSON: D, passphraseUTF8: P) throws -> Vault {
        let config = try VaultConfig.parse(vaultJSON)
        var pw = try Passphrase.normalizedUTF8(bytes: passphraseUTF8)
        defer { wipe(&pw) }
        return try unlock(config: config, normalizedPassphrase: pw)
    }

    static func unlock(config: VaultConfig, normalizedPassphrase pw: [UInt8]) throws -> Vault {
        let kek = try Argon2id.deriveKEK(passphraseUTF8: pw, salt: config.salt)
        let nonce = config.wrappedVK.copy(from: 0, count: 12)
        let sealed = config.wrappedVK.copy(from: 12, count: 48)
        var vkData: Data
        do {
            vkData = try AEAD.open(sealed, key: kek, nonce: nonce, aad: config.configAAD, what: "wrapped_vk")
        } catch {
            throw ValvError.wrongPassphrase
        }
        defer { wipe(&vkData) }
        let vault = try Vault(vkKey: SymmetricKey(data: vkData))
        try vault.checkInboxPublicKey(config)
        return vault
    }

    // MARK: Creating and re-wrapping (SPEC 4.3 init, 4.4, 4.5 step 3)

    public struct Created: Sendable {
        public let vault: Vault
        /// The vault.json bytes to write (SPEC 8), read back and unlock.
        public let vaultJSON: Data
        /// Show once; the caller must confirm it was written out (SPEC 4.3).
        public let recoveryKey: String
    }

    /// Generates VK, salt and nonce and builds vault.json in memory (SPEC 4.3 init step 1).
    public static func create(passphrase: String, allowWeakPassphrase: Bool = false) throws -> Created {
        var pw = Passphrase.normalizedUTF8(passphrase)
        defer { wipe(&pw) }
        guard allowWeakPassphrase || Passphrase.isLongEnough(normalized: pw) else { throw ValvError.weakPassphrase }
        var vkRaw = Random.bytes(32, for: .vk)
        let vault = try Vault(vkKey: takeKey(&vkRaw))
        let json = try vault.wrap(normalizedPassphrase: pw)
        return Created(vault: vault, vaultJSON: json, recoveryKey: vault.recoveryKey)
    }

    /// A new vault.json for this VK under a new passphrase, with a fresh
    /// random salt and wrap nonce (SPEC 4.4, 4.5 step 3).
    public func makeVaultJSON(passphrase: String, allowWeakPassphrase: Bool = false) throws -> Data {
        var pw = Passphrase.normalizedUTF8(passphrase)
        defer { wipe(&pw) }
        guard allowWeakPassphrase || Passphrase.isLongEnough(normalized: pw) else { throw ValvError.weakPassphrase }
        return try wrap(normalizedPassphrase: pw)
    }

    private func wrap(normalizedPassphrase pw: [UInt8]) throws -> Data {
        let salt = Random.bytes(KDFParams.saltBytes, for: .kdfSalt)
        let nonce = Random.bytes(12, for: .vkWrapNonce)
        // config_aad needs inbox_pub and the salt; the ciphertext is filled in below.
        let draft = VaultConfig(salt: salt, wrappedVK: [UInt8](repeating: 0, count: 60), inboxPublicKey: inboxPublicKey)
        let kek = try Argon2id.deriveKEK(passphraseUTF8: pw, salt: salt)
        let sealed = vk.withUnsafeBytes { AEAD.seal($0, key: kek, nonce: nonce, aad: draft.configAAD) }
        let config = VaultConfig(salt: salt, wrappedVK: nonce + sealed, inboxPublicKey: inboxPublicKey)
        return config.serialized()
    }
}
