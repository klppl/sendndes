import CryptoKit
import Foundation

/// Recovery key (SPEC 3): base32(VK | first 3 bytes of
/// SHA-256("valv/v1/recovery-checksum" | VK)), 56 characters in 14 groups of 4.
enum RecoveryKey {
    static let alphabet: [UInt8] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)
    static let characters = 56

    static func checksum(_ vk: SymmetricKey) -> [UInt8] {
        var h = SHA256()
        h.update(data: Label.recoveryChecksum)
        vk.withUnsafeBytes { h.update(bufferPointer: $0) }
        return Array(h.finalize()).copy(from: 0, count: 3)
    }

    static func encode(_ vk: SymmetricKey) -> String {
        var raw = keyBytes(vk) + checksum(vk)  // 35 bytes = 280 bits = 56 chars
        defer { wipe(&raw) }
        var chars = [UInt8]()
        var buffer: UInt32 = 0
        var bits = 0
        for b in raw {
            buffer = buffer << 8 | UInt32(b)
            bits += 8
            while bits >= 5 {
                chars.append(alphabet[Int(buffer >> UInt32(bits - 5) & 31)])
                bits -= 5
            }
        }
        precondition(bits == 0 && chars.count == characters)
        var out = [UInt8]()
        for (i, c) in chars.enumerated() {
            if i > 0 && i % 4 == 0 { out.append(UInt8(ascii: "-")) }
            out.append(c)
        }
        wipe(&chars)
        return String(decoding: out, as: UTF8.self)
    }

    /// Spaces and hyphens are ignored, ASCII letters uppercased (no other case
    /// mapping); the rest must be exactly 56 base32 characters and the
    /// checksum must match.
    static func decode(_ input: String) throws -> SymmetricKey {
        var chars = [UInt8]()
        defer { wipe(&chars) }
        for scalar in input.unicodeScalars {
            let v = scalar.value
            if v == 0x20 || v == 0x2D { continue }
            guard v < 0x80 else { throw ValvError.malformed("recovery key contains a non-ASCII character") }
            var c = UInt8(v)
            if c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z") { c -= 32 }
            chars.append(c)
        }
        guard chars.count == characters else {
            throw ValvError.malformed("recovery key must have \(characters) characters")
        }
        var raw = [UInt8]()
        defer { wipe(&raw) }
        var buffer: UInt32 = 0
        var bits = 0
        for c in chars {
            let d: UInt32
            switch c {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"): d = UInt32(c - UInt8(ascii: "A"))
            case UInt8(ascii: "2")...UInt8(ascii: "7"): d = UInt32(c - UInt8(ascii: "2")) + 26
            default: throw ValvError.malformed("recovery key contains a character outside A-Z, 2-7")
            }
            buffer = (buffer << 5 | d) & 0xFFFF
            bits += 5
            if bits >= 8 {
                raw.append(UInt8(truncatingIfNeeded: buffer >> UInt32(bits - 8)))
                bits -= 8
            }
        }
        precondition(raw.count == 35 && bits == 0)
        var vkRaw = raw.copy(from: 0, count: 32)
        let vk = takeKey(&vkRaw)
        guard constantTimeEqual(checksum(vk), raw.copy(from: 32, count: 3)) else {
            throw ValvError.recoveryTypo
        }
        return vk
    }
}

/// A file offered to the recovery checks: its path inside the vault (the
/// expected file_id comes from it) and a way to open it.
public struct RecoveryCandidate {
    public let path: String
    public let open: () throws -> ValvInput

    public init(path: String, open: @escaping () throws -> ValvInput) {
        self.path = path
        self.open = open
    }
}

/// The four cases of SPEC 4.5 step 2.
public enum RecoveryVerification: Equatable, Sendable {
    /// Case 1. `unwrapping` of `readable` readable objects unwrap; if they
    /// differ, tell the user "N of M objects do not unwrap with this key".
    case verified(unwrapping: Int, readable: Int)
    /// Case 2: no object unwraps, but an inbox file authenticates.
    case verifiedByInbox
    /// Case 3: refuse unless the user overrides (`--unverified-key`).
    case cannotBeVerified(readable: Int)
    /// Case 4: no objects and no inbox files; only the checksum vouches for the key.
    case nothingToCheck
}

extension Vault {
    /// The recovery key for this vault's VK, grouped for display.
    public var recoveryKey: String {
        RecoveryKey.encode(vk)
    }

    /// Decodes a recovery key (checksum included) into a vault. No Argon2.
    public convenience init(recoveryKey: String) throws {
        try self.init(vkKey: RecoveryKey.decode(recoveryKey))
    }

    /// Recovery-key unlock (SPEC 4.3). Succeeds only if the derived
    /// `inbox_pub` equals the one in vault.json. Otherwise, if `sampleObject`
    /// is given (the vault has at least one object), tries to unwrap its
    /// `wrapped_fk` to tell an altered vault.json from a wrong key.
    public static func unlock<D: DataProtocol>(vaultJSON: D, recoveryKey: String,
                                                sampleObject: RecoveryCandidate?) throws -> Vault {
        let config = try VaultConfig.parse(vaultJSON)
        let vault = try Vault(recoveryKey: recoveryKey)
        if constantTimeEqual(vault.inboxPublicKey, config.inboxPublicKey) {
            return vault
        }
        if let sampleObject, vault.objectUnwraps(sampleObject) == true {
            throw ValvError.vaultJSONAltered
        }
        throw ValvError.wrongRecoveryKeyOrAlteredVaultJSON
    }

    /// SPEC 4.5 step 2: checks a recovered key against the vault's files.
    /// No failed check counts against the key on its own.
    public func verifyRecoveredKey<O: Sequence, I: Sequence>(objects: O, inboxFiles: I) -> RecoveryVerification
    where O.Element == RecoveryCandidate, I.Element == RecoveryCandidate {
        var readable = 0
        var unwrapping = 0
        var sawObject = false
        for candidate in objects {
            sawObject = true
            switch objectUnwraps(candidate) {
            case .none: continue  // not readable
            case .some(let ok):
                readable += 1
                if ok { unwrapping += 1 }
            }
        }
        if unwrapping > 0 {
            return .verified(unwrapping: unwrapping, readable: readable)
        }
        var sawInbox = false
        for candidate in inboxFiles {
            sawInbox = true
            if inboxAuthenticates(candidate) { return .verifiedByInbox }
        }
        if !sawObject && !sawInbox { return .nothingToCheck }
        return .cannotBeVerified(readable: readable)
    }

    /// nil if the object is not readable (path, header, meta_len, structural
    /// check); otherwise whether its `wrapped_fk` unwraps with K_wrap.
    func objectUnwraps(_ c: RecoveryCandidate) -> Bool? {
        guard let expected = try? FileID(objectPath: c.path),
              let input = try? c.open(),
              let header = try? FileHeader.read(input, kind: .object, expected: expected) else {
            return nil
        }
        return (try? unwrapFK(header)) != nil
    }
}
