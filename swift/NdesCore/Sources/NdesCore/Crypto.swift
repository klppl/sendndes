import Clibsodium
import CryptoKit
import Foundation

// The primitives of SPEC section 2, and nothing else.

enum Label {
    static let wrap = Array("ndes/v1/wrap".utf8)
    static let inboxX25519 = Array("ndes/v1/inbox-x25519".utf8)
    static let inboxAuth = Array("ndes/v1/inbox-auth".utf8)
    static let content = Array("ndes/v1/content".utf8)
    static let meta = Array("ndes/v1/meta".utf8)
    static let inboxFK = Array("ndes/v1/inbox-fk".utf8)
    static let recoveryChecksum = Array("ndes/v1/recovery-checksum".utf8)
    static let configAAD = Array("ndes-config-v1".utf8)
}

enum KDFParams {
    static let alg = "argon2id"
    static let t: UInt32 = 3
    static let mKiB: UInt32 = 65536
    static let p: UInt32 = 1
    static let saltBytes = 16
}

/// HKDF-SHA256 with L = 32 (SPEC 3). `salt` is empty for every derivation
/// from VK or FK; CryptoKit treats an empty salt as RFC 5869 does (HashLen
/// zero bytes), which the K_wrap, K_auth and K_content vectors confirm.
func hkdf32(_ ikm: SymmetricKey, salt: [UInt8] = [], info: [UInt8]) -> SymmetricKey {
    HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: info, outputByteCount: 32)
}

/// Copies a key's bytes out. Only for places where the format needs the raw
/// bytes as data (wrapping, HKDF input concatenation); callers wipe the copy.
func keyBytes(_ key: SymmetricKey) -> [UInt8] {
    key.withUnsafeBytes { [UInt8]($0) }
}

/// Builds a SymmetricKey from bytes and wipes the source array.
func takeKey(_ raw: inout [UInt8]) -> SymmetricKey {
    defer { wipe(&raw) }
    return SymmetricKey(data: raw)
}

// MARK: - ChaCha20-Poly1305

enum AEAD {
    static let nonceBytes = 12
    static let tagBytes = 16

    /// Returns ciphertext | tag (no nonce: the caller places the nonce where the
    /// format puts it).
    static func seal<P: DataProtocol, A: DataProtocol>(
        _ plaintext: P, key: SymmetricKey, nonce: [UInt8], aad: A
    ) -> [UInt8] {
        precondition(nonce.count == nonceBytes)
        do {
            let box = try ChaChaPoly.seal(plaintext, using: key,
                                          nonce: ChaChaPoly.Nonce(data: nonce),
                                          authenticating: aad)
            var out = [UInt8]()
            out.reserveCapacity(box.ciphertext.count + tagBytes)
            out.append(contentsOf: box.ciphertext)
            out.append(contentsOf: box.tag)
            return out
        } catch {
            // Only a wrong nonce length can make sealing fail.
            preconditionFailure("ChaChaPoly.seal failed")
        }
    }

    /// Opens ciphertext | tag. Built with SealedBox(nonce:ciphertext:tag:),
    /// never the `combined` initializer, so the nonce comes from where the
    /// format stores it.
    static func open<A: DataProtocol>(
        _ ciphertextAndTag: [UInt8], key: SymmetricKey, nonce: [UInt8], aad: A, what: String
    ) throws -> Data {
        guard nonce.count == nonceBytes, ciphertextAndTag.count >= tagBytes else {
            throw NdesError.malformed("\(what): too short")
        }
        let ctLen = ciphertextAndTag.count - tagBytes
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: nonce),
                ciphertext: ciphertextAndTag[0..<ctLen],
                tag: ciphertextAndTag[ctLen...])
            return try ChaChaPoly.open(box, using: key, authenticating: aad)
        } catch {
            throw NdesError.auth(what)
        }
    }
}

// MARK: - Argon2id (libsodium, used for nothing else)

enum Argon2id {
    /// KEK = Argon2id(passphrase, salt, t=3, m=65536 KiB, p=1) -> 32 bytes.
    /// libsodium's crypto_pwhash with ALG_ARGON2ID13 always uses one lane (p=1).
    static func deriveKEK(passphraseUTF8 pw: [UInt8], salt: [UInt8]) throws -> SymmetricKey {
        precondition(salt.count == KDFParams.saltBytes)
        guard sodium_init() >= 0 else { throw NdesError.io("libsodium failed to initialize") }
        let opslimit = UInt64(KDFParams.t)
        let memlimit = Int(KDFParams.mKiB) * 1024  // 64 MiB in bytes
        var out = [UInt8](repeating: 0, count: 32)
        var empty: CChar = 0  // crypto_pwhash wants a non-null pointer even for length 0
        let rc: Int32 = out.withUnsafeMutableBufferPointer { o in
            salt.withUnsafeBufferPointer { s in
                pw.withUnsafeBytes { p in
                    let pwPtr = p.baseAddress.map { $0.assumingMemoryBound(to: CChar.self) }
                    return withUnsafeMutablePointer(to: &empty) { e in
                        crypto_pwhash(o.baseAddress!, UInt64(o.count),
                                      pwPtr ?? UnsafePointer(e), UInt64(p.count),
                                      s.baseAddress!, opslimit, memlimit,
                                      crypto_pwhash_alg_argon2id13())
                    }
                }
            }
        }
        guard rc == 0 else {
            wipe(&out)
            throw NdesError.io("Argon2id failed (out of memory?)")
        }
        return takeKey(&out)
    }
}

// MARK: - X25519

enum X25519 {
    /// RFC 7748 clamping, applied to the derived inbox private key (SPEC 3).
    static func clamp(_ b: inout [UInt8]) {
        b[0] &= 248
        b[31] &= 127
        b[31] |= 64
    }

    static func privateKey(_ raw: inout [UInt8]) throws -> Curve25519.KeyAgreement.PrivateKey {
        defer { wipe(&raw) }
        do {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
        } catch {
            throw NdesError.malformed("X25519 private key")
        }
    }

    /// X25519(priv, pub). Rejects an all-zero result explicitly instead of
    /// relying on CryptoKit to do it.
    static func sharedSecret(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pub: [UInt8]) throws -> [UInt8] {
        let peer: Curve25519.KeyAgreement.PublicKey
        do {
            peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub)
        } catch {
            throw NdesError.malformed("X25519 public key")
        }
        let shared: SharedSecret
        do {
            shared = try priv.sharedSecretFromKeyAgreement(with: peer)
        } catch {
            // CryptoKit may itself refuse a low-order point; that is the same
            // all-zero case.
            throw NdesError.malformed("X25519 result is all zero")
        }
        var out = shared.withUnsafeBytes { [UInt8]($0) }
        let zero = [UInt8](repeating: 0, count: out.count)
        if out.count != 32 || constantTimeEqual(out, zero) {
            wipe(&out)
            throw NdesError.malformed("X25519 result is all zero")
        }
        return out
    }
}

// MARK: - Key schedule shared by objects and inbox files

/// K_content and K_meta from FK (SPEC 3).
struct FileKeys {
    let fk: SymmetricKey
    let content: SymmetricKey
    let meta: SymmetricKey

    init(fk: SymmetricKey) {
        self.fk = fk
        self.content = hkdf32(fk, info: Label.content)
        self.meta = hkdf32(fk, info: Label.meta)
    }
}
