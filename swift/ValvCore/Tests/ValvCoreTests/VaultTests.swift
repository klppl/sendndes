import CryptoKit
import Foundation
import Testing
@testable import ValvCore

@Suite struct VaultTests {
    @Test func vaultJSONParsesAndReserializesIdentically() throws {
        let cfg = try VaultConfig.parse(vaultJSONBytes)
        #expect(cfg.serialized() == vaultJSONBytes)
        #expect([UInt8](vaultJSONBytes) == hex(vaultVector["vault_json_hex"]))
        #expect(cfg.salt == hex(vaultVector["salt"]))
        #expect(cfg.wrappedVK == hex(vaultVector["wrapped_vk"]))
        #expect(cfg.inboxPublicKey == hex(vaultVector["inbox_pub"]))
        #expect(cfg.configAAD == hex(vaultVector["config_aad"]))
        #expect(cfg.configAAD.count == 83)
    }

    @Test func subkeysMatchVectors() throws {
        let v = try Vault(vk: hex(vaultVector["vk"]))
        #expect(keyBytes(v.kWrap) == hex(vaultVector["k_wrap"]))
        #expect(keyBytes(v.kAuth) == hex(vaultVector["k_auth"]))
        #expect(keyBytes(hkdf32(v.vk, info: Label.inboxX25519)) == hex(vaultVector["inbox_priv_unclamped"]))
        #expect([UInt8](v.inboxPrivateKey.rawRepresentation) == hex(vaultVector["inbox_priv"]))
        #expect(v.inboxPublicKey == hex(vaultVector["inbox_pub"]))
    }

    /// CryptoKit's HKDF with an empty salt must equal RFC 5869's 32 zero bytes.
    @Test func emptyHKDFSaltEqualsZeroSalt() {
        let ikm = SymmetricKey(data: hex(vaultVector["vk"]))
        let a = keyBytes(hkdf32(ikm, salt: [], info: Label.wrap))
        let b = keyBytes(hkdf32(ikm, salt: [UInt8](repeating: 0, count: 32), info: Label.wrap))
        #expect(a == b)
        #expect(a == hex(vaultVector["k_wrap"]))
    }

    @Test func passphraseUnlock() throws {
        let v = try Vault.unlock(vaultJSON: vaultJSONBytes, passphrase: passphrase)
        #expect(v.exportVK() == hex(vaultVector["vk"]))
        let v2 = try Vault.unlock(vaultJSON: vaultJSONBytes, passphraseUTF8: hex(vaultVector["passphrase_hex"]))
        #expect(v2.exportVK() == hex(vaultVector["vk"]))
    }

    @Test func kekMatchesVector() throws {
        let kek = try Argon2id.deriveKEK(passphraseUTF8: Passphrase.normalizedUTF8(passphrase),
                                         salt: hex(vaultVector["salt"]))
        #expect(keyBytes(kek) == hex(vaultVector["kek"]))
    }

    @Test func passphraseNormalization() throws {
        let pn = vaultVector["passphrase_normalization"] as! JSONObject
        let nfd = hex(pn["nfd_hex"]), nfc = hex(pn["nfc_hex"])
        #expect(nfd != nfc)
        #expect(try Passphrase.normalizedUTF8(bytes: nfd) == nfc)
        #expect(Passphrase.normalizedUTF8(String(decoding: nfd, as: UTF8.self)) == nfc)
        let salt = hex(vaultVector["salt"])
        let k1 = try Argon2id.deriveKEK(passphraseUTF8: Passphrase.normalizedUTF8(bytes: nfd), salt: salt)
        let k2 = try Argon2id.deriveKEK(passphraseUTF8: Passphrase.normalizedUTF8(bytes: nfc), salt: salt)
        #expect(keyBytes(k1) == hex(pn["kek"]))
        #expect(keyBytes(k2) == hex(pn["kek"]))
    }

    @Test func invalidUTF8PassphraseRejected() {
        #expect(errorClass { _ = try Vault.unlock(vaultJSON: vaultJSONBytes, passphraseUTF8: [0x61, 0xFF]) } == "malformed")
        // A lone surrogate encoded in UTF-8 and an overlong "/" are invalid too.
        #expect(!isValidUTF8([0xED, 0xA0, 0x80]))
        #expect(!isValidUTF8([0xC0, 0xAF]))
        #expect(!isValidUTF8([0xF4, 0x90, 0x80, 0x80]))
        #expect(isValidUTF8(Array("Räksmörgås 한국 😀".utf8)))
    }

    @Test func vkInitializerRunsNoArgon2AndChecksInboxPub() throws {
        _ = try Vault(vk: hex(vaultVector["vk"]), vaultJSON: vaultJSONBytes)
        var other = hex(vaultVector["vk"])
        other[0] ^= 1
        #expect(errorClass { _ = try Vault(vk: other, vaultJSON: vaultJSONBytes) } == "inbox_key_mismatch")
        #expect(errorClass { _ = try Vault(vk: [UInt8](repeating: 1, count: 31)) } == "malformed")
    }

    @Test func createAndRewrap() throws {
        let created = try Vault.create(passphrase: "a long enough passphrase")
        let v = try Vault.unlock(vaultJSON: created.vaultJSON, passphrase: "a long enough passphrase")
        #expect(v.exportVK() == created.vault.exportVK())
        #expect(try Vault(recoveryKey: created.recoveryKey).exportVK() == v.exportVK())

        let json2 = try v.makeVaultJSON(passphrase: "another long passphrase")
        let c1 = try VaultConfig.parse(created.vaultJSON), c2 = try VaultConfig.parse(json2)
        #expect(c1.salt != c2.salt)
        #expect(c1.wrappedVK.prefix(12) != c2.wrappedVK.prefix(12))
        #expect(c1.inboxPublicKey == c2.inboxPublicKey)
        #expect(try Vault.unlock(vaultJSON: json2, passphrase: "another long passphrase").exportVK() == v.exportVK())
        #expect(errorClass { _ = try Vault.unlock(vaultJSON: json2, passphrase: "a long enough passphrase") } == "wrong_passphrase")
    }

    @Test func weakPassphraseRefusedUnlessOverridden() throws {
        #expect(errorClass { _ = try Vault.create(passphrase: "short") } == "weak_passphrase")
        // 11 code points after NFC, although the NFD input has more.
        let elevenNFD = "a\u{0308}" + String(repeating: "b", count: 10)
        #expect(errorClass { _ = try Vault.create(passphrase: elevenNFD) } == "weak_passphrase")
        _ = try Vault.create(passphrase: "short", allowWeakPassphrase: true)
    }

    @Test func vaultJSONSizeCap() {
        var big = [UInt8](vaultJSONBytes)
        big.insert(contentsOf: [UInt8](repeating: 0x20, count: 4096), at: 2)
        #expect(errorClass { _ = try VaultConfig.parse(big) } == "malformed")
    }

    @Test func nonCanonicalBase64Rejected() {
        // "AB==" decodes to one byte but has nonzero unused bits.
        #expect(Base64.decodeCanonical(Array("AB==".utf8)) == nil)
        #expect(Base64.decodeCanonical(Array("AA==".utf8)) == [0])
        #expect(Base64.decodeCanonical(Array("AA=A".utf8)) == nil)
        #expect(Base64.decodeCanonical(Array("AA".utf8)) == nil)
        #expect(Base64.decodeCanonical(Array("A A=".utf8)) == nil)
        let s = String(decoding: vaultJSONBytes, as: UTF8.self)
        let pub = Base64.encode(hex(vaultVector["inbox_pub"]))  // ends in "="
        var chars = Array(pub)
        let last = chars[chars.count - 2]
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        chars[chars.count - 2] = alphabet[alphabet.firstIndex(of: last)! + 1]  // sets an unused bit
        let tampered = s.replacingOccurrences(of: pub, with: String(chars))
        #expect(errorClass { _ = try VaultConfig.parse(Data(tampered.utf8)) } == "malformed")
    }

    #if VALV_TESTVECTORS
    @Test func createReproducesVaultJSONExactly() throws {
        let (created, source) = try TestHooks.withFixedRandom([
            .vk: [hex(vaultVector["vk"])],
            .kdfSalt: [hex(vaultVector["salt"])],
            .vkWrapNonce: [hex(vaultVector["wrap_nonce"])],
        ]) { try Vault.create(passphrase: passphrase) }
        #expect(source.isExhausted)
        #expect(created.vaultJSON == vaultJSONBytes)
        #expect(created.recoveryKey == vaultVector["recovery_key"] as! String)
    }
    #endif
}
