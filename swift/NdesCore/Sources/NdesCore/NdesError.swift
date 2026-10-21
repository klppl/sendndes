/// Every error NdesCore throws. Messages describe structure only; they never
/// contain keys, passphrases, FKs or plaintext.
public enum NdesError: Error, Equatable, Sendable, CustomStringConvertible {
    /// Bad structure: magic, kind, meta_len, failed structural check,
    /// non-canonical vault.json, all-zero X25519 result, bad recovery-key syntax.
    case malformed(String)
    /// A version or KDF parameters v1 does not accept.
    case unsupported(String)
    /// An AEAD tag did not verify.
    case auth(String)
    /// Metadata decrypted but is not canonical or breaks a field rule (SPEC 5.2),
    /// or a writer was given metadata it must reject.
    case metadata(String)
    /// `wrapped_vk` did not open.
    case wrongPassphrase
    /// `wrapped_vk` opened but `inbox_pub` is not the one derived from VK.
    case inboxKeyMismatch
    /// A recovery key's checksum does not match.
    case recoveryTypo
    /// The path is not a valid object or inbox name, or does not match the header file_id.
    case path(String)
    /// A new passphrase is shorter than 12 code points after NFC (SPEC 3).
    case weakPassphrase
    /// Recovery-key unlock (SPEC 4.3 step 4): the key unwraps an object but
    /// `inbox_pub` does not match, so vault.json has been altered.
    case vaultJSONAltered
    /// Recovery-key unlock (SPEC 4.3 step 4): nothing confirms the key.
    case wrongRecoveryKeyOrAlteredVaultJSON
    /// Reading or writing failed.
    case io(String)

    /// The error class name used by testvectors/README.md.
    public var vectorClass: String {
        switch self {
        case .malformed: return "malformed"
        case .unsupported: return "unsupported"
        case .auth: return "auth"
        case .metadata: return "metadata"
        case .wrongPassphrase: return "wrong_passphrase"
        case .inboxKeyMismatch: return "inbox_key_mismatch"
        case .recoveryTypo: return "recovery_typo"
        case .path: return "path"
        case .weakPassphrase: return "weak_passphrase"
        case .vaultJSONAltered: return "vault_json_altered"
        case .wrongRecoveryKeyOrAlteredVaultJSON: return "wrong_recovery_key"
        case .io: return "io"
        }
    }

    public var description: String {
        switch self {
        case .malformed(let s): return "malformed: \(s)"
        case .unsupported(let s): return "unsupported: \(s)"
        case .auth(let s): return "authentication failed: \(s)"
        case .metadata(let s): return "invalid metadata: \(s)"
        case .wrongPassphrase: return "wrong passphrase or altered vault.json"
        case .inboxKeyMismatch: return "inbox_pub in vault.json does not match the key derived from VK"
        case .recoveryTypo: return "recovery key has a typo"
        case .path(let s): return "path check failed: \(s)"
        case .weakPassphrase: return "passphrase is shorter than 12 characters"
        case .vaultJSONAltered: return "vault.json has been altered"
        case .wrongRecoveryKeyOrAlteredVaultJSON: return "wrong recovery key or altered vault.json"
        case .io(let s): return "I/O error: \(s)"
        }
    }
}
