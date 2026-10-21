#if NDES_TESTVECTORS
// Compiled only with `--traits NDES_TESTVECTORS`, for interop checks against
// the Go CLI. A normal build has none of this; scripts/check-release-symbols.sh
// verifies that.

public enum TestExports {
    /// The same lines as `ndes server-config`: `inbox_pub: <b64>` and
    /// `k_auth: <b64>`, then `recovery_key: <grouped>` and `vk: <hex>`.
    public static func keyReport(_ vault: Vault) -> String {
        var kAuth = keyBytes(vault.kAuth)
        defer { wipe(&kAuth) }
        return "inbox_pub: \(Base64.encode(vault.inboxPublicKey))\n"
            + "k_auth: \(Base64.encode(kAuth))\n"
            + "recovery_key: \(vault.recoveryKey)\n"
            + "vk: \(hexEncode(keyBytes(vault.vk)))\n"
    }
}
#endif
