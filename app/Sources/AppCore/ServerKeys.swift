import Foundation
import CryptoKit

/// The two lines `valv server-config` prints and the valvd admin GUI asks the owner to paste.
public struct ServerKeys: Equatable, Sendable {
    public let inboxPub: String
    public let kAuth: String

    /// Parses the helper's stdout lines ("inbox_pub: <b64>", "k_auth: <b64>"); each value must be 32 bytes of base64.
    public init?(lines: [String]) {
        guard lines.count == 2,
              let p = Self.value(lines[0], prefix: "inbox_pub: "),
              let k = Self.value(lines[1], prefix: "k_auth: ") else { return nil }
        inboxPub = p; kAuth = k
    }

    private static func value(_ line: String, prefix: String) -> String? {
        guard line.hasPrefix(prefix) else { return nil }
        let v = String(line.dropFirst(prefix.count))
        guard let d = Data(base64Encoded: v), d.count == 32, d.base64EncodedString() == v else { return nil }
        return v
    }

    /// Exactly what `valv server-config` writes to stdout.
    public var clipboardText: String { "inbox_pub: \(inboxPub)\nk_auth: \(kAuth)\n" }

    /// Non-secret check value shown by the valvd GUI: first 4 bytes of SHA-256(inbox_pub), uppercase hex, XXXX-XXXX.
    public var fingerprint: String {
        let raw = Data(base64Encoded: inboxPub) ?? Data()
        let h = SHA256.hash(data: raw).prefix(4).map { String(format: "%02X", $0) }.joined()
        return String(h.prefix(4)) + "-" + String(h.suffix(4))
    }
}
