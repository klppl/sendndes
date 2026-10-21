import Foundation
import CryptoKit
import NdesCore

/// The two lines `ndes server-config` prints and the ndesd admin GUI asks the owner to paste.
public struct ServerKeys: Equatable, Sendable {
    public let inboxPub: String
    public let kAuth: String

    public init?(inboxPub: String, kAuth: String) {
        guard let p = Data(base64Encoded: inboxPub), p.count == 32, p.base64EncodedString() == inboxPub,
              let k = Data(base64Encoded: kAuth), k.count == 32, k.base64EncodedString() == kAuth else { return nil }
        self.inboxPub = inboxPub
        self.kAuth = kAuth
    }

    /// Parses the helper's stdout lines ("inbox_pub: <b64>", "k_auth: <b64>"); each value must be 32 bytes of base64.
    public init?(lines: [String]) {
        guard lines.count == 2,
              let p = Self.value(lines[0], prefix: "inbox_pub: "),
              let k = Self.value(lines[1], prefix: "k_auth: ") else { return nil }
        inboxPub = p; kAuth = k
    }

    /// Parses pasted text that contains "inbox_pub: <b64>" and "k_auth: <b64>".
    public init?(text: String) {
        let lines = text.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        self.init(lines: lines)
    }

    private static func value(_ line: String, prefix: String) -> String? {
        guard line.hasPrefix(prefix) else { return nil }
        let v = String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
        guard let d = Data(base64Encoded: v), d.count == 32, d.base64EncodedString() == v else { return nil }
        return v
    }

    /// Creates an InboxSealer configured with these keys.
    public func makeSealer() throws -> InboxSealer {
        try InboxSealer(inboxPubBase64: inboxPub, kAuthBase64: kAuth)
    }

    /// Exactly what `ndes server-config` writes to stdout.
    public var clipboardText: String { "inbox_pub: \(inboxPub)\nk_auth: \(kAuth)\n" }

    /// Non-secret check value shown by the ndesd GUI: first 4 bytes of SHA-256(inbox_pub), uppercase hex, XXXX-XXXX.
    public var fingerprint: String {
        let raw = Data(base64Encoded: inboxPub) ?? Data()
        let h = SHA256.hash(data: raw).prefix(4).map { String(format: "%02X", $0) }.joined()
        return String(h.prefix(4)) + "-" + String(h.suffix(4))
    }
}
