import CryptoKit
import Foundation

/// What a pairing QR code holds (`ndes sender-config`): the server address, the two server keys that let the
/// phone seal for the vault, and a token that may only upload.
public struct SenderPayload: Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public var description: String { "SenderPayload(\(server.host), \(label), check \(fingerprint))" }
    public var debugDescription: String { description }
    public static let prefix = "ndes-sender1:"

    public let server: ServerURL
    public let inboxPub: [UInt8]
    public let kAuth: [UInt8]
    public let token: String
    public let label: String
    /// First 8 hex characters of SHA-256(inbox_pub), shown on both screens so the owner can compare them.
    public let fingerprint: String

    public enum Failure: Error, Equatable, Sendable {
        case notAPairingCode, tooLarge, badEncoding, badJSON, unsupportedVersion
        case badField(String)
        case fingerprintMismatch
        case badURL(ServerURL.Failure)
    }

    private static let keys: Set<String> = ["v", "url", "inbox_pub", "k_auth", "token", "label", "fp"]

    public static func parse(_ text: String) throws -> SenderPayload {
        try parse(text, urlParser: ServerURL.parse)
    }

    package static func parseForTests(_ text: String) throws -> SenderPayload {
        try parse(text, urlParser: ServerURL.parseForTests)
    }

    private static func parse(_ text: String, urlParser: (String) throws -> ServerURL) throws -> SenderPayload {
        guard text.hasPrefix(prefix) else { throw Failure.notAPairingCode }
        guard text.utf8.count <= SenderLimits.maxPayloadCharacters else { throw Failure.tooLarge }
        let body = String(text.dropFirst(prefix.count))
        guard let raw = base64URLDecode(body) else { throw Failure.badEncoding }
        let obj: [String: StrictJSON.Value]
        do { obj = try StrictJSON.parseFlatObject(raw) } catch { throw Failure.badJSON }
        guard Set(obj.keys) == keys else { throw Failure.badJSON }
        guard case .int(1)? = obj["v"] else { throw Failure.unsupportedVersion }
        func str(_ k: String) throws -> String {
            guard case .string(let s)? = obj[k] else { throw Failure.badField(k) }
            return s
        }
        let server: ServerURL
        do { server = try urlParser(try str("url")) } catch let f as ServerURL.Failure { throw Failure.badURL(f) }
        let pub = try key32(try str("inbox_pub"), "inbox_pub")
        let auth = try key32(try str("k_auth"), "k_auth")
        let token = try str("token")
        // 32 random bytes in base64url is 43 characters; longer is fine, shorter is not.
        guard token.utf8.count >= 43, token.utf8.count <= 512,
              token.utf8.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F }) else {
            throw Failure.badField("token")
        }
        let label = try str("label")
        guard (1...32).contains(label.utf8.count), label.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { throw Failure.badField("label") }
        let fp = try str("fp")
        guard fp.utf8.count == 8, fp.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }) else { throw Failure.badField("fp") }
        let digest = SHA256.hash(data: Data(pub))
        let want = digest.prefix(4).map { String(format: "%02x", $0) }.joined()
        guard fp == want else { throw Failure.fingerprintMismatch }
        return SenderPayload(server: server, inboxPub: pub, kAuth: auth, token: token, label: label, fingerprint: fp)
    }

    private static func key32(_ s: String, _ name: String) throws -> [UInt8] {
        guard s.utf8.count == 44, let d = Data(base64Encoded: s), d.count == 32, d.base64EncodedString() == s,
              d.contains(where: { $0 != 0 }) else { throw Failure.badField(name) }
        return [UInt8](d)
    }

    /// Unpadded base64url only; any other character, padding or length that cannot be valid is rejected.
    static func base64URLDecode(_ s: String) -> [UInt8]? {
        guard !s.isEmpty, s.utf8.count % 4 != 1,
              s.utf8.allSatisfy({ ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F }) else { return nil }
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        t += String(repeating: "=", count: (4 - t.count % 4) % 4)
        guard let d = Data(base64Encoded: t) else { return nil }
        return [UInt8](d)
    }
}
