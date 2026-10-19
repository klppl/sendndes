import Foundation

/// D-A7: https, or plain http only to loopback or a Tailscale address
/// (100.64.0.0/10), written as an IP literal. Produces the one canonical string
/// used both for URLSession and for `valv pull --server=`.
public struct ServerURL: Equatable {
    public let canonical: String
    public let host: String
}

public enum URLPolicyError: Error, Equatable {
    case invalid
    case plainHTTPNotAllowed

    public var message: String {
        switch self {
        case .invalid:
            return "That is not a valid server address. Use https://host or http://100.x.y.z:port."
        case .plainHTTPNotAllowed:
            return "Plain http is only allowed to 127.x/::1 or a Tailscale 100.64–100.127 address; use https:// for anything else."
        }
    }
}

public enum URLPolicy {
    public static func parse(_ raw: String) throws -> ServerURL {
        // Printable ASCII only, no percent-escapes or backslashes: nothing for the
        // two URL parsers (Foundation here, Go in the helper) to read differently.
        guard !raw.isEmpty, raw.utf8.count <= 300,
              raw.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f && $0 != 0x25 && $0 != 0x5c })
        else { throw URLPolicyError.invalid }
        guard let c = URLComponents(string: raw),
              c.user == nil, c.password == nil, c.query == nil, c.fragment == nil,
              c.path.isEmpty || c.path == "/",
              let scheme = c.scheme?.lowercased(), let rawHost = c.host, !rawHost.isEmpty
        else { throw URLPolicyError.invalid }
        if let p = c.port, !(1...65535).contains(p) { throw URLPolicyError.invalid }
        var host = rawHost.lowercased()
        if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
        var hostText = host
        switch scheme {
        case "https":
            let labels = host.split(separator: ".", omittingEmptySubsequences: false)
            guard host.utf8.count <= 253,
                  host.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d || $0 == 0x2e }),
                  !labels.contains(where: { $0.isEmpty })
            else { throw URLPolicyError.invalid }
        case "http":
            guard isTrustedLiteral(host) else {
                // A name or any other address: say so, but not for garbage.
                throw URLPolicyError.plainHTTPNotAllowed
            }
            if host.contains(":") { hostText = "[\(host)]" }
        default:
            throw URLPolicyError.invalid
        }
        let port = c.port.map { ":\($0)" } ?? ""
        return ServerURL(canonical: "\(scheme)://\(hostText)\(port)", host: host)
    }

    static func isTrustedLiteral(_ host: String) -> Bool {
        var v4 = in_addr()
        if inet_pton(AF_INET, host, &v4) == 1 {
            let a = UInt32(bigEndian: v4.s_addr)
            let loopback = (a >> 24) == 127
            let tailscale = (a & 0xFFC0_0000) == 0x6440_0000 // 100.64.0.0/10
            return loopback || tailscale
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, host, &v6) == 1 {
            let bytes = withUnsafeBytes(of: v6) { Array($0) }
            return bytes == [UInt8](repeating: 0, count: 15) + [1]
        }
        return false
    }
}
