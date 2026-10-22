import Foundation

/// The server address of a paired phone: `https://host[:port]`, nothing else.
public struct ServerURL: Equatable, Sendable, CustomStringConvertible {
    public let canonical: String
    public let host: String
    public var description: String { canonical }
    public var url: URL { URL(string: canonical)! }

    public enum Failure: Error, Equatable, Sendable {
        case notHTTPS, malformed, hasUserInfo, hasPathQueryOrFragment, ipLiteral, badHost
    }

    /// Production rules: https only (no ATS exceptions anywhere), a real DNS name (no IP literal, no trailing
    /// dot, no single-label name), no userinfo, path, query or fragment. IDN hosts must arrive in punycode.
    public static func parse(_ raw: String) throws -> ServerURL {
        try parse(raw, allowInsecureLoopback: false)
    }

    /// Tests only (`package` access: the app cannot call this): also allows http://127.0.0.1:port for a loopback ndesd.
    package static func parseForTests(_ raw: String) throws -> ServerURL {
        try parse(raw, allowInsecureLoopback: true)
    }

    private static func parse(_ raw: String, allowInsecureLoopback: Bool) throws -> ServerURL {
        guard raw.utf8.count <= 300, !raw.contains(where: { $0.isWhitespace || $0.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F } }),
              !raw.contains("\\") else { throw Failure.malformed }
        guard let schemeEnd = raw.range(of: "://") else {
            throw raw.lowercased().hasPrefix("http") ? Failure.malformed : Failure.notHTTPS
        }
        let scheme = raw[..<schemeEnd.lowerBound].lowercased()
        var rest = raw[schemeEnd.upperBound...]
        guard scheme == "https" || (allowInsecureLoopback && scheme == "http") else { throw Failure.notHTTPS }
        if rest.contains("@") { throw Failure.hasUserInfo }
        if let slash = rest.firstIndex(of: "/") {
            let tail = rest[slash...]
            guard tail == "/" else { throw Failure.hasPathQueryOrFragment }
            rest = rest[..<slash]
        }
        if rest.contains("?") || rest.contains("#") { throw Failure.hasPathQueryOrFragment }
        guard !rest.isEmpty else { throw Failure.malformed }
        if rest.hasPrefix("[") { throw Failure.ipLiteral }

        var hostPart = String(rest)
        var port: Int?
        if let colon = hostPart.lastIndex(of: ":") {
            let p = hostPart[hostPart.index(after: colon)...]
            guard !p.isEmpty, p.count <= 5, p.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Int(p), (1...65535).contains(n),
                  !(p.count > 1 && p.hasPrefix("0")) else { throw Failure.malformed }
            port = n
            hostPart = String(hostPart[..<colon])
        }
        let host = hostPart.lowercased()
        if scheme == "http" {
            guard host == "127.0.0.1" else { throw Failure.notHTTPS }
            return ServerURL(canonical: "http://" + host + (port.map { ":\($0)" } ?? ""), host: host)
        }
        try validateDNSName(host)
        return ServerURL(canonical: "https://" + host + (port.map { ":\($0)" } ?? ""), host: host)
    }

    private static func validateDNSName(_ host: String) throws {
        guard !host.isEmpty, host.utf8.count <= 253, host.utf8.allSatisfy({ $0 < 0x80 }) else { throw Failure.badHost }
        if host.hasSuffix(".") || host.hasPrefix(".") { throw Failure.badHost }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { throw Failure.badHost }
        // An all-numeric last label is an IPv4 literal (or a spelling of one), never a public DNS name.
        // Numeric or hex ("0x7f") labels are spellings of an IP address, never a DNS name.
        func numericLabel(_ l: Substring) -> Bool {
            l.allSatisfy { $0.isNumber } || (l.lowercased().hasPrefix("0x") && l.dropFirst(2).allSatisfy { $0.isHexDigit })
        }
        if labels.contains(where: numericLabel) && (labels.last.map(numericLabel) ?? false) { throw Failure.ipLiteral }
        if let last = labels.last, numericLabel(last) { throw Failure.ipLiteral }
        if labels.allSatisfy({ $0.allSatisfy { $0.isNumber } }) { throw Failure.ipLiteral }
        for l in labels {
            guard (1...63).contains(l.utf8.count), l.first != "-", l.last != "-",
                  l.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D }) else { throw Failure.badHost }
        }
    }
}
