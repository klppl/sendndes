import Foundation

/// H1: plain http is only acceptable inside the Tailscale tunnel. The URL policy trusts the destination
/// address, which says nothing about the path: with Tailscale off (or after sleep) packets to 100.x leave
/// through the default gateway. Before talking plain http to a 100.64.0.0/10 address, ask the OS which
/// interface it would use for that destination (a connected UDP socket, nothing is sent) and require a
/// Tailscale one (`utun*`, `tailscale*`, or a name the user listed). Fails closed. Loopback and https are
/// not checked.
public final class RouteGuard {
    /// Local interface the OS would use to reach an IPv4 address, nil if it cannot be determined.
    public var lookup: (String) -> String?
    /// Extra interface names accepted as Tailscale (UserDefaults key `tailscaleInterfaces`, comma separated).
    public var extraInterfaces: () -> [String]

    public static let defaultsKey = "tailscaleInterfaces"

    public init(lookup: @escaping (String) -> String? = RouteGuard.systemLookup,
                extraInterfaces: @escaping () -> [String] = { [] }) {
        self.lookup = lookup
        self.extraInterfaces = extraInterfaces
    }

    /// Interface names from a user-typed list; anything that is not a plain interface name is dropped.
    public static func parseInterfaceList(_ text: String) -> [String] {
        text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter {
            !$0.isEmpty && $0.utf8.count <= 15 && $0.utf8.allSatisfy {
                ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x41 && $0 <= 0x5a) || $0 == 0x2e || $0 == 0x5f || $0 == 0x2d
            }
        }
    }

    /// True when no check applies or the route goes through a Tailscale interface.
    public func allows(_ server: ServerURL) -> Bool {
        guard server.canonical.hasPrefix("http://"), Self.isTailscaleAddress(server.host) else { return true }
        guard let name = lookup(server.host) else { return false }
        return Self.isTailscaleInterface(name, extra: extraInterfaces())
    }

    static func isTailscaleInterface(_ name: String, extra: [String]) -> Bool {
        name.hasPrefix("utun") || name.hasPrefix("tailscale") || extra.contains(name)
    }

    static func isTailscaleAddress(_ host: String) -> Bool {
        var v4 = in_addr()
        guard inet_pton(AF_INET, host, &v4) == 1 else { return false }
        return (UInt32(bigEndian: v4.s_addr) & 0xFFC0_0000) == 0x6440_0000
    }

    public static let routeMessage = "The route to this address does not go through Tailscale; is Tailscale connected?"

    public static func systemLookup(_ host: String) -> String? {
        var dst = sockaddr_in()
        dst.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        dst.sin_family = sa_family_t(AF_INET)
        dst.sin_port = UInt16(9).bigEndian
        guard inet_pton(AF_INET, host, &dst.sin_addr) == 1 else { return nil }
        let s = socket(AF_INET, SOCK_DGRAM, 0)
        guard s >= 0 else { return nil }
        defer { close(s) }
        let rc = withUnsafePointer(to: &dst) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0 else { return nil }
        var local = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let rc2 = withUnsafeMutablePointer(to: &local) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) }
        }
        guard rc2 == 0, local.sin_addr.s_addr != 0 else { return nil }
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return nil }
        defer { freeifaddrs(list) }
        var p: UnsafeMutablePointer<ifaddrs>? = first
        while let cur = p {
            if let a = cur.pointee.ifa_addr, a.pointee.sa_family == sa_family_t(AF_INET) {
                let same = a.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr == local.sin_addr.s_addr }
                if same { return String(cString: cur.pointee.ifa_name) }
            }
            p = cur.pointee.ifa_next
        }
        return nil
    }
}
