import CryptoKit
import Foundation
@testable import SenderCore

func tempDir(_ name: String = "t") -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("sendndes-\(name)-\(UUID().uuidString)")
    try! FileManager.default.createDirectory(at: u, withIntermediateDirectories: true)
    return u
}

func b64url(_ d: Data) -> String {
    d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func fingerprint(_ pub: [UInt8]) -> String {
    SHA256.hash(data: Data(pub)).prefix(4).map { String(format: "%02x", $0) }.joined()
}

struct Fixture {
    var url = "https://inbox.example.com"
    var pub: [UInt8] = (0..<32).map { UInt8($0 + 1) }
    var auth: [UInt8] = (0..<32).map { UInt8(200 - $0) }
    var token = b64url(Data((0..<32).map { UInt8($0 * 7 + 3) }))
    var label = "iphone-1"
    var version = 1
    var fp: String?
    var extra = ""
    /// A pairing code (version 2): no token inside, the phone asks the server for one.
    var pairing = false

    func json() -> String {
        let f = fp ?? fingerprint(pub)
        let tok = pairing ? "" : #""token":"\#(token)","#
        return #"{"v":\#(pairing ? 2 : version),"url":"\#(url)","inbox_pub":"\#(Data(pub).base64EncodedString())","k_auth":"\#(Data(auth).base64EncodedString())",\#(tok)"label":"\#(label)","fp":"\#(f)"\#(extra)}"#
    }
    func payload() -> String { (pairing ? SenderPayload.pairPrefix : SenderPayload.prefix) + b64url(Data(json().utf8)) }
}

func pairing(_ f: Fixture = Fixture()) throws -> Pairing {
    let p = try SenderPayload.parse(f.payload())
    return Pairing(server: p.server, label: p.label, fingerprint: p.fingerprint, inboxPub: p.inboxPub, kAuth: p.kAuth, token: p.token!)
}

/// Pseudo-random bytes, repeatable.
func pattern(_ n: Int, seed: UInt8 = 1) -> Data {
    var d = Data(count: n)
    var x = UInt32(seed) &* 2654435761
    for i in 0..<n { x = x &* 1103515245 &+ 12345; d[i] = UInt8(truncatingIfNeeded: x >> 16) }
    return d
}

/// The stored plaintext length of a file of `size` bytes (SPEC 5.3), written out independently of NdesCore.
func paddedSize(_ size: Int) -> Int {
    let l = max(size, 4096)
    let e = Int.bitWidth - 1 - l.leadingZeroBitCount
    let s = Int.bitWidth - e.leadingZeroBitCount
    let mask = (1 << (e - s)) - 1
    return (l + mask) & ~mask
}

import NdesCore
final class DataInputShim: NdesInput, @unchecked Sendable {
    private let inner: DataInput
    init(_ d: Data) { inner = DataInput(d) }
    func read(upTo count: Int) throws -> Data { try inner.read(upTo: count) }
    func totalLength() throws -> Int64 { try inner.totalLength() }
}
