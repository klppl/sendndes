import Foundation
import Testing
@testable import SenderCore

@Suite struct PayloadTests {
    @Test func validPayload() throws {
        let f = Fixture()
        let p = try SenderPayload.parse(f.payload())
        #expect(p.server.canonical == "https://inbox.example.com")
        #expect(p.label == "iphone-1")
        #expect(p.fingerprint == fingerprint(f.pub))
        #expect(p.inboxPub == f.pub && p.kAuth == f.auth && p.token == f.token)
        #expect("\(p)".contains("iphone-1") && !"\(p)".contains(f.token))
    }

    @Test func pairingCodeHasNoToken() throws {
        var f = Fixture(); f.pairing = true
        let p = try SenderPayload.parse(f.payload())
        #expect(p.token == nil && p.server.canonical == "https://inbox.example.com" && p.fingerprint == fingerprint(f.pub))
        let withTok = p.withToken("t" + String(repeating: "x", count: 42))
        #expect(withTok.token?.count == 43 && withTok.inboxPub == p.inboxPub)
        // A version 2 code that smuggles a token, a version 1 code without one, and mismatched prefix and version.
        var smuggled = f; smuggled.extra = #","token":"\#(f.token)""#
        #expect(throws: SenderPayload.Failure.badJSON) { _ = try SenderPayload.parse(smuggled.payload()) }
        let v1WithoutToken = SenderPayload.prefix + b64url(Data(f.json().replacingOccurrences(of: #""v":2"#, with: #""v":1"#).utf8))
        #expect(throws: SenderPayload.Failure.badJSON) { _ = try SenderPayload.parse(v1WithoutToken) }
        let v2Prefix1Json = SenderPayload.pairPrefix + b64url(Data(Fixture().json().utf8))
        #expect(throws: SenderPayload.Failure.self) { _ = try SenderPayload.parse(v2Prefix1Json) }
        // The same URL, address-check and fingerprint rules apply.
        var bad = f; bad.url = "http://inbox.example.com"
        #expect(throws: SenderPayload.Failure.badURL(.notHTTPS)) { _ = try SenderPayload.parse(bad.payload()) }
        bad = f; bad.fp = "00000000"
        #expect(throws: SenderPayload.Failure.fingerprintMismatch) { _ = try SenderPayload.parse(bad.payload()) }
        // The store refuses to save a code that has no token yet.
        let store = PairingStore(directory: tempDir("v2"), secrets: MemorySecrets())
        #expect(throws: SecretStoreError.self) { try store.save(p) }
        try store.save(withTok)
        #expect(store.load()?.token == withTok.token)
    }

    @Test func rejectsWrongPrefixAndEncodings() {
        let good = Fixture().payload()
        for bad in ["", "ndes-sender2:" + good.dropFirst(13), "NDES-SENDER1:" + good.dropFirst(13), " " + good, good + "\n", good + "=",
                    "ndes-sender1:", "ndes-sender1:!!!!", "ndes-sender1:abcde", String(good.dropLast())] {
            #expect(throws: SenderPayload.Failure.self, "\(bad.prefix(30))") { _ = try SenderPayload.parse(bad) }
        }
        // Standard base64 characters are not base64url.
        let std = SenderPayload.prefix + Data(Fixture().json().utf8).base64EncodedString()
        if std.contains("+") || std.contains("/") || std.contains("=") {
            #expect(throws: SenderPayload.Failure.self) { _ = try SenderPayload.parse(std) }
        }
    }

    @Test func rejectsOversized() {
        let big = SenderPayload.prefix + String(repeating: "A", count: SenderLimits.maxPayloadCharacters)
        #expect(throws: SenderPayload.Failure.tooLarge) { _ = try SenderPayload.parse(big) }
        var f = Fixture(); f.label = String(repeating: "x", count: 5000)
        #expect(throws: SenderPayload.Failure.self) { _ = try SenderPayload.parse(f.payload()) }
    }

    @Test func rejectsBadFields() {
        func fails(_ f: Fixture, _ expect: SenderPayload.Failure? = nil, _ line: Int = #line) {
            do { _ = try SenderPayload.parse(f.payload()); Issue.record("accepted at line \(line)") }
            catch let e as SenderPayload.Failure { if let expect { #expect(e == expect, "line \(line)") } }
            catch { Issue.record("wrong error \(error)") }
        }
        var f = Fixture(); f.version = 2; fails(f, .unsupportedVersion)
        f = Fixture(); f.version = 0; fails(f, .unsupportedVersion)
        f = Fixture(); f.url = "http://inbox.example.com"; fails(f, .badURL(.notHTTPS))
        f = Fixture(); f.url = "https://u:p@inbox.example.com"; fails(f, .badURL(.hasUserInfo))
        f = Fixture(); f.url = "https://192.168.1.5"; fails(f, .badURL(.ipLiteral))
        f = Fixture(); f.fp = "00000000"; fails(f, .fingerprintMismatch)
        f = Fixture(); f.fp = "ABCDEF01"; fails(f, .badField("fp"))
        f = Fixture(); f.fp = "abc"; fails(f, .badField("fp"))
        f = Fixture(); f.pub = [UInt8](repeating: 0, count: 32); fails(f, .badField("inbox_pub"))
        f = Fixture(); f.auth = [UInt8](repeating: 0, count: 32); fails(f, .badField("k_auth"))
        f = Fixture(); f.token = "short"; fails(f, .badField("token"))
        f = Fixture(); f.token = String(repeating: "a", count: 42); fails(f, .badField("token"))
        f = Fixture(); f.token = String(repeating: "a", count: 42) + "+"; fails(f, .badField("token"))
        f = Fixture(); f.label = ""; fails(f, .badField("label"))
        f = Fixture(); f.label = "has space"; fails(f, .badField("label"))
        f = Fixture(); f.label = String(repeating: "l", count: 33); fails(f, .badField("label"))
        f = Fixture(); f.extra = #","extra":"x""#; fails(f, .badJSON)
    }

    @Test func rejectsStructuralJSONProblems() {
        func enc(_ json: String) -> String { SenderPayload.prefix + b64url(Data(json.utf8)) }
        let f = Fixture()
        let j = f.json()
        // A duplicate key (the last one would win in a lenient parser).
        #expect(throws: SenderPayload.Failure.badJSON) { _ = try SenderPayload.parse(enc(String(j.dropLast()) + #","token":"another""# + "}")) }
        for (n, bad) in ["", "{}", "[]", "null", j + " ", " " + j, j + "x", String(j.dropLast()), j.replacingOccurrences(of: #""v":1"#, with: #""v":"1""#),
                    j.replacingOccurrences(of: #""v":1"#, with: #""v":1.0"#), j.replacingOccurrences(of: #""v":1"#, with: #""v":01"#),
                    j.replacingOccurrences(of: "iphone-1", with: "iph" + String(UnicodeScalar(92)) + "u006fne-1"),
                    j.replacingOccurrences(of: #""v":1"#, with: #""v":1e0"#), j.replacingOccurrences(of: #"{"#, with: #"{ "#)].enumerated().map({ ($0.offset, $0.element) }) {
            #expect(throws: SenderPayload.Failure.self, "case \(n)") { _ = try SenderPayload.parse(enc(bad)) }
        }
        // Invalid UTF-8 inside a string.
        var raw = Array(j.utf8)
        if let i = raw.firstIndex(of: UInt8(ascii: "i")) { raw[i] = 0xFF }
        #expect(throws: SenderPayload.Failure.self) { _ = try SenderPayload.parse(SenderPayload.prefix + b64url(Data(raw))) }
    }

    /// Mutations of a valid payload never crash, and anything accepted is one of the fields' valid forms.
    @Test func fuzz() {
        let good = Array(Fixture().payload().utf8)
        var rng = SystemRandomNumberGenerator()
        var accepted = 0
        for _ in 0..<20_000 {
            var m = good
            switch Int.random(in: 0..<5, using: &rng) {
            case 0: m[Int.random(in: 0..<m.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
            case 1: m.removeSubrange(Int.random(in: 0..<m.count, using: &rng)..<m.count)
            case 2: m.insert(UInt8.random(in: 0...255, using: &rng), at: Int.random(in: 0...m.count, using: &rng))
            case 3: m = m + Array(repeating: 65, count: Int.random(in: 0...3000, using: &rng))
            default: m = (0..<Int.random(in: 0...200, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
            }
            if let s = String(bytes: m, encoding: .utf8), let p = try? SenderPayload.parse(s) {
                accepted += 1
                #expect(p.server.canonical.hasPrefix("https://") && (p.token?.count ?? 0) >= 43 && p.fingerprint.count == 8)
            }
        }
        #expect(accepted < 20_000)
    }

    @Test func serverURLPolicy() throws {
        for ok in ["https://inbox.example.com", "https://Inbox.Example.com/", "https://a.b:8443", "https://xn--hej-5qa.example.se"] {
            let u = try ServerURL.parse(ok)
            #expect(u.canonical.hasPrefix("https://"), "\(ok)")
        }
        #expect(try ServerURL.parse("https://Inbox.Example.com/").canonical == "https://inbox.example.com")
        let bad: [(String, ServerURL.Failure?)] = [
            ("http://inbox.example.com", .notHTTPS), ("inbox.example.com", .notHTTPS), ("ftp://x.example.com", .notHTTPS),
            ("https://user@inbox.example.com", .hasUserInfo), ("https://u:p@inbox.example.com", .hasUserInfo),
            ("https://inbox.example.com/api", .hasPathQueryOrFragment), ("https://inbox.example.com?x=1", .hasPathQueryOrFragment),
            ("https://inbox.example.com/#x", .hasPathQueryOrFragment), ("https://inbox.example.com//", .hasPathQueryOrFragment),
            ("https://127.0.0.1", .ipLiteral), ("https://10.0.0.5:8443", .ipLiteral), ("https://[::1]", .ipLiteral),
            ("https://[2001:db8::1]:443", .ipLiteral), ("https://2130706433", nil), ("https://127.0.0.0x1", .ipLiteral), ("https://1.0x1", .ipLiteral), ("https://example.0xff", .ipLiteral), ("https://1.2.3.4.", nil),
            ("https://inbox.example.com.", nil), ("https://.example.com", nil), ("https://example..com", nil), ("https://localhost", nil),
            ("https://inbox", nil), ("https://", nil), ("https://-bad.example.com", nil), ("https://bad-.example.com", nil),
            ("https://ex ample.com", nil), ("https://inbox.example.com:0", nil), ("https://inbox.example.com:65536", nil),
            ("https://inbox.example.com:80a", nil), ("https://inbox.example.com:", nil), ("https://inbox.exämple.com", nil),
            ("https://inbox.example.com\\@evil.com", nil), ("https://inbox.example.com\n", nil), ("https://" + String(repeating: "a", count: 64) + ".com", nil),
            ("https://ex_ample.com", nil), ("HTTP://inbox.example.com", .notHTTPS),
        ]
        for (s, expect) in bad {
            do { _ = try ServerURL.parse(s); Issue.record("accepted \(s)") }
            catch let e as ServerURL.Failure { if let expect { #expect(e == expect, "\(s)") } }
            catch { Issue.record("wrong error for \(s)") }
        }
        // Loopback http only through the test-only door.
        #expect(throws: ServerURL.Failure.self) { _ = try ServerURL.parse("http://127.0.0.1:8485") }
        #expect(try ServerURL.parseForTests("http://127.0.0.1:8485").canonical == "http://127.0.0.1:8485")
        #expect(throws: ServerURL.Failure.self) { _ = try ServerURL.parseForTests("http://10.0.0.1:8485") }
    }
}
