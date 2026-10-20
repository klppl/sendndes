import XCTest
@testable import AppCore

final class URLPolicyTests: XCTestCase {
    func testAccepted() throws {
        XCTAssertEqual(try URLPolicy.parse("https://Example.com").canonical, "https://example.com")
        XCTAssertEqual(try URLPolicy.parse("https://example.com/").canonical, "https://example.com")
        XCTAssertEqual(try URLPolicy.parse("https://example.com:8443").canonical, "https://example.com:8443")
        XCTAssertEqual(try URLPolicy.parse("http://127.0.0.1:8485").canonical, "http://127.0.0.1:8485")
        XCTAssertEqual(try URLPolicy.parse("http://127.9.9.9").canonical, "http://127.9.9.9")
        XCTAssertEqual(try URLPolicy.parse("http://100.101.102.103:8485").canonical, "http://100.101.102.103:8485")
        XCTAssertEqual(try URLPolicy.parse("http://100.64.0.1").canonical, "http://100.64.0.1")
        XCTAssertEqual(try URLPolicy.parse("http://100.127.255.255").canonical, "http://100.127.255.255")
        XCTAssertEqual(try URLPolicy.parse("http://[::1]:8000").canonical, "http://[::1]:8000")
    }

    func testRefused() {
        let bad = [
            "", " ", "http://example.com", "http://localhost:8485", "http://192.168.1.1", "http://100.63.255.255",
            "http://100.128.0.1", "http://10.0.0.1", "http://127.0.0.1.evil.com", "http://127.1", "http://0x7f.0.0.1",
            "http://[fd7a:115c:a1e0::1]", "ftp://example.com", "file:///etc/passwd", "https://", "https://user@example.com",
            "https://user:pw@example.com", "https://example.com/path", "https://example.com?x=1", "https://example.com#f",
            "https://example.com:0", "https://example.com:70000", "https://exa mple.com", "https://exämple.com",
            "https://example.com%2f", "https://example.com\\evil", "https://ex..ample.com", "https://-.", "https:example.com",
            "https://example.com\n", "HTTP://127.0.0.1:1@evil.com", "http://127.0.0.1:8485/x",
        ]
        for b in bad { XCTAssertThrowsError(try URLPolicy.parse(b), b) }
    }

    func testPlainHTTPMessage() {
        do { _ = try URLPolicy.parse("http://example.com"); XCTFail() } catch { XCTAssertEqual(error as? URLPolicyError, .plainHTTPNotAllowed) }
    }
}

final class DisplayNameTests: XCTestCase {
    func testStrips() {
        XCTAssertEqual(DisplayName.sanitize("a\nb\r\tc"), "abc")
        XCTAssertEqual(DisplayName.sanitize("evil\u{202E}txt.exe"), "eviltxt.exe")
        XCTAssertEqual(DisplayName.sanitize("a\u{200B}b\u{FEFF}c\u{2066}d\u{061C}e\u{200E}f"), "abcdef")
        XCTAssertEqual(DisplayName.sanitize("x\u{FFFC}y\u{E000}z\u{2028}w\u{2029}"), "xyzw")
        XCTAssertEqual(DisplayName.sanitize(""), "(unnamed)")
        XCTAssertEqual(DisplayName.sanitize(" \u{200B}\n "), "(unnamed)")
        XCTAssertEqual(DisplayName.sanitize("Räksmörgås 日本語 😀"), "Räksmörgås 日本語 😀")
    }

    func testCombiningMarksAndLength() {
        let zalgo = "a" + String(repeating: "\u{0301}", count: 50)
        XCTAssertEqual(DisplayName.sanitize(zalgo).unicodeScalars.count, 5)
        XCTAssertEqual(DisplayName.sanitize(String(repeating: "x", count: 10_000)).count, 256)
    }
}

final class TokenFileTests: XCTestCase {
    func testCreateRemoveSweep() throws {
        let base = realTemp()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let tf = try TokenFile.create(token: "secret-token-value", base: base)
        var st = stat()
        XCTAssertEqual(stat(tf.filePath, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o600)
        XCTAssertEqual(stat(tf.dirPath, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o700)
        XCTAssertTrue(tf.dirPath.contains("sendndes-\(getpid())-"))
        XCTAssertEqual(try String(contentsOfFile: tf.filePath), "secret-token-value\n")
        tf.remove(); tf.remove()
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: base), [])

        // A live instance's directory survives a sweep; a dead one's does not.
        let live = try TokenFile.create(token: "x", base: base)
        let dead = base + "/sendndes-999999-" + String(repeating: "a", count: 32)
        mkdir(dead, 0o700)
        FileManager.default.createFile(atPath: dead + "/tok", contents: Data("x".utf8), attributes: [.posixPermissions: 0o600])
        TokenFile.sweep(base: base)
        XCTAssertTrue(FileManager.default.fileExists(atPath: live.dirPath))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dead))
        live.remove()
    }
}

final class HelperOutputTests: XCTestCase {
    func line(_ s: String) -> Data { Data(s.utf8) }
    let id = String(repeating: "ab", count: 16)

    func testListing() {
        let a = ListingAccumulator()
        _ = a.feed(line(#"{"type":"file","id":"\#(id)","size":3,"mtime":1000000000,"name":"a‮b\nc","dir":"d"}"#))
        _ = a.feed(line(#"{"type":"warning","code":"unreadable","id":"\#(id)"}"#))
        _ = a.feed(line(#"{"type":"end","files":1,"problems":1}"#))
        XCTAssertTrue(a.result.complete)
        XCTAssertEqual(a.result.entries.first?.name, "abc")
        XCTAssertEqual(a.result.problems, 1)
    }

    func testListingRejectsGarbage() {
        let a = ListingAccumulator()
        for bad in [#"{"type":"file","id":"../../etc","size":1,"mtime":1,"name":"x","dir":""}"#,
                    #"{"type":"file","id":"\#(id.uppercased())","size":1,"mtime":1,"name":"x","dir":""}"#,
                    #"{"type":"file","id":"\#(id)","size":-1,"mtime":1,"name":"x","dir":""}"#,
                    #"{"type":"file","id":"\#(id)","size":1.5,"mtime":1,"name":"x","dir":""}"#,
                    #"{"type":"nonsense"}"#, "not json", #"{"type":"file"}"#, ""] {
            _ = a.feed(line(bad))
        }
        XCTAssertEqual(a.result.entries.count, 0)
        XCTAssertEqual(a.result.invalidRecords, 8)
        XCTAssertFalse(a.result.complete)
    }

    func testMissingEndIsIncomplete() {
        let a = ListingAccumulator()
        _ = a.feed(line(#"{"type":"file","id":"\#(id)","size":1,"mtime":1,"name":"x","dir":""}"#))
        XCTAssertFalse(a.result.complete)
        XCTAssertFalse(a.result.endSeen)
    }

    func testPull() {
        let counter = Counter()
        let a = PullAccumulator(onStarted: { counter.n += 1 })
        for l in [#"{"type":"started"}"#, #"{"type":"started"}"#,
                  #"{"type":"ingested","id":"\#(id)"}"#, #"{"type":"not-authentic","id":"\#(id)"}"#,
                  #"{"type":"error","code":"invalid-id","item":true}"#,
                  #"{"type":"end","ingested":1,"already":0,"failed":2,"delete_failed":0}"#] { _ = a.feed(line(l)) }
        XCTAssertEqual(counter.n, 1)
        XCTAssertEqual(a.result.items.map(\.kind), [.ingested, .notAuthentic, .error])
        XCTAssertTrue(a.result.complete)
        let b = PullAccumulator(onStarted: {})
        _ = b.feed(line(#"{"type":"started"}"#)); _ = b.feed(line(#"{"type":"error","code":"unauthorized"}"#))
        XCTAssertEqual(b.result.errorCode, "unauthorized")
        XCTAssertFalse(b.result.complete)
    }
}

final class Counter: @unchecked Sendable { var n = 0 }

final class OpenPolicyTests: XCTestCase {
    func testAllowedAndRefused() {
        for ok in ["a.jpg", "a.PNG", "a.heic", "a.mp4", "a.mov", "a.mp3", "a.pdf", "a.txt", "a.rtf", "a.csv"] {
            XCTAssertTrue(OpenPolicy.canOpen(fileName: ok), ok)
        }
        for bad in ["a.command", "a.sh", "a.py", "a.app", "a.pkg", "a.dmg", "a.html", "a.htm", "a.svg", "a.terminal", "a.webloc",
                    "a.zip", "a.jar", "a.js", "a.pl", "a.rb", "a.workflow", "a.scpt", "a.inetloc", "a.docm", "noext", "a.zzzunknown", ".hidden", "a.xml"] {
            XCTAssertFalse(OpenPolicy.canOpen(fileName: bad), bad)
        }
    }
}

final class RouteGuardTests: XCTestCase {
    func guardFor(_ iface: String?, extra: [String] = [], looked: UnsafeMutablePointer<Int>? = nil) -> RouteGuard {
        RouteGuard(lookup: { _ in looked?.pointee += 1; return iface }, extraInterfaces: { extra })
    }
    let ts = try! URLPolicy.parse("http://100.101.102.103:8485")

    func testRouteViaDefaultGatewayWithTailscaleAddressIsRefused() {
        XCTAssertFalse(guardFor("en0").allows(ts))
    }
    func testRouteViaTunnelInterfaceIsAccepted() {
        XCTAssertTrue(guardFor("utun4").allows(ts))
        XCTAssertTrue(guardFor("tailscale0").allows(ts))
    }
    func testNoInterfaceIsRefused() {
        XCTAssertFalse(guardFor(nil).allows(ts))
    }
    func testOverrideListNamesAreAccepted() {
        XCTAssertTrue(guardFor("wg0", extra: ["wg0"]).allows(ts))
        XCTAssertFalse(guardFor("en0", extra: ["wg0"]).allows(ts))
        XCTAssertEqual(RouteGuard.parseInterfaceList(" wg0, ,bad name,utun9"), ["wg0", "utun9"])
    }
    func testLoopbackAndHttpsAreNotChecked() {
        var n = 0
        let g = guardFor(nil, looked: &n)
        XCTAssertTrue(g.allows(try! URLPolicy.parse("http://127.0.0.1:8485")))
        XCTAssertTrue(g.allows(try! URLPolicy.parse("https://example.com")))
        XCTAssertTrue(g.allows(try! URLPolicy.parse("https://100.101.102.103")))
        XCTAssertEqual(n, 0)
    }
    func testUploadIsRefusedBeforeAnyNetworkOrFileAccess() async {
        let client = ServerClient(route: guardFor("en0"))
        let r = await client.upload(file: URL(fileURLWithPath: "/nonexistent"), name: "a", dir: "", server: ts, token: "x")
        XCTAssertEqual(r, .failure(.notTailscaleRoute))
        XCTAssertTrue(UploadFailure.notTailscaleRoute.pausesQueue)
    }
    func testSystemLookupFindsTheLoopbackInterfaceForLocalAddress() {
        // 127.0.0.1 is owned by lo0 on macOS: proves the socket/getifaddrs path works.
        XCTAssertEqual(RouteGuard.systemLookup("127.0.0.1"), "lo0")
    }
}

final class MtimeConversionTests: XCTestCase {
    func testNormalAndExtremeDates() {
        XCTAssertEqual(ServerClient.mtimeNanos(sec: 1_700_000_000, nsec: 5), 1_700_000_000_000_000_005)
        XCTAssertEqual(ServerClient.mtimeNanos(sec: 0, nsec: 0), 0)
        XCTAssertEqual(ServerClient.mtimeNanos(sec: -1, nsec: 999_999_999), -1)
        XCTAssertNil(ServerClient.mtimeNanos(sec: 9_223_372_037, nsec: 0))          // just past year 2262
        XCTAssertNil(ServerClient.mtimeNanos(sec: -9_223_372_037, nsec: 0))
        XCTAssertNil(ServerClient.mtimeNanos(sec: Int64.max, nsec: 0))
        XCTAssertNil(ServerClient.mtimeNanos(sec: Int64.min, nsec: 0))
        XCTAssertNil(ServerClient.mtimeNanos(sec: 0, nsec: -1))
        XCTAssertNil(ServerClient.mtimeNanos(sec: 0, nsec: 1_000_000_000))
        XCTAssertFalse(UploadFailure.dateOutOfRange.pausesQueue, "only that file fails")
    }
}

/// L12: the Swift policy and the Go policy (`valv pull`) must accept and reject the same inputs.
/// The list is shared with the Go test `TestURLPolicyCases`; when the helper is available every
/// case also goes through the real `valv pull`.
final class URLPolicyDifferentialTests: XCTestCase {
    static func decode(_ s: String) -> [UInt8] {
        var out = [UInt8](), b = Array(s.utf8), i = 0
        while i < b.count {
            if b[i] == 0x5c, i + 3 < b.count, b[i + 1] == 0x78, let v = UInt8(String(decoding: b[i + 2...i + 3], as: UTF8.self), radix: 16) {
                out.append(v); i += 4
            } else { out.append(b[i]); i += 1 }
        }
        return out
    }

    func cases() throws -> [(raw: [UInt8], want: String)] {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("url-policy-cases.tsv")
        return try String(contentsOf: url, encoding: .utf8).split(separator: "\n", omittingEmptySubsequences: true)
            .filter { !$0.hasPrefix("#") }
            .map { line in
                let parts = line.split(separator: "\t", maxSplits: 1, omittingEmptySubsequences: false)
                return (Self.decode(parts.count > 0 ? String(parts[0]) : ""), parts.count > 1 ? String(parts[1]) : "")
            }
    }

    func testSwiftPolicyMatchesTheSharedList() throws {
        let list = try cases()
        XCTAssertGreaterThan(list.count, 80)
        for c in list {
            let text = String(decoding: c.raw, as: UTF8.self)
            let got = try? URLPolicy.parse(text).canonical
            if c.want == "REJECT" {
                XCTAssertNil(got, "\(text.debugDescription) must be rejected, got \(got ?? "")")
            } else {
                XCTAssertEqual(got, c.want, text.debugDescription)
            }
        }
    }

    func testRealHelperAgreesWithSwift() throws {
        guard let bin = ProcessInfo.processInfo.environment["VALV_TEST_BIN"] else { throw XCTSkip("VALV_TEST_BIN not set") }
        for c in try cases() where !c.raw.contains(0) && !c.raw.isEmpty {
            // Bytes that are not UTF-8 cannot be passed as a String argument; those cases are covered by the Go test.
            guard let text = String(validatingUTF8: c.raw.map { CChar(bitPattern: $0) } + [0]) else { continue }
            let r = runTool(bin + "/valv", ["pull", "--json", "--server=" + text, "--token-file=/nonexistent", "--vault=/nonexistent"])
            let out = String(decoding: r.out, as: UTF8.self)
            let helperRejects = out.contains("\"code\":\"server-url\"")
            let swiftRejects = (try? URLPolicy.parse(text)) == nil
            XCTAssertEqual(helperRejects, swiftRejects, "\(text.debugDescription): helper said \(out.debugDescription)")
        }
    }
}
