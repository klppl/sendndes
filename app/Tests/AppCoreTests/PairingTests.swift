import XCTest
@testable import AppCore

@MainActor
final class PairingTests: XCTestCase {
    var env: Env!
    override func setUpWithError() throws { env = try Env(startServer: false) }
    override func tearDown() async throws { env?.teardown() }

    func testPairingCreatesPayloadFingerprintAndTokenLine() async throws {
        let m = env.model
        let early = await m.createPairing(label: "iphone", serverURL: "https://inbox.example.com")
        XCTAssertFalse(early, "locked")
        await env.unlock()
        let ok = await m.createPairing(label: "iphone", serverURL: "https://inbox.example.com")
        XCTAssertTrue(ok, m.pairingMessage ?? "nil")
        let p = try XCTUnwrap(m.pairing)
        XCTAssertTrue(p.payload.hasPrefix("ndes-sender2:"), "the phone asks the server to pair: no token in the code")
        XCTAssertEqual(p.fingerprint.count, 8)
        XCTAssertEqual(p.tokenLine, "")
        // The payload decodes to the documented JSON.
        let body = String(p.payload.dropFirst("ndes-sender2:".count))
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let json = try XCTUnwrap(Data(base64Encoded: body + String(repeating: "=", count: (4 - body.count % 4) % 4)))
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: json) as? [String: Any])
        XCTAssertEqual(obj["v"] as? Int, 2)
        XCTAssertEqual(obj["url"] as? String, "https://inbox.example.com")
        XCTAssertEqual(obj["label"] as? String, "iphone")
        XCTAssertEqual(obj["fp"] as? String, p.fingerprint)
        XCTAssertNil(obj["token"], "no token in a pairing code")
        XCTAssertNotNil(obj["inbox_pub"]); XCTAssertNotNil(obj["k_auth"])
        // There is nothing random in it any more: no token is made here, the phone asks the server for its own.
        _ = await m.createPairing(label: "iphone", serverURL: "https://inbox.example.com")
        XCTAssertEqual(m.pairing?.payload, p.payload)
    }

    func testRejectedInputsNeverRunTheHelper() async {
        await env.unlock()
        let m = env.model
        for (label, url) in [("", "https://a.example"), ("has space", "https://a.example"), (String(repeating: "x", count: 33), "https://a.example"),
                             ("ok", "http://a.example"), ("ok", "https://u:p@a.example"), ("ok", "https://a.example/x"),
                             ("ok", "https://a.example?x=1"), ("ok", "not a url"), ("tel\u{e9}", "https://a.example")] {
            let r = await m.createPairing(label: label, serverURL: url)
            XCTAssertFalse(r, "\(label) \(url)")
            XCTAssertNil(m.pairing)
            XCTAssertNotNil(m.pairingMessage)
        }
    }

    func testPairingClearsAfterTheLifetimeOnLockAndOnDeactivate() async throws {
        await env.unlock()
        let m = env.model
        m.pairingLifetime = 0.3
        _ = await m.createPairing(label: "a", serverURL: "https://inbox.example.com")
        XCTAssertNotNil(m.pairing)
        try await Task.sleep(nanoseconds: 800_000_000)
        XCTAssertNil(m.pairing, "gone after its lifetime")

        m.pairingLifetime = 60
        _ = await m.createPairing(label: "a", serverURL: "https://inbox.example.com")
        XCTAssertNotNil(m.pairing)
        m.lock()
        XCTAssertNil(m.pairing, "gone on lock")

        await env.unlock()
        _ = await m.createPairing(label: "a", serverURL: "https://inbox.example.com")
        m.clearPairing()   // the window closing, or the app losing focus
        XCTAssertNil(m.pairing)
    }

    func testNothingSecretOnTheCommandLine() async {
        let args = AppModel.senderConfigArguments(vault: "/v", server: "https://inbox.example.com", label: "iphone")
        XCTAssertEqual(args, ["sender-config", "--json", "--passphrase-stdin", "--pair", "--vault=/v", "--server=https://inbox.example.com", "--label=iphone"])
        await env.unlock()
        _ = await env.model.createPairing(label: "iphone", serverURL: "https://inbox.example.com")
        let secret = String(env.model.pairing?.payload.dropFirst(13) ?? "")
        XCTAssertFalse(secret.isEmpty)
        XCTAssertFalse(args.joined().contains(secret))
        XCTAssertFalse(passphrase.isEmpty ? true : args.joined().contains(passphrase))
    }

    func testQRCodeRoundTrips() throws {
        let payload = "ndes-sender1:" + String(repeating: "AbC-_123", count: 80)
        let img = try XCTUnwrap(QRCode.image(for: payload))
        XCTAssertGreaterThan(img.width, 200)
        XCTAssertEqual(QRCode.decode(img), payload)
    }

    func testAccumulatorIsStrict() {
        func run(_ lines: [String]) -> DevicePairing? {
            let a = PairingAccumulator()
            for l in lines { _ = a.feed(Data(l.utf8)) }
            return a.result(label: "x", server: "https://a", expires: Date())
        }
        let good = [#"{"type":"payload","payload":"ndes-sender1:abc","fp":"0123abcd"}"#,
                    #"{"type":"token-line","line":"upload x \#(String(repeating: "a", count: 64))"}"#, #"{"type":"end"}"#]
        XCTAssertNotNil(run(good))
        XCTAssertNotNil(run([#"{"type":"payload","payload":"ndes-sender2:abc","fp":"0123abcd"}"#, good[2]]), "a pairing payload has no token line")
        XCTAssertNil(run([#"{"type":"payload","payload":"ndes-sender2:abc","fp":"0123abcd"}"#, good[1], good[2]]), "a pairing payload with a token line")
        XCTAssertNil(run([good[0].replacingOccurrences(of: "sender1", with: "sender1"), good[2]]), "an old payload needs its token line")
        XCTAssertNil(run(Array(good.dropLast())), "no end record")
        XCTAssertNil(run([good[0], good[1], #"{"type":"error","code":"other"}"#]))
        XCTAssertNil(run([#"{"type":"payload","payload":"nope","fp":"0123abcd"}"#, good[1], good[2]]))
        XCTAssertNil(run([#"{"type":"payload","payload":"ndes-sender1:abc","fp":"XYZ"}"#, good[1], good[2]]))
        XCTAssertNil(run([good[0], #"{"type":"token-line","line":"both x aa"}"#, good[2]]))
        XCTAssertNil(run(good + [#"{"type":"surprise"}"#]))
        XCTAssertNil(run([good[0], good[0], good[1], good[2]]), "a repeated payload record")
    }
}
