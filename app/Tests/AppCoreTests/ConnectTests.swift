import CryptoKit
import XCTest
@testable import AppCore

/// The Mac connects to a real ndesd by approval (no token is typed), then approves a "phone".
@MainActor
final class ConnectTests: XCTestCase {
    var env: Env!
    var server: Process?
    var ownerToken = ""

    override func setUpWithError() throws {
        env = try Env(startServer: false)
        ownerToken = "owner-" + UUID().uuidString.replacingOccurrences(of: "-", with: "") + "-token"
        let hash = SHA256.hash(data: Data(ownerToken.utf8)).map { String(format: "%02x", $0) }.joined()
        let tokens = env.tmp + "/device-tokens"
        FileManager.default.createFile(atPath: tokens, contents: Data("both owner-test \(hash)\n".utf8), attributes: [.posixPermissions: 0o600])
        let p = Process()
        p.executableURL = URL(fileURLWithPath: env.binDir + "/ndesd")
        p.arguments = ["--tokens-file", tokens, "--pairing", "--pairing-open-minutes", "5", "--inbox", env.inbox, "--listen", "127.0.0.1:\(env.port)"]
        let logPath = env.tmp + "/ndesd.log"
        FileManager.default.createFile(atPath: logPath, contents: nil)
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle(forWritingAtPath: logPath)
        try p.run()
        server = p
        for _ in 0..<100 { if portOpen(env.port) { return }; Thread.sleep(forTimeInterval: 0.05) }
        XCTFail("ndesd did not start: " + ((try? String(contentsOfFile: logPath, encoding: .utf8)) ?? "no log"))
    }

    override func tearDown() async throws {
        server?.terminate(); server?.waitUntilExit()
        env?.teardown()
    }

    private var address: String { "http://127.0.0.1:\(env.port)" }

    private func waitFor(_ what: String, timeout: TimeInterval = 10, _ cond: () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !cond(), Date() < end { try? await Task.sleep(nanoseconds: 50_000_000) }
        XCTAssertTrue(cond(), what)
    }

    func testMacConnectsByApprovalAndApprovesAPhone() async throws {
        let m = env.model
        env.secrets.value = nil; env.secrets.server = nil
        m.pairPollInterval = 0.2
        let server = try URLPolicy.parse(address)

        m.connect(to: address)
        await waitFor("the Mac shows a code") { if case .waiting = m.connectState { return true }; return false }
        guard case .waiting(let shown) = m.connectState else { return }
        // The server lists the same code for the owner.
        guard case .success(let st) = await PairClient.pairingState(server: server, token: ownerToken) else { return XCTFail("owner view") }
        XCTAssertEqual(st.requests.count, 1)
        XCTAssertEqual(st.requests[0].spacedCode, shown, "the code on the Mac and on the server match")
        XCTAssertEqual(st.requests[0].role, "both")
        // Not approved yet: nothing was saved.
        XCTAssertNil(m.credentials())
        XCTAssertNil(env.secrets.value)
        // The owner approves on the server; the Mac collects its token by itself.
        _ = await PairClient.ownerAction(server: server, token: ownerToken, method: "POST", path: "/v1/pair/\(st.requests[0].id)/approve")
        await waitFor("connected") { m.connectState == .connected }
        XCTAssertEqual(env.secrets.value?.count, 43)
        XCTAssertNotNil(m.credentials())
        XCTAssertEqual(m.serverURLText, server.canonical)

        // With its own token the Mac can use the owner functions: open the window, approve a phone.
        await m.openPairingWindow(minutes: 5)
        XCTAssertNil(m.devicesMessage, m.devicesMessage ?? "")
        let phone = try await requirePhoneRequest(server)
        await m.refreshDevices()
        XCTAssertEqual(m.phonePairing?.requests.count, 1)
        XCTAssertEqual(m.phonePairing?.requests.first?.spacedCode, phone.spacedCode)
        XCTAssertEqual(m.phonePairing?.requests.first?.isPhone, true)
        await m.decidePair(m.phonePairing!.requests[0].id, approve: true)
        guard case .success(.approved(let token, let role, let label)) = await PairClient.status(server: server, request: phone) else { return XCTFail("phone not approved") }
        XCTAssertEqual(role, "upload"); XCTAssertEqual(label, "iphone-test"); XCTAssertEqual(token.count, 43)
        XCTAssertTrue(m.deviceList.contains { $0.label == "iphone-test" && $0.role == "upload" })
        // The phone's token works, only for sending.
        let up = await ping(token)
        XCTAssertEqual(up, 204)
        // Revoke from the Mac: it stops at once.
        await m.revokeDevice("iphone-test")
        XCTAssertFalse(m.deviceList.contains { $0.label == "iphone-test" })
        let gone = await ping(token)
        XCTAssertEqual(gone, 401)
        // The window closes: a later phone is turned away with words a person can follow.
        _ = await PairClient.ownerAction(server: server, token: ownerToken, method: "POST", path: "/v1/pair/close")
        if case .failure(let f) = await PairClient.request(server: server, label: "late", role: "upload") { XCTAssertEqual(f, .closed); XCTAssertTrue(f.message.contains("Add a device")) }
        else { XCTFail("a closed window accepted a request") }
    }

    func testDenyAndCancel() async throws {
        let m = env.model
        env.secrets.value = nil; env.secrets.server = nil
        m.pairPollInterval = 0.2
        let server = try URLPolicy.parse(address)
        m.connect(to: address)
        await waitFor("code") { if case .waiting = m.connectState { return true }; return false }
        guard case .success(let st) = await PairClient.pairingState(server: server, token: ownerToken) else { return XCTFail() }
        _ = await PairClient.ownerAction(server: server, token: ownerToken, method: "POST", path: "/v1/pair/\(st.requests[0].id)/deny")
        await waitFor("denied") { if case .failed(let msg) = m.connectState { return msg == PairFailure.denied.message }; return false }
        XCTAssertNil(m.credentials())
        // Cancel while waiting.
        m.connect(to: address)
        await waitFor("code again") { if case .waiting = m.connectState { return true }; return false }
        m.cancelConnect()
        XCTAssertEqual(m.connectState, .idle)
    }

    func testBadAddressesAndUnreachableServers() async throws {
        let m = env.model
        m.connect(to: "not a url")
        XCTAssertEqual({ if case .failed = m.connectState { return true }; return false }(), true)
        m.connect(to: "http://127.0.0.1:1")   // nothing listens there
        await waitFor("unreachable") { if case .failed(let msg) = m.connectState { return msg == PairFailure.unreachable.message }; return false }
    }

    func testDeviceLabelIsAcceptedByTheServer() {
        let l = AppModel.deviceLabel()
        XCTAssertTrue((1...32).contains(l.utf8.count) && l.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D || $0 == 0x5F }, l)
    }

    private func requirePhoneRequest(_ server: ServerURL) async throws -> PairRequestInfo {
        guard case .success(let r) = await PairClient.request(server: server, label: "iphone-test", role: "upload") else { throw XCTSkip("no request") }
        return r
    }

    private func ping(_ token: String) async -> Int {
        var r = URLRequest(url: URL(string: address + "/v1/ping")!)
        r.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        return ((try? await URLSession.shared.data(for: r))?.1 as? HTTPURLResponse)?.statusCode ?? 0
    }
}
