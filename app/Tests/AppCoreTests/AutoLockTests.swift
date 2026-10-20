import XCTest
@testable import AppCore

/// M1: inactivity timer, system lock events, and locking while a pull or a send is running.
@MainActor
final class AutoLockTests: XCTestCase {
    var env: Env!
    override func setUpWithError() throws { env = try Env(startServer: false) }
    override func tearDown() async throws { env?.teardown() }

    func waitFor(_ what: String, timeout: TimeInterval = 20, _ cond: @escaping () -> Bool) async {
        let end = Date().addingTimeInterval(timeout)
        while !cond() && Date() < end { try? await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertTrue(cond(), what)
    }

    /// A server that answers GET /inbox with one id and then never finishes the download or the upload.
    func hangingServer() -> FakeServer {
        FakeServer { fd, srv in
            if srv.requests.last?.hasPrefix("GET /inbox ") == true {
                let body = "{\"ids\":[\"\(String(repeating: "a", count: 32))\"]}"
                srv.write(fd, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)")
            } else {
                Thread.sleep(forTimeInterval: 30) // pull download or PUT: stall
            }
        }
    }

    func pointAt(_ s: FakeServer) throws {
        try env.model.saveSettings(serverURL: "http://127.0.0.1:\(s.port)", token: goodToken, vaultPath: env.vault)
    }

    func testDefaultsPersistenceAndClamping() {
        XCTAssertEqual(env.model.autoLockMinutes, 10)
        env.model.autoLockMinutes = 25
        let suite = UserDefaults(suiteName: env.defaultsName)!
        let again = AppModel(defaults: suite, secrets: env.secrets, runner: env.runner, tempBase: env.tokenBase)
        XCTAssertEqual(again.autoLockMinutes, 25)
        env.model.autoLockMinutes = 0
        XCTAssertEqual(env.model.autoLockMinutes, 1)
        env.model.autoLockMinutes = 100_000
        XCTAssertEqual(env.model.autoLockMinutes, 120)
    }

    func testInactivityLocksAfterTheConfiguredTime() async {
        await env.unlock()
        env.model.autoLockMinutes = 2
        let t0 = Date()
        env.model.noteActivity()
        XCTAssertFalse(env.model.inactivityTick(now: t0.addingTimeInterval(100)))
        XCTAssertEqual(env.model.lockState, .unlocked)
        XCTAssertTrue(env.model.inactivityTick(now: t0.addingTimeInterval(130)))
        XCTAssertEqual(env.model.lockState, .locked)
        XCTAssertTrue(env.model.entries.isEmpty)
        // Locked: nothing more to do.
        XCTAssertFalse(env.model.inactivityTick(now: t0.addingTimeInterval(10_000)))
    }

    func testActivityResetsTheTimer() async {
        await env.unlock()
        env.model.autoLockMinutes = 1
        let later = Date().addingTimeInterval(61)
        env.model.noteActivity()                      // now: well within the minute
        XCTAssertFalse(env.model.inactivityTick(now: Date().addingTimeInterval(30)))
        XCTAssertTrue(env.model.inactivityTick(now: later))
    }

    func testSystemEventsLock() async {
        var count = 0
        let obs = SystemLockObserver(onLock: { count += 1 })
        defer { obs.stop() }
        for n in SystemLockObserver.workspaceEvents { NSWorkspace.shared.notificationCenter.post(name: n, object: nil) }
        for n in SystemLockObserver.distributedEvents { DistributedNotificationCenter.default().postNotificationName(n, object: nil, userInfo: nil, deliverImmediately: true) }
        await waitFor("five events seen") { count == 5 }
    }

    func testLockDuringRunningPull() async throws {
        let srv = hangingServer(); defer { srv.shutdown() }
        try pointAt(srv)
        await env.unlock()
        XCTAssertEqual(env.model.lockState, .unlocked)
        let pull = Task { await env.model.pull() }
        await waitFor("download started") { srv.requests.contains { $0.hasPrefix("GET /inbox/") } }
        XCTAssertTrue(env.model.pullRunning)
        env.model.lockForSystemEvent()
        await pull.value
        XCTAssertEqual(env.model.lockState, .locked)
        XCTAssertFalse(env.model.pullRunning)
        XCTAssertTrue(env.model.pullMessage?.hasPrefix("Interrupted") == true, env.model.pullMessage ?? "nil")
        XCTAssertEqual(env.tokenDirs, [], "token file removed")
        // The helper is gone: a new job under the dropped passphrase must not run.
        await env.model.pull()
        XCTAssertFalse(env.model.pullRunning)
    }

    func testLockDuringRunningSend() async throws {
        let srv = hangingServer(); defer { srv.shutdown() }
        try pointAt(srv)
        await env.unlock()
        let q = env.model.sendQueue
        q.add(urls: [env.writeSource("a.txt", Data("a".utf8)), env.writeSource("b.txt", Data("b".utf8))])
        await waitFor("upload started") { srv.requests.contains { $0.hasPrefix("PUT /inbox") } }
        // An inactivity lock waits for the running send...
        env.model.autoLockMinutes = 1
        XCTAssertFalse(env.model.inactivityTick(now: Date().addingTimeInterval(3600)))
        XCTAssertEqual(env.model.lockState, .unlocked)
        // ...but a system lock cancels it.
        env.model.lockForSystemEvent()
        await q.waitUntilIdle()
        XCTAssertEqual(env.model.lockState, .locked)
        XCTAssertTrue(q.items.allSatisfy { $0.state == .waiting }, "nothing marked sent or failed")
        XCTAssertTrue(q.pausedReason?.hasPrefix("Interrupted") == true, q.pausedReason ?? "nil")
        XCTAssertEqual(srv.requests.filter { $0.hasPrefix("PUT /inbox") }.count, 1, "the second file never started")
    }

    func testInactivityLockWaitsForRunningPullThenLocks() async throws {
        let srv = hangingServer(); defer { srv.shutdown() }
        try pointAt(srv)
        await env.unlock()
        env.model.autoLockMinutes = 1
        let pull = Task { await env.model.pull() }
        await waitFor("download started") { srv.requests.contains { $0.hasPrefix("GET /inbox/") } }
        XCTAssertFalse(env.model.inactivityTick(now: Date().addingTimeInterval(3600)))
        XCTAssertEqual(env.model.lockState, .unlocked)
        env.model.lock()
        await pull.value
    }
}
