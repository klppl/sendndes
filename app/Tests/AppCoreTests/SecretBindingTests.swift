import XCTest
@testable import AppCore

/// M3: the token is bound to the server address it was saved for.
@MainActor
final class SecretBindingTests: XCTestCase {
    var env: Env!
    override func setUpWithError() throws { env = try Env(startServer: false) }
    override func tearDown() async throws { env?.teardown() }

    func testEditedUserDefaultsNeverReceivesTheToken() async throws {
        let attacker = FakeServer { fd, srv in srv.write(fd, "HTTP/1.1 201 Created\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") }
        defer { attacker.shutdown() }
        // The app is configured for its own server and the token was saved for that address.
        try env.model.saveSettings(serverURL: "http://127.0.0.1:\(env.port)", token: goodToken, vaultPath: env.vault)
        // Same-user malware: `defaults write ... serverURL http://127.0.0.1:<attacker>`.
        let suite = UserDefaults(suiteName: env.defaultsName)!
        suite.set("http://127.0.0.1:\(attacker.port)", forKey: AppModel.urlKey)
        // Next launch.
        let relaunched = AppModel(defaults: suite, secrets: env.secrets, runner: env.runner, tempBase: env.tokenBase)
        XCTAssertTrue(relaunched.tokenNeedsReentry)
        XCTAssertNil(relaunched.credentials())
        relaunched.sendQueue.add(urls: [env.writeSource("a.txt", Data("a".utf8))])
        await relaunched.sendQueue.waitUntilIdle()
        XCTAssertEqual(relaunched.sendQueue.items[0].state, .waiting)
        XCTAssertTrue(relaunched.sendQueue.pausedReason?.contains("Enter the token again") == true, relaunched.sendQueue.pausedReason ?? "nil")
        await relaunched.unlock(passphrase: passphrase)
        await relaunched.pull()
        XCTAssertTrue(relaunched.pullMessage?.contains("Enter the token again") == true, relaunched.pullMessage ?? "nil")
        XCTAssertEqual(attacker.requests, [], "no request, so no token, reached the edited address")

        // Saving the edited address without retyping the token is refused; with the token it is accepted.
        XCTAssertThrowsError(try relaunched.saveSettings(serverURL: suite.string(forKey: AppModel.urlKey)!, token: nil, vaultPath: env.vault)) {
            XCTAssertEqual($0 as? AppModel.SettingsError, .tokenRequiredForNewHost)
        }
        try relaunched.saveSettings(serverURL: suite.string(forKey: AppModel.urlKey)!, token: goodToken, vaultPath: env.vault)
        XCTAssertFalse(relaunched.tokenNeedsReentry)
        XCTAssertNotNil(relaunched.credentials())
    }

    func testPortOrSchemeChangeNeedsTheTokenToo() throws {
        try env.model.saveSettings(serverURL: "http://127.0.0.1:\(env.port)", token: goodToken, vaultPath: env.vault)
        XCTAssertThrowsError(try env.model.saveSettings(serverURL: "http://127.0.0.1:\(env.port + 1)", token: nil, vaultPath: env.vault))
        XCTAssertThrowsError(try env.model.saveSettings(serverURL: "https://example.com", token: nil, vaultPath: env.vault))
        // Unchanged address, no token typed: fine, and the token stays.
        try env.model.saveSettings(serverURL: "http://127.0.0.1:\(env.port)/", token: nil, vaultPath: env.vault)
        XCTAssertNotNil(env.model.credentials())
    }

    func testTokenWithoutServerBindingIsNeverSent() {
        env.secrets.server = nil   // an item saved by an older version
        XCTAssertNil(env.model.credentials())
        XCTAssertTrue(env.model.tokenNeedsReentry)
    }
}
