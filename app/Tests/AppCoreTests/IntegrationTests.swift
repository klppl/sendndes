import XCTest
@testable import AppCore

/// AppCore against a temp vault, the real `ndes` helper and a loopback `ndesd`.
@MainActor
final class IntegrationTests: XCTestCase {
    var env: Env!

    override func setUpWithError() throws { env = try Env() }
    override func tearDown() async throws { env?.teardown() }

    func testWrongThenRightPassphrase() async {
        await env.model.unlock(passphrase: "not-the-passphrase")
        XCTAssertEqual(env.model.lockState, .locked)
        XCTAssertEqual(env.model.vaultMessage, "Wrong passphrase.")
        await env.model.unlock(passphrase: "bad\nline")
        XCTAssertEqual(env.model.lockState, .locked)
        await env.unlock()
        XCTAssertEqual(env.model.lockState, .unlocked)
        XCTAssertEqual(env.model.entries.count, 0)
        env.model.lock()
        XCTAssertEqual(env.model.lockState, .locked)
        XCTAssertTrue(env.model.entries.isEmpty)
    }

    func testRecoveryKeyCanBeShownAgain() async throws {
        let m = env.model
        let none = await m.revealRecoveryKey(passphrase: passphrase)
        XCTAssertNil(none, "locked")
        await env.unlock()
        let wrong = await m.revealRecoveryKey(passphrase: "nope")
        XCTAssertNil(wrong)
        XCTAssertEqual(m.recoveryMessage, "Wrong passphrase.")
        let revealed = await m.revealRecoveryKey(passphrase: passphrase)
        let key = try XCTUnwrap(revealed)
        XCTAssertNotNil(key.range(of: "^[A-Z2-7]{4}(-[A-Z2-7]{4})+(-[A-Z2-7]{1,4})?$", options: .regularExpression), key)
        let again = await m.revealRecoveryKey(passphrase: passphrase)
        XCTAssertEqual(again, key)
    }

    func testTouchIDUnlock() async throws {
        let m = env.model
        XCTAssertFalse(m.touchIDEnabled)
        await env.unlock()
        m.enableTouchID()
        XCTAssertTrue(m.touchIDEnabled)
        let viaTouchID = await m.revealRecoveryKey(passphrase: nil)
        XCTAssertNotNil(viaTouchID)
        m.lock()
        await m.unlockWithTouchID()
        XCTAssertEqual(m.lockState, .unlocked)
        // A saved passphrase that stopped working is forgotten.
        m.lock()
        env.biometric.saved[m.vaultPath] = "stale-passphrase"
        await m.unlockWithTouchID()
        XCTAssertEqual(m.lockState, .locked)
        XCTAssertFalse(m.touchIDEnabled)
        XCTAssertEqual(m.vaultMessage, "The saved passphrase no longer works. Type the passphrase.")
    }

    func testCreateVaultFromTheApp() async throws {
        let m = env.model
        let folder = env.tmp + "/created"
        let pw = "a-brand-new-passphrase"
        await m.createVault(at: folder, passphrase: pw, repeated: "different")
        XCTAssertEqual(m.createMessage, "The two passphrases are different.")
        await m.createVault(at: folder, passphrase: "short", repeated: "short")
        XCTAssertEqual(m.createMessage, "Use at least 12 characters.")
        XCTAssertFalse(FileManager.default.fileExists(atPath: folder))
        XCTAssertNil(m.recoveryKey)

        await m.createVault(at: folder, passphrase: pw, repeated: pw)
        XCTAssertNil(m.createMessage)
        let key = try XCTUnwrap(m.recoveryKey)
        XCTAssertNotNil(key.range(of: "^[A-Z2-7]{4}(-[A-Z2-7]{4})+(-[A-Z2-7]{1,4})?$", options: .regularExpression), key)
        XCTAssertEqual(m.lockState, .unlocked, "the new vault is unlocked right away")
        XCTAssertEqual(m.vaultPath, folder)
        XCTAssertTrue(FileManager.default.fileExists(atPath: folder + "/vault.json"))
        XCTAssertEqual(env.tokenDirs, [])
        // The recovery key opens it: `ndes recover` into a copy of the vault without vault.json.
        let copy = env.tmp + "/copy"
        try FileManager.default.copyItem(atPath: folder, toPath: copy)
        try FileManager.default.removeItem(atPath: copy + "/vault.json")
        let r = runTool(env.helper, ["recover", copy, "--unverified-key", "--passphrase-stdin"], stdin: key + "\nnew-passphrase-123\n")
        XCTAssertEqual(r.status, 0, String(decoding: r.err, as: UTF8.self))
        m.acknowledgeRecoveryKey()
        XCTAssertNil(m.recoveryKey)

        // A folder that already holds a vault is refused, without a key.
        m.lock()
        await m.createVault(at: env.vault, passphrase: pw, repeated: pw)
        XCTAssertEqual(m.createMessage, "That folder isn't empty. Choose or create an empty folder.")
        XCTAssertNil(m.recoveryKey)
    }

    func testAddFilesDirectlyWithoutServer() async throws {
        env.stopServer() // nothing may need the server
        await env.unlock()
        let payload = Data((0..<200_000).map { UInt8(truncatingIfNeeded: $0 &* 13) })
        let a = env.writeSource("Direkt – ünï.bin", payload)
        let folder = env.tmp + "/src/Pics"
        try FileManager.default.createDirectory(atPath: folder + "/2026", withIntermediateDirectories: true)
        try Data("nested".utf8).write(to: URL(fileURLWithPath: folder + "/2026/n.txt"))
        let m = env.model
        m.addToVault(urls: [a, URL(fileURLWithPath: folder)])
        await m.waitForAdds()
        XCTAssertTrue(m.addItems.allSatisfy { $0.state == .sent }, "\(m.addItems.map(\.state))")
        XCTAssertEqual(m.addItems.count, 2)
        XCTAssertEqual(m.entries.count, 2, "the listing is refreshed after adding")
        let big = try XCTUnwrap(m.entries.first { $0.name.hasPrefix("Direkt") })
        XCTAssertTrue(m.entries.contains { $0.name == "n.txt" && $0.dir == "Pics/2026" })
        let out = env.tmp + "/direct.bin"
        let r = runTool(env.helper, ["get", "--vault=\(env.vault)", "--passphrase-stdin", "-o=\(out)", "--", big.id], stdin: passphrase + "\n")
        XCTAssertEqual(r.status, 0)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: out)), payload)
        XCTAssertEqual(env.tokenDirs, [])
        // Locked: adding does nothing.
        m.lock()
        m.addToVault(urls: [a])
        XCTAssertTrue(m.addItems.isEmpty)
    }

    func testExportAndOpen() async throws {
        env.stopServer()
        await env.unlock()
        let m = env.model
        let one = env.writeSource("n.txt", Data("one".utf8))
        let folder = env.tmp + "/src/F"
        try FileManager.default.createDirectory(atPath: folder, withIntermediateDirectories: true)
        try Data("two".utf8).write(to: URL(fileURLWithPath: folder + "/n.txt"))
        let cmd = env.writeSource("run.command", Data("#!/bin/sh\n".utf8))
        m.addToVault(urls: [one, URL(fileURLWithPath: folder), cmd])
        await m.waitForAdds()
        XCTAssertEqual(m.entries.count, 3)

        // Export all: same names don't overwrite each other or anything already there.
        let out = env.tmp + "/exported"
        try FileManager.default.createDirectory(atPath: out, withIntermediateDirectories: true)
        try Data("precious".utf8).write(to: URL(fileURLWithPath: out + "/n.txt"))
        await m.export(m.entries, toFolder: out)
        XCTAssertEqual(m.exportMessage, "3 exported.")
        XCTAssertEqual(try String(contentsOfFile: out + "/n.txt"), "precious")
        let names = try FileManager.default.contentsOfDirectory(atPath: out).sorted()
        XCTAssertEqual(names.count, 4, "\(names)")
        let contents = Set(try names.map { try String(contentsOfFile: out + "/" + $0) })
        XCTAssertTrue(contents.isSuperset(of: ["one", "two", "precious"]))

        // Into the vault: refused by the helper, nothing written.
        await m.export([m.entries[0]], toFolder: env.vault)
        XCTAssertEqual(m.exportMessage, "0 exported, 1 failed (Choose a folder outside the vault.).")

        // Open: a text file is decrypted into a private folder that disappears on lock.
        let txt = try XCTUnwrap(m.entries.first { $0.name == "n.txt" && $0.dir == "" })
        let opened = await m.prepareOpen(txt)
        let url = try XCTUnwrap(opened)
        XCTAssertEqual(try String(contentsOf: url), "one")
        var st = stat()
        XCTAssertEqual(stat(url.deletingLastPathComponent().path, &st), 0)
        XCTAssertEqual(st.st_mode & 0o777, 0o700)
        XCTAssertEqual(stat(url.path, &st), 0)
        XCTAssertEqual(st.st_mode & 0o077, 0, "decrypted copy must not be readable by others")
        // A script is never opened and nothing is decrypted for it.
        let before = env.tokenDirs
        let script = try XCTUnwrap(m.entries.first { $0.name == "run.command" })
        let none = await m.prepareOpen(script)
        XCTAssertNil(none)
        XCTAssertTrue(m.openMessage?.contains("Use Export") == true)
        XCTAssertEqual(env.tokenDirs, before)
        m.lock()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertEqual(env.tokenDirs, [])
    }

    func testNotAVault() async throws {
        let empty = env.tmp + "/empty"
        try FileManager.default.createDirectory(atPath: empty, withIntermediateDirectories: true)
        try env.model.saveSettings(serverURL: "http://127.0.0.1:\(env.port)", token: nil, vaultPath: empty)
        await env.unlock()
        XCTAssertEqual(env.model.lockState, .locked)
        XCTAssertTrue(env.model.vaultMessage?.contains("ndes init") == true, env.model.vaultMessage ?? "nil")
    }

    func testSendPullListThenExportMatches() async throws {
        let payload = Data((0..<300_000).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) })
        let a = env.writeSource("Räksmörgås – ünï.bin", payload)
        let b = env.writeSource("small.txt", Data("hello".utf8))
        let folder = env.tmp + "/src/Folder"
        try FileManager.default.createDirectory(atPath: folder + "/sub", withIntermediateDirectories: true)
        try Data("nested".utf8).write(to: URL(fileURLWithPath: folder + "/sub/n.txt"))
        symlink("/etc/passwd", folder + "/link")

        let q = env.model.sendQueue
        q.add(urls: [a, b, URL(fileURLWithPath: folder)])
        await q.waitUntilIdle()
        XCTAssertEqual(q.items.count, 3, "symlink must be skipped")
        XCTAssertTrue(q.items.allSatisfy { $0.state == .sent }, "\(q.items.map(\.state))")
        XCTAssertTrue(q.notes.joined().contains("link"))
        XCTAssertEqual(env.inboxFiles.count, 3)

        await env.unlock()
        await env.model.pull()
        XCTAssertEqual(env.model.pullItems.count, 3)
        XCTAssertTrue(env.model.pullItems.allSatisfy { $0.kind == .ingested })
        XCTAssertTrue(env.model.pullSummary?.hasPrefix("3 added") == true, env.model.pullSummary ?? "nil")
        XCTAssertEqual(env.inboxFiles.count, 0, "server inbox must be empty after a verified pull")
        XCTAssertEqual(env.tokenDirs, [], "token file directory must be gone")
        XCTAssertTrue(env.model.listingStale)

        await env.model.rebuildListing()
        XCTAssertEqual(env.model.entries.count, 3)
        let big = try XCTUnwrap(env.model.entries.first { $0.name.hasPrefix("Räksm") })
        XCTAssertEqual(big.size, Int64(payload.count))
        XCTAssertTrue(env.model.entries.contains { $0.name == "n.txt" && $0.dir == "Folder/sub" })

        let out = env.tmp + "/exported.bin"
        let r = runTool(env.helper, ["get", "--vault=\(env.vault)", "--passphrase-stdin", "-o=\(out)", "--", big.id], stdin: passphrase + "\n")
        XCTAssertEqual(r.status, 0, String(decoding: r.err, as: UTF8.self))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: out)), payload)

        // Pulling again with nothing waiting is fine.
        await env.model.pull()
        XCTAssertEqual(env.model.pullSummary?.hasPrefix("0 added"), true)
    }

    func testWrongTokenPausesQueueAndFailsPull() async throws {
        env.secrets.value = "wrong-token-wrong-token-wrong-token-1234"
        let f = env.writeSource("x.txt", Data("x".utf8))
        let q = env.model.sendQueue
        q.add(urls: [f, env.writeSource("y.txt", Data("y".utf8))])
        await q.waitUntilIdle()
        XCTAssertEqual(q.pausedReason, "The server rejected the token.")
        XCTAssertTrue(q.items.allSatisfy { $0.state == .waiting }, "queue paused, nothing failed")
        XCTAssertEqual(env.inboxFiles.count, 0)

        env.secrets.value = goodToken
        q.resume()
        await q.waitUntilIdle()
        XCTAssertTrue(q.items.allSatisfy { $0.state == .sent })

        env.secrets.value = "wrong-token-wrong-token-wrong-token-1234"
        await env.unlock()
        await env.model.pull()
        XCTAssertEqual(env.model.pullMessage, "The server rejected the token.")
        XCTAssertEqual(env.tokenDirs, [])
        XCTAssertEqual(env.inboxFiles.count, 2, "files stay on the server")
    }

    func testPullWithWrongPassphraseCleansUp() async throws {
        // Unlock with the right passphrase, then hand the runner a different one by re-unlocking is not possible;
        // instead point the model at a second vault whose passphrase differs.
        let other = env.tmp + "/other"
        XCTAssertEqual(runTool(env.helper, ["init", other, "--passphrase-stdin", "--allow-weak-passphrase"], stdin: "another-passphrase\n").status, 0)
        // Server address, token and keys belong to the vault that is open: switch to the second vault, then give it its own.
        try env.model.saveSettings(serverURL: "http://127.0.0.1:\(env.port)", token: nil, vaultPath: other)
        try env.model.saveSettings(serverURL: "http://127.0.0.1:\(env.port)", token: goodToken, vaultPath: other)
        await env.model.unlock(passphrase: "another-passphrase")
        XCTAssertEqual(env.model.lockState, .unlocked)
        env.model.sendQueue.add(urls: [env.writeSource("p.txt", Data("p".utf8))])
        await env.model.sendQueue.waitUntilIdle()
        await env.model.pull() // sealed with the first vault's keys: not authentic here
        XCTAssertEqual(env.model.pullItems.map(\.kind), [.notAuthentic])
        XCTAssertTrue(env.model.pullSummary?.contains("not authentic and left on the server") == true, env.model.pullSummary ?? "nil")
        XCTAssertEqual(env.inboxFiles.count, 1)
        XCTAssertEqual(env.tokenDirs, [])
    }

    func testTooLargeFailsOnlyThatFile() async throws {
        env.stopServer()
        try env.startServerProcess(maxUploadBytes: 1 << 20)
        let q = env.model.sendQueue
        q.add(urls: [env.writeSource("big.bin", Data(count: 2 << 20)), env.writeSource("ok.txt", Data("ok".utf8))])
        await q.waitUntilIdle()
        XCTAssertNil(q.pausedReason)
        guard case .failed(let m) = q.items[0].state else { return XCTFail("\(q.items[0].state)") }
        XCTAssertTrue(m.hasPrefix("Larger than the server allows"))
        XCTAssertEqual(q.items[1].state, .sent)
        q.retry(q.items[0].id)
        await q.waitUntilIdle()
        guard case .failed = q.items[0].state else { return XCTFail() }
    }

    func testServerDownPausesAndResumes() async throws {
        env.stopServer()
        let q = env.model.sendQueue
        q.add(urls: [env.writeSource("a.txt", Data("a".utf8))])
        await q.waitUntilIdle()
        XCTAssertEqual(q.pausedReason, "Can't reach the server. Is Tailscale on?")
        try env.startServerProcess()
        q.resume()
        await q.waitUntilIdle()
        XCTAssertEqual(q.items[0].state, .sent)
        await env.unlock()
        env.stopServer()
        await env.model.pull()
        XCTAssertEqual(env.model.pullMessage, "Can't reach the server. Is Tailscale on?")
        XCTAssertEqual(env.tokenDirs, [])
    }

    func testSecretsNotInArgvOrEnvOrFds() async throws {
        final class Box: @unchecked Sendable { var snaps: [(String, String)] = [] }
        let box = Box()
        env.runner.afterSpawn = { pid in
            let ps = runTool("/bin/ps", ["-E", "-ww", "-p", String(pid), "-o", "command="])
            let lsof = runTool("/usr/sbin/lsof", ["-p", String(pid), "-Ffnt"])
            box.snaps.append((String(decoding: ps.out, as: UTF8.self), String(decoding: lsof.out, as: UTF8.self)))
        }
        env.model.sendQueue.add(urls: [env.writeSource("s.txt", Data("s".utf8))])
        await env.model.sendQueue.waitUntilIdle()
        await env.unlock()
        await env.model.pull()
        XCTAssertEqual(env.model.pullSummary?.hasPrefix("1 added"), true, env.model.pullMessage ?? "")
        XCTAssertEqual(box.snaps.count, 2)
        for (ps, lsof) in box.snaps {
            XCTAssertFalse(ps.contains(passphrase), "passphrase in argv/env")
            XCTAssertFalse(ps.contains(goodToken), "token in argv/env")
            XCTAssertTrue(ps.contains("PATH=/usr/bin:/bin"), ps)
            for k in ["HOME=", "USER=", "TMPDIR=", "SSH_AUTH_SOCK=", "NDES_"] { XCTAssertFalse(ps.contains(k), "\(k) leaked: \(ps)") }
            // No inherited descriptors: besides stdin/out/err, the helper may hold only what it opened itself
            // (the vault folder and its subfolders).
            var fd = "", type = ""
            for l in lsof.split(separator: "\n") {
                if l.hasPrefix("f") { fd = String(l.dropFirst()) }
                else if l.hasPrefix("t") { type = String(l.dropFirst()) }
                else if l.hasPrefix("n"), Int(fd) != nil, type == "REG" || type == "DIR" {
                    let name = String(l.dropFirst())
                    XCTAssertTrue(name.hasPrefix(env.vault), "fd \(fd) (\(type)) is \(name)")
                }
            }
        }
        XCTAssertTrue(box.snaps[1].0.contains("--token-file="))
        XCTAssertTrue(box.snaps[1].0.contains("--passphrase-stdin"))
    }

    func testHelperIntegrityChecks() async throws {
        // Wrong hash
        let bad = HelperRunner(helperPath: env.helper, expectedSHA256: String(repeating: "0", count: 64))
        do { _ = try await bad.run(args: ["help"], passphrase: { "x" }, onLine: { _ in true }); XCTFail() }
        catch { XCTAssertEqual(error as? HelperError, .refused("hash")) }
        // No hash compiled in
        let none = HelperRunner(helperPath: env.helper, expectedSHA256: nil)
        do { _ = try await none.run(args: ["help"], passphrase: { "x" }, onLine: { _ in true }); XCTFail() }
        catch { XCTAssertEqual(error as? HelperError, .refused("no build hash")) }
        // Symlinked ancestor
        symlink(env.tmp + "/helper", env.tmp + "/linkdir")
        let viaLink = HelperRunner(helperPath: env.tmp + "/linkdir/ndes", expectedSHA256: sha256Hex(of: env.helper))
        do { _ = try await viaLink.run(args: ["help"], passphrase: { "x" }, onLine: { _ in true }); XCTFail() }
        catch { guard case HelperError.refused? = error as? HelperError else { return XCTFail("\(error)") } }
        // Group-writable helper
        chmod(env.helper, 0o775)
        do { _ = try await env.runner.run(args: ["help"], passphrase: { "x" }, onLine: { _ in true }); XCTFail() }
        catch { XCTAssertEqual(error as? HelperError, .refused("file")) }
        chmod(env.helper, 0o755)
        // Replaced after the hash was taken
        try Data("#!/bin/sh\necho hi\n".utf8).write(to: URL(fileURLWithPath: env.helper))
        do { _ = try await env.runner.run(args: ["help"], passphrase: { "x" }, onLine: { _ in true }); XCTFail() }
        catch { XCTAssertEqual(error as? HelperError, .refused("hash")) }
    }

    func testLockedJobDoesNotRun() async {
        do { _ = try await env.runner.run(args: ["help"], passphrase: { nil }, onLine: { _ in true }); XCTFail() }
        catch { XCTAssertEqual(error as? HelperError, .locked) }
    }

    func testOutputLimits() async throws {
        // A helper that prints one endless line is cut off; one with a NUL byte is refused.
        let sh = env.tmp + "/helper/endless"
        try Data("#!/bin/sh\nhead -c 3000000 /dev/zero | tr '\\0' 'a'\n".utf8).write(to: URL(fileURLWithPath: sh))
        chmod(sh, 0o755)
        let r = HelperRunner(helperPath: sh, expectedSHA256: sha256Hex(of: sh))
        let o = try await r.run(args: [], passphrase: { "x" }, onLine: { _ in true })
        XCTAssertTrue(o.outputViolation)
        let nul = env.tmp + "/helper/nul"
        try Data("#!/bin/sh\nprintf 'ab\\0cd\\n'\n".utf8).write(to: URL(fileURLWithPath: nul))
        chmod(nul, 0o755)
        let r2 = HelperRunner(helperPath: nul, expectedSHA256: sha256Hex(of: nul))
        let o2 = try await r2.run(args: [], passphrase: { "x" }, onLine: { _ in true })
        XCTAssertTrue(o2.outputViolation)
    }
}

/// Hostile servers talking to ServerClient directly.
final class HostileServerTests: XCTestCase {
    func upload(_ port: Int) async -> (Result<String, UploadFailure>, URL) {
        let dir = realTemp()
        let f = URL(fileURLWithPath: dir + "/f.txt")
        try! Data("payload".utf8).write(to: f)
        let s = try! URLPolicy.parse("http://127.0.0.1:\(port)")
        return (await ServerClient().upload(file: f, name: "f.txt", dir: "", server: s, token: goodToken), f)
    }

    func testRedirectIsNotFollowed() async {
        let evil = FakeServer { fd, srv in srv.write(fd, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") }
        defer { evil.shutdown() }
        let redirector = FakeServer { fd, srv in
            srv.write(fd, "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:\(evil.port)/evil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        }
        defer { redirector.shutdown() }
        let (r, _) = await upload(redirector.port)
        if case .success = r { XCTFail("redirect treated as success") }
        try? await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(redirector.requests.count, 1)
        XCTAssertTrue(redirector.requests[0].hasPrefix("PUT /inbox"))
        XCTAssertEqual(evil.requests.count, 0, "the token must never reach the redirect target")
    }

    func testEndlessResponseBodyIsCutOff() async {
        let endless = FakeServer { fd, srv in
            srv.write(fd, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n")
            let chunk = [UInt8](repeating: 0x61, count: 16384)
            while srv.write(fd, chunk) { if srv.written > 200_000_000 { return } }
        }
        defer { endless.shutdown() }
        let started = Date()
        let (r, _) = await upload(endless.port)
        XCTAssertEqual(r, .failure(.unexpectedResponse))
        XCTAssertLessThan(Date().timeIntervalSince(started), 15)
        XCTAssertLessThan(endless.written, 50_000_000)
    }

    func testBadSuccessBodiesAreRejected() async {
        for body in ["{\"id\":\"../../x\"}", "{\"id\":\"\(String(repeating: "A", count: 32))\"}", "[]", "", "{\"id\":\"abc\"}"] {
            let s = FakeServer { fd, srv in
                srv.write(fd, "HTTP/1.1 201 Created\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)")
            }
            let (r, _) = await upload(s.port)
            XCTAssertEqual(r, .failure(.unexpectedResponse), body)
            s.shutdown()
        }
    }

    func testStatusMapping() async {
        for (code, expected) in [(401, UploadFailure.tokenRejected), (413, .tooLarge), (429, .rateLimited), (507, .inboxFull), (400, .badName), (503, .serverError)] {
            let s = FakeServer { fd, srv in srv.write(fd, "HTTP/1.1 \(code) X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") }
            let (r, _) = await upload(s.port)
            XCTAssertEqual(r, .failure(expected), "\(code)")
            s.shutdown()
        }
    }
}

/// L5: the body comes from the descriptor that was checked, not from the path.
final class UploadTOCTOUTests: XCTestCase {
    final class Captured: @unchecked Sendable { var body = Data(); var head = ""; var id = "" }

    func capturingServer(_ cap: Captured) -> FakeServer {
        FakeServer { fd, srv in
            let len = srv.lastHead.lowercased().components(separatedBy: "\r\n")
                .first { $0.hasPrefix("content-length:") }.flatMap { Int($0.dropFirst(15).trimmingCharacters(in: .whitespaces)) } ?? -1
            var body = srv.lastBodyPrefix
            var buf = [UInt8](repeating: 0, count: 65536)
            while len >= 0 && body.count < len {
                let n = read(fd, &buf, buf.count)
                if n <= 0 { break }
                body.append(contentsOf: buf[0..<n])
            }
            if srv.lastHead.hasPrefix("PUT ") { cap.head = srv.lastHead; cap.body = body }
            srv.write(fd, "HTTP/1.1 201 Created\r\nContent-Length: 41\r\nConnection: close\r\n\r\n{\"id\":\"\(String(repeating: "b", count: 32))\"}")
        }
    }

    func testBodyComesFromTheOpenedFileNotThePath() async {
        let cap = Captured()
        let srv = capturingServer(cap); defer { srv.shutdown() }
        let dir = realTemp()
        let path = dir + "/f.bin"
        let original = Data((0..<300_000).map { UInt8($0 % 251) })
        try! original.write(to: URL(fileURLWithPath: path))
        var client = ServerClient()
        client.beforeBody = {
            // The attacker (or a sync client) swaps the path right after the checks.
            try? FileManager.default.removeItem(atPath: path)
            symlink("/etc/hosts", path)
        }
        let s = try! URLPolicy.parse("http://127.0.0.1:\(srv.port)")
        let r = await client.upload(file: URL(fileURLWithPath: path), name: "f.bin", dir: "", server: s, token: goodToken)
        XCTAssertEqual(r, .success(String(repeating: "b", count: 32)))
        XCTAssertEqual(cap.body, original, "what the server got is the file that was opened")
        XCTAssertTrue(cap.head.lowercased().contains("content-length: \(original.count)"), cap.head)
        XCTAssertFalse(cap.head.lowercased().contains("transfer-encoding"), cap.head)
    }

    func testEmptyFileAndGrowingFile() async {
        let cap = Captured()
        let srv = capturingServer(cap); defer { srv.shutdown() }
        let dir = realTemp()
        let s = try! URLPolicy.parse("http://127.0.0.1:\(srv.port)")
        let empty = dir + "/empty"
        FileManager.default.createFile(atPath: empty, contents: Data())
        let r0 = await ServerClient().upload(file: URL(fileURLWithPath: empty), name: "e", dir: "", server: s, token: goodToken)
        XCTAssertEqual(r0, .success(String(repeating: "b", count: 32)))
        XCTAssertEqual(cap.body.count, 0)

        // The file grows after the checks: only the checked length is sent, and the change is reported.
        let grow = dir + "/grow"
        try! Data(repeating: 1, count: 1000).write(to: URL(fileURLWithPath: grow))
        var client = ServerClient()
        client.beforeBody = {
            let h = FileHandle(forWritingAtPath: grow)!
            h.seekToEndOfFile(); h.write(Data(repeating: 2, count: 500)); try? h.close()
        }
        let r1 = await client.upload(file: URL(fileURLWithPath: grow), name: "g", dir: "", server: s, token: goodToken)
        XCTAssertEqual(cap.body, Data(repeating: 1, count: 1000), )
        if case .failure(.fileChanged) = r1 {} else { XCTFail("expected fileChanged, got \(r1)") }
    }
}

/// L2: ndesd's 507 bodies and the 400s that are not about names.
final class StorageStatusTests: XCTestCase {
    func upload(status: Int, body: String) async -> Result<String, UploadFailure> {
        let s = FakeServer { fd, srv in
            srv.write(fd, "HTTP/1.1 \(status) X\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)")
        }
        defer { s.shutdown() }
        let dir = realTemp()
        let f = URL(fileURLWithPath: dir + "/f.txt")
        try! Data("payload".utf8).write(to: f)
        return await ServerClient().upload(file: f, name: "f.txt", dir: "", server: try! URLPolicy.parse("http://127.0.0.1:\(s.port)"), token: goodToken)
    }

    func test507And400Bodies() async {
        let a = await upload(status: 507, body: "server out of space\n")
        XCTAssertEqual(a, .failure(.serverOutOfSpace))
        let b = await upload(status: 507, body: "inbox byte limit reached\n")
        XCTAssertEqual(b, .failure(.inboxFull))
        let c = await upload(status: 507, body: "inbox file limit reached\n")
        XCTAssertEqual(c, .failure(.inboxFull))
        let d = await upload(status: 400, body: "invalid or missing file name header\n")
        XCTAssertEqual(d, .failure(.badName))
        let e = await upload(status: 400, body: "upload failed\n")
        XCTAssertEqual(e, .failure(.uploadRejected))
        XCTAssertEqual(UploadFailure.serverOutOfSpace.message, "The server is out of space.")
        XCTAssertTrue(UploadFailure.serverOutOfSpace.pausesQueue)
        XCTAssertFalse(UploadFailure.uploadRejected.pausesQueue)
    }
}

/// The real ndesd out of free space (margin larger than any disk): the app says so and pauses.
@MainActor
final class OutOfSpaceIntegrationTests: XCTestCase {
    func testServerOutOfSpaceIsShown() async throws {
        let env = try Env(serverArgs: ["--min-free-bytes", String(Int64(1) << 60)])
        defer { env.teardown() }
        let q = env.model.sendQueue
        q.add(urls: [env.writeSource("a.txt", Data("a".utf8))])
        await q.waitUntilIdle()
        XCTAssertEqual(q.pausedReason, "The server is out of space.")
        XCTAssertEqual(q.items[0].state, .waiting)
    }
}

final class ClientSealedUploadTests: XCTestCase {
    private let pub = Data((0..<32).map { UInt8($0) }).base64EncodedString()
    private let auth = Data(repeating: 0xAB, count: 32).base64EncodedString()

    func testClientSealedUploadSendsSealedInboxFileWithoutMetadataHeaders() async throws {
        let keys = try XCTUnwrap(ServerKeys(inboxPub: pub, kAuth: auth))
        let cap = UploadTOCTOUTests.Captured()
        let srv = FakeServer { fd, s in
            let head = s.lastHead
            if head.hasPrefix("PUT /inbox/") {
                cap.head = head
                let line = head.components(separatedBy: "\r\n").first ?? ""
                let path = line.split(separator: " ")[1]
                let receivedID = String(path.dropFirst("/inbox/".count))
                cap.id = receivedID
                let len = head.lowercased().components(separatedBy: "\r\n")
                    .first { $0.hasPrefix("content-length:") }.flatMap { Int($0.dropFirst(15).trimmingCharacters(in: .whitespaces)) } ?? -1
                var body = s.lastBodyPrefix
                var buf = [UInt8](repeating: 0, count: 65536)
                while len >= 0 && body.count < len {
                    let n = read(fd, &buf, buf.count)
                    if n <= 0 { break }
                    body.append(contentsOf: buf[0..<n])
                }
                cap.body = body
                s.write(fd, "HTTP/1.1 201 Created\r\nContent-Length: 41\r\nConnection: close\r\n\r\n{\"id\":\"\(receivedID)\"}")
            }
        }
        defer { srv.shutdown() }

        let dir = realTemp()
        let fileURL = URL(fileURLWithPath: dir + "/secret.txt")
        let plaintext = Data("super confidential secret bytes".utf8)
        try plaintext.write(to: fileURL)

        let serverURL = try URLPolicy.parse("http://127.0.0.1:\(srv.port)")
        let client = ServerClient()
        let result = await client.upload(file: fileURL, name: "secret.txt", dir: "my/subfolder", server: serverURL, token: goodToken, keys: keys)

        guard case .success(let uploadedID) = result else {
            XCTFail("upload failed: \(result)")
            return
        }
        XCTAssertEqual(uploadedID, cap.id)

        // Verify headers: Bearer token and Content-Length are present; NO X-Ndes-* headers!
        let lowerHead = cap.head.lowercased()
        XCTAssertTrue(lowerHead.contains("authorization: bearer \(goodToken)"), "bearer token present")
        XCTAssertFalse(lowerHead.contains("x-ndes-name"), "no plaintext file name header")
        XCTAssertFalse(lowerHead.contains("x-ndes-dir"), "no plaintext dir header")
        XCTAssertFalse(lowerHead.contains("x-ndes-mtime"), "no plaintext mtime header")
        XCTAssertFalse(lowerHead.contains("x-ndes-mime"), "no plaintext mime header")

        // Verify body: it is a valid inbox file starting with NDES\x02\x02 and the 16-byte fileID matches receivedID
        XCTAssertGreaterThan(cap.body.count, 58)
        XCTAssertEqual(Array(cap.body.prefix(4)), Array("NDES".utf8))
        XCTAssertEqual(cap.body[4], 2) // version
        XCTAssertEqual(cap.body[5], 2) // KindInbox
        let idHex = cap.body[6..<22].map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(idHex, cap.id)
    }

    func testClientSealedUploadIdempotentResponse200Accepted() async throws {
        let keys = try XCTUnwrap(ServerKeys(inboxPub: pub, kAuth: auth))
        let srv = FakeServer { fd, s in
            let line = s.lastHead.components(separatedBy: "\r\n").first ?? ""
            let path = line.split(separator: " ")[1]
            let id = String(path.dropFirst("/inbox/".count))
            s.write(fd, "HTTP/1.1 200 OK\r\nContent-Length: 41\r\nConnection: close\r\n\r\n{\"id\":\"\(id)\"}")
        }
        defer { srv.shutdown() }

        let dir = realTemp()
        let fileURL = URL(fileURLWithPath: dir + "/retry.txt")
        try Data("payload".utf8).write(to: fileURL)

        let serverURL = try URLPolicy.parse("http://127.0.0.1:\(srv.port)")
        let r = await ServerClient().upload(file: fileURL, name: "retry.txt", dir: "", server: serverURL, token: goodToken, keys: keys)
        guard case .success(let id) = r else {
            XCTFail("200 OK retry was not treated as success: \(r)")
            return
        }
        XCTAssertEqual(id.count, 32)
    }

    func testClientSealedUploadConflict409Rejected() async throws {
        let keys = try XCTUnwrap(ServerKeys(inboxPub: pub, kAuth: auth))
        let srv = FakeServer { fd, s in
            s.write(fd, "HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        }
        defer { srv.shutdown() }

        let dir = realTemp()
        let fileURL = URL(fileURLWithPath: dir + "/conflict.txt")
        try Data("payload".utf8).write(to: fileURL)

        let serverURL = try URLPolicy.parse("http://127.0.0.1:\(srv.port)")
        let r = await ServerClient().upload(file: fileURL, name: "conflict.txt", dir: "", server: serverURL, token: goodToken, keys: keys)
        XCTAssertEqual(r, .failure(.uploadRejected))
    }
}
