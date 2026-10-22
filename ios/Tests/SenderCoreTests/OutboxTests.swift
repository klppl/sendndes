import Foundation
import Security
import Testing
@testable import SenderCore

final class FakeTransport: UploadTransport, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var started: [UploadTask] = []
    private(set) var bodies: [String: [Data]] = [:]
    var active: Set<String> = []
    func start(_ task: UploadTask) {
        lock.lock(); defer { lock.unlock() }
        started.append(task)
        bodies[task.id, default: []].append((try? Data(contentsOf: task.fileURL)) ?? Data())
    }
    func activeTaskIDs() async -> Set<String> { active }
    var count: Int { lock.lock(); defer { lock.unlock() }; return started.count }
}

final class Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var t: Date
    init(_ t: Date = Date()) { self.t = t }
    var now: Date { lock.lock(); defer { lock.unlock() }; return t }
    func advance(_ s: TimeInterval) { lock.lock(); t = t.addingTimeInterval(s); lock.unlock() }
}

/// ndesd's answer to a stored upload.
func storedBody(_ id: String) -> Data { Data(#"{"id":"\#(id)"}"#.utf8) + Data("\n".utf8) }

struct Rig {
    let dir: URL
    let outbox: Outbox
    let store: PairingStore
    let transport: FakeTransport
    let coordinator: UploadCoordinator
    let clock: Clock
    let secrets: MemorySecrets

    init(paired: Bool = true, maxParallel: Int = 2) throws {
        dir = tempDir("rig")
        clock = Clock()
        let c = clock
        outbox = try Outbox(directory: dir.appendingPathComponent("outbox"), now: { c.now })
        secrets = MemorySecrets()
        store = PairingStore(directory: dir.appendingPathComponent("config"), secrets: secrets)
        if paired { try store.save(SenderPayload.parse(Fixture().payload())) }
        transport = FakeTransport()
        coordinator = UploadCoordinator(outbox: outbox, pairings: store, transport: transport, maxParallel: maxParallel)
    }

    /// A sealed file in the outbox with the given content bytes (not a real sealed file: the state machine does not care).
    @discardableResult
    func addItem(_ i: Int, bytes: Int = 100) throws -> SealedItem {
        let id = String(format: "%032x", i + 1)
        try pattern(bytes, seed: UInt8(i + 1)).write(to: outbox.sealedURL(id))
        return try outbox.add(id: id, displayName: "file\(i).txt", size: Int64(bytes), sealedSize: Int64(bytes))
    }
}

@Suite struct OutboxTests {
    @Test func uploadRequestHasNoNamesAndTheRightShape() throws {
        let rig = try Rig()
        let it = try rig.addItem(0, bytes: 1234)
        rig.coordinator.startPending()
        let t = try #require(rig.transport.started.first)
        #expect(t.request.httpMethod == "PUT")
        #expect(t.request.url?.absoluteString == "https://inbox.example.com/inbox/\(it.id)")
        #expect(t.request.value(forHTTPHeaderField: "Authorization")?.hasPrefix("Bearer ") == true)
        #expect(t.request.value(forHTTPHeaderField: "Content-Length") == "1234")
        #expect(t.request.value(forHTTPHeaderField: "Content-Type") == "application/octet-stream")
        #expect(!(t.request.url!.absoluteString.contains("file0")), "no name in the URL")
        let headers = (t.request.allHTTPHeaderFields ?? [:]).keys.map { $0.lowercased() }
        #expect(!headers.contains { $0.hasPrefix("x-ndes") }, "no X-Ndes-* headers")
        #expect(t.request.allowsCellularAccess)
        #expect(t.request.httpShouldHandleCookies == false)
    }

    @Test func requestBuilderRejectsBadInput() throws {
        let s = try ServerURL.parse("https://inbox.example.com")
        let id = String(repeating: "a", count: 32)
        #expect(UploadRequest.make(server: s, id: id, token: "t", length: 10) != nil)
        for bad in [String(repeating: "A", count: 32), String(repeating: "a", count: 31), "../" + String(repeating: "a", count: 29), ""] {
            #expect(UploadRequest.make(server: s, id: bad, token: "t", length: 10) == nil, "\(bad)")
        }
        #expect(UploadRequest.make(server: s, id: id, token: "bad token", length: 10) == nil)
        #expect(UploadRequest.make(server: s, id: id, token: "t\r\nX: y", length: 10) == nil)
        #expect(UploadRequest.make(server: s, id: id, token: "t", length: 0) == nil)
        #expect(UploadRequest.make(server: s, id: id, token: "t", length: 10, allowsCellular: false)?.allowsCellularAccess == false)
    }

    @Test func aTwoHundredFromSomethingElseIsNeverStored() throws {
        let rig = try Rig()
        let it = try rig.addItem(0)
        rig.coordinator.startPending()
        // A login page or a redirect target answering 200 with HTML, or ndesd's answer for another id.
        for body in [Data("<html>please log in</html>".utf8), Data(), Data("{}".utf8), storedBody(String(repeating: "b", count: 32)), Data(#"{"id":"x","extra":1}"#.utf8)] {
            rig.coordinator.handle(taskID: it.id, result: .response(status: 200, body: body))
            let cur = try #require(rig.outbox.item(it.id), "the file must be kept")
            #expect(cur.state == .failed && cur.failure == .unexpected)
            #expect(FileManager.default.fileExists(atPath: rig.outbox.sealedURL(it.id).path))
            #expect(rig.outbox.history().allSatisfy { $0.status != .stored })
            #expect(rig.outbox.retry(it.id)); rig.coordinator.startPending()
        }
        // A request that was redirected somewhere else is the same.
        rig.coordinator.handle(taskID: it.id, result: .redirected)
        #expect(rig.outbox.item(it.id)?.failure == .unexpected)
    }

    @Test func retryLaterWaitsLongerEachTime() throws {
        let rig = try Rig()
        let it = try rig.addItem(0)
        var waits: [TimeInterval] = []
        for _ in 0..<5 {
            rig.clock.advance(4000)   // past any wait
            #expect(rig.coordinator.startPending().count == 1)
            let before = rig.clock.now
            rig.coordinator.handle(taskID: it.id, result: .response(status: 429, body: Data()))
            #expect(rig.coordinator.startPending().isEmpty, "not again at once")
            waits.append(try #require(rig.outbox.item(it.id)?.notBefore).timeIntervalSince(before))
        }
        #expect(zip(waits, [30.0, 60, 120, 240, 480]).allSatisfy { abs($0 - $1) <= 1 }, "dates are stored to the second")
        #expect(waits.allSatisfy { $0 <= 3600 })
    }

    @Test func aFileIsOnlySentToTheServerItWasLockedFor() throws {
        let rig = try Rig()
        let id = String(format: "%032x", 99)
        try pattern(100).write(to: rig.outbox.sealedURL(id))
        _ = try rig.outbox.add(id: id, displayName: "x", size: 100, sealedSize: 100, pairingFP: "deadbeef")
        #expect(rig.coordinator.startPending().isEmpty)
        #expect(rig.outbox.item(id)?.failure == .pairedElsewhere)
        #expect(rig.transport.count == 0, "nothing was sent to the new server")
    }

    @Test func recoverLeavesTheOtherSessionsUploadsAlone() async throws {
        let rig = try Rig()
        let a = try rig.addItem(0)
        rig.outbox.markUploading(a.id, session: "share")
        await rig.coordinator.recover()   // this process is session "app"; its task list says nothing about "share"
        #expect(rig.outbox.item(a.id)?.state == .uploading)
        rig.clock.advance(3 * 3600)
        await rig.coordinator.recover()
        #expect(rig.outbox.item(a.id)?.state == .sealed, "a long-gone upload of the other session is retried")
    }

    @Test func recoverKeepsYoungSealingFilesAndNewOrphans() async throws {
        let rig = try Rig()
        let dir = rig.dir.appendingPathComponent("outbox")
        let tmp = dir.appendingPathComponent(".sealing-live.tmp"), orphan = dir.appendingPathComponent(String(repeating: "c", count: 32) + ".inb")
        try Data("x".utf8).write(to: tmp); try Data("y".utf8).write(to: orphan)
        rig.outbox.recover(activeTaskIDs: [])
        #expect(FileManager.default.fileExists(atPath: tmp.path) && FileManager.default.fileExists(atPath: orphan.path), "another process may be writing these right now")
    }

    @Test func twoProcessesCannotBothTakeTheSameItem() throws {
        let rig = try Rig()
        let it = try rig.addItem(0)
        let other = try Outbox(directory: rig.dir.appendingPathComponent("outbox"))   // as the share extension would
        var wins = 0
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: 8) { i in
            let ok = (i % 2 == 0 ? rig.outbox : other).markUploading(it.id, session: "s\(i)")
            lock.lock(); if ok { wins += 1 }; lock.unlock()
        }
        #expect(wins == 1)
    }

    @Test func outcomesFollowTheDocumentedCodes() {
        let cases: [(Int, UploadOutcome)] = [
            (401, .failed(.tokenRejected)), (403, .failed(.tokenRejected)), (409, .failed(.conflict)),
            (507, .failed(.serverFull)), (413, .failed(.tooLargeForServer)), (429, .retryLater), (408, .retryLater), (500, .retryLater),
            (502, .retryLater), (524, .retryLater), (400, .failed(.rejectedByServer)), (404, .failed(.rejectedByServer)),
            (301, .failed(.unexpected)), (302, .failed(.unexpected)), (204, .failed(.unexpected)), (100, .failed(.unexpected)),
        ]
        let id = String(repeating: "a", count: 32)
        for (code, want) in cases { #expect(UploadOutcome.classify(status: code, forID: id) == want, "\(code)") }
        #expect(UploadOutcome.classify(status: 200, body: storedBody(id), forID: id) == .stored)
        #expect(UploadOutcome.classify(status: 201, body: storedBody(id), forID: id) == .stored)
    }

    @Test func retryAfterNetworkErrorSendsTheIdenticalBytesAndId() throws {
        let rig = try Rig()
        let it = try rig.addItem(0, bytes: 5000)
        let original = try Data(contentsOf: rig.outbox.sealedURL(it.id))
        rig.coordinator.startPending()
        #expect(rig.outbox.item(it.id)?.state == .uploading)
        rig.coordinator.handle(taskID: it.id, result: .networkError)
        #expect(rig.outbox.item(it.id)?.state == .sealed, "back in the queue, not failed")
        #expect(rig.transport.count == 1, "a network error does not restart by itself")
        #expect(rig.coordinator.startPending().isEmpty, "and not before its wait is over")
        rig.clock.advance(4000)
        rig.coordinator.startPending()
        rig.coordinator.handle(taskID: it.id, result: .response(status: 429, body: Data()))
        rig.clock.advance(4000)
        rig.coordinator.startPending()
        #expect(rig.transport.count == 3)
        let sent = rig.transport.bodies[it.id]!
        #expect(sent.allSatisfy { $0 == original }, "every attempt sent the same bytes")
        #expect(Set(rig.transport.started.map(\.request.url)).count == 1, "under the same id")
        #expect(rig.outbox.item(it.id)?.attempts == 3)
        // The file on disk was never touched (never re-sealed).
        #expect(try Data(contentsOf: rig.outbox.sealedURL(it.id)) == original)
    }

    @Test func storedDeletesTheSealedFileAndWritesHistory() throws {
        let rig = try Rig()
        let it = try rig.addItem(0)
        rig.coordinator.startPending()
        rig.coordinator.handle(taskID: it.id, result: .response(status: 201, body: storedBody(it.id)))
        #expect(!FileManager.default.fileExists(atPath: rig.outbox.sealedURL(it.id).path))
        #expect(rig.outbox.item(it.id) == nil)
        let h = rig.outbox.history()
        #expect(h.count == 1 && h[0].status == .stored && h[0].statusText == "Stored on server" && h[0].name == "file0.txt")
        #expect(!h.map(\.statusText).contains { $0.lowercased().contains("deliver") })
    }

    @Test func idempotentStoredAnswer200IsStoredToo() throws {
        let rig = try Rig()
        let it = try rig.addItem(0)
        rig.coordinator.startPending()
        rig.coordinator.handle(taskID: it.id, result: .response(status: 200, body: storedBody(it.id)))
        #expect(rig.outbox.history().first?.status == .stored)
    }

    @Test func failuresStayWithAReasonAndRetryWorks() throws {
        let rig = try Rig()
        let it = try rig.addItem(0)
        rig.coordinator.startPending()
        rig.coordinator.handle(taskID: it.id, result: .response(status: 401, body: Data()))
        var cur = try #require(rig.outbox.item(it.id))
        #expect(cur.state == .failed && cur.failure == .tokenRejected)
        #expect(cur.failure!.message.contains("Scan the QR"))
        #expect(rig.outbox.pending().isEmpty, "a failed item is not retried by itself")
        #expect(rig.outbox.retry(it.id))
        cur = try #require(rig.outbox.item(it.id))
        #expect(cur.state == .sealed && cur.failure == nil)
        // Messages exist for every reason.
        for r in [SealedItem.FailureReason.conflict, .serverFull, .tooLargeForServer, .rejectedByServer, .fileMissing, .unexpected] { #expect(!r.message.isEmpty) }
        #expect(SealedItem.FailureReason.serverFull.message.contains("out of space"))
    }

    @Test func failedItemsExpireAfterSevenDays() throws {
        let rig = try Rig()
        let a = try rig.addItem(0), b = try rig.addItem(1)
        rig.coordinator.startPending()
        rig.coordinator.handle(taskID: a.id, result: .response(status: 507, body: Data()))
        rig.clock.advance(7 * 24 * 3600 - 60)
        rig.outbox.expireOldFailures()
        #expect(rig.outbox.item(a.id) != nil, "not yet")
        rig.clock.advance(120)
        rig.outbox.expireOldFailures()
        #expect(rig.outbox.item(a.id) == nil)
        #expect(!FileManager.default.fileExists(atPath: rig.outbox.sealedURL(a.id).path))
        #expect(rig.outbox.history().contains { $0.id == a.id && $0.status == .expired })
        #expect(rig.outbox.item(b.id) != nil, "an item that is still uploading is not expired")
    }

    @Test func crashRecoveryPutsOrphanedUploadsBackAndCleansLeftovers() async throws {
        let rig = try Rig()
        let a = try rig.addItem(0), b = try rig.addItem(1)
        rig.coordinator.startPending()
        #expect(rig.outbox.items().allSatisfy { $0.state == .uploading })
        // The app was killed. The system still runs the upload for `a`, but not for `b`.
        rig.transport.active = [a.id]
        // A half-written seal and a sealed file with no record.
        try Data("x".utf8).write(to: rig.dir.appendingPathComponent("outbox/.sealing-123.tmp"))
        try Data("y".utf8).write(to: rig.dir.appendingPathComponent("outbox/" + String(repeating: "e", count: 32) + ".inb"))
        // Leftovers count as old once an hour has passed.
        for n in [".sealing-123.tmp", String(repeating: "e", count: 32) + ".inb"] {
            try FileManager.default.setAttributes([.modificationDate: Date().addingTimeInterval(-7200)], ofItemAtPath: rig.dir.appendingPathComponent("outbox/" + n).path)
        }
        await rig.coordinator.recover()
        #expect(rig.outbox.item(a.id)?.state == .uploading)
        #expect(rig.outbox.item(b.id)?.state == .sealed)
        let names = try FileManager.default.contentsOfDirectory(atPath: rig.dir.appendingPathComponent("outbox").path)
        #expect(!names.contains { $0.hasPrefix(".sealing-") } && !names.contains(String(repeating: "e", count: 32) + ".inb"))
        // A record whose sealed file vanished fails with a clear reason instead of retrying forever.
        try FileManager.default.removeItem(at: rig.outbox.sealedURL(b.id))
        await rig.coordinator.recover()
        #expect(rig.outbox.item(b.id)?.failure == .fileMissing)
    }

    @Test func queueRunsTwoAtATimeAndContinuesAfterEachStored() throws {
        let rig = try Rig()
        for i in 0..<5 { try rig.addItem(i) }
        #expect(rig.coordinator.startPending().count == 2)
        #expect(rig.coordinator.startPending().isEmpty, "already two running")
        let first = rig.transport.started[0].id
        rig.coordinator.handle(taskID: first, result: .response(status: 201, body: storedBody(first)))
        #expect(rig.transport.count == 3, "the next item started when one finished")
        // A failure does not start another one by itself.
        let second = rig.transport.started[1].id
        rig.coordinator.handle(taskID: second, result: .response(status: 409, body: Data()))
        #expect(rig.transport.count == 3)
    }

    @Test func nothingStartsWithoutAPairing() throws {
        let rig = try Rig(paired: false)
        try rig.addItem(0)
        #expect(rig.coordinator.startPending().isEmpty)
        #expect(rig.outbox.items().first?.state == .sealed, "the item waits")
    }

    @Test func discardAndWipe() throws {
        let rig = try Rig()
        let a = try rig.addItem(0)
        _ = try rig.addItem(1)
        rig.coordinator.startPending()
        rig.coordinator.handle(taskID: a.id, result: .response(status: 409, body: Data()))
        rig.outbox.discard(a.id)
        #expect(rig.outbox.item(a.id) == nil && rig.outbox.history().contains { $0.id == a.id && $0.status == .discarded })
        rig.outbox.clearHistory()
        #expect(rig.outbox.history().isEmpty)
        rig.outbox.wipeAll()
        #expect(rig.outbox.items().isEmpty && rig.outbox.history().isEmpty)
        let left = (try? FileManager.default.contentsOfDirectory(atPath: rig.dir.appendingPathComponent("outbox").path)) ?? []
        #expect(left.allSatisfy { $0 == ".lock" }, "only the lock file stays: \(left)")
    }

    @Test func idsAreValidatedEverywhere() throws {
        let rig = try Rig()
        #expect(throws: OutboxError.badID) { try rig.outbox.add(id: "../../x", displayName: "x", size: 1, sealedSize: 1) }
        #expect(rig.outbox.item("../../etc/passwd") == nil)
        rig.outbox.discard("../../etc/passwd")   // must not delete or crash
        #expect(!rig.outbox.markUploading("nothing"))
    }

    @Test func historyNeverHoldsSecretsAndIsBounded() throws {
        let rig = try Rig()
        for i in 0..<20 {
            let it = try rig.addItem(i)
            rig.coordinator.startPending()
            rig.coordinator.handle(taskID: it.id, result: .response(status: 201, body: storedBody(it.id)))
        }
        let raw = try String(contentsOf: rig.dir.appendingPathComponent("outbox/history.json"), encoding: .utf8)
        let p = try pairing()
        #expect(!raw.contains(p.token) && !raw.contains(Data(p.kAuth).base64EncodedString()))
        #expect(rig.outbox.history().count == 20)
    }
}

@Suite struct SecretStoreTests {
    @Test func pairingRoundTripsAndRemoves() throws {
        let rig = try Rig(paired: false)
        #expect(rig.store.load() == nil)
        try rig.store.save(SenderPayload.parse(Fixture().payload()))
        let p = try #require(rig.store.load())
        #expect(p.label == "iphone-1" && p.server.canonical == "https://inbox.example.com" && p.kAuth == Fixture().auth)
        // Only the address, label and fingerprint are in the shared file; no secret.
        let pub = try String(contentsOf: rig.dir.appendingPathComponent("config/pairing.json"), encoding: .utf8)
        #expect(!pub.contains(p.token) && !pub.contains(Data(p.kAuth).base64EncodedString()) && !pub.contains(Data(p.inboxPub).base64EncodedString()))
        try rig.store.remove()
        #expect(rig.store.load() == nil && rig.secrets.isEmpty)
        #expect(rig.store.publicInfo() == nil)
    }

    @Test func aPartialPairingIsNeverReturned() throws {
        let rig = try Rig(paired: false)
        try rig.store.save(SenderPayload.parse(Fixture().payload()))
        try rig.secrets.write(.kAuth, Data(repeating: 1, count: 31))   // damaged
        #expect(rig.store.load() == nil)
        try rig.secrets.write(.kAuth, Data(repeating: 1, count: 32))
        #expect(rig.store.load() != nil)
        try FileManager.default.removeItem(at: rig.dir.appendingPathComponent("config/pairing.json"))
        #expect(rig.store.load() == nil)
    }

    @Test func aLockedKeychainIsNotTheSameAsNotPaired() throws {
        final class LockedKeys: SecretStoring, @unchecked Sendable {
            let inner = MemorySecrets()
            var locked = false
            func read(_ item: SecretItem) throws -> Data? {
                if locked, item != .token { throw SecretStoreError(status: -25308) }
                return try inner.read(item)
            }
            func write(_ item: SecretItem, _ data: Data) throws { try inner.write(item, data) }
            func deleteAll() throws { try inner.deleteAll() }
        }
        let dir = tempDir("locked")
        let keys = LockedKeys()
        let store = PairingStore(directory: dir, secrets: keys)
        #expect(store.state() == .notPaired)
        try store.save(SenderPayload.parse(Fixture().payload()))
        keys.locked = true
        #expect(store.state() == .keychainLocked)
        #expect(store.load() == nil)
        let info = try #require(store.loadUploadInfo(), "uploading needs only the address and the token")
        #expect(info.server.canonical == "https://inbox.example.com" && info.fingerprint == fingerprint(Fixture().pub))
        keys.locked = false
        if case .paired = store.state() {} else { Issue.record("not paired after unlock") }
        // A check value that does not belong to the key is not a pairing.
        try Data(#"{"url":"https://inbox.example.com","label":"x","fp":"00000000"}"#.utf8).write(to: dir.appendingPathComponent("pairing.json"))
        #expect(store.state() == .notPaired)
    }

    @Test func printingAPairingNeverShowsASecret() throws {
        let p = try pairing()
        let text = "\(p) \(String(reflecting: p)) \(try SenderPayload.parse(Fixture().payload()))"
        #expect(!text.contains(p.token) && !text.contains(Data(p.kAuth).base64EncodedString()))
    }

    @Test func keychainAttributesAreAsDecided() {
        #expect(KeychainSecrets.accessibility(for: .token) == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        #expect(KeychainSecrets.accessibility(for: .kAuth) == kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        #expect(KeychainSecrets.accessibility(for: .inboxPub) == kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    @Test func pingMessages() {
        #expect(UploadRequest.pingMessage(status: 204).ok)
        #expect(!UploadRequest.pingMessage(status: 401).ok && UploadRequest.pingMessage(status: 403).text.contains("QR"))
        #expect(UploadRequest.pingMessage(status: nil).text.contains("reach"))
        let s = try! ServerURL.parse("https://inbox.example.com")
        #expect(UploadRequest.ping(server: s, token: "t")?.url?.path == "/v1/ping")
    }
}
