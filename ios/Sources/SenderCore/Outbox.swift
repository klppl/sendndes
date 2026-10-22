import Foundation

/// The persisted queue of sealed files and the history of what happened to them. One file per item
/// (`<id>.json` beside `<id>.inb`), written atomically, so the app and the share extension can both use it.
public final class Outbox: @unchecked Sendable {
    private let directory: URL
    private let files: FileProtecting
    private let now: @Sendable () -> Date
    private let lock: CrossProcessLock
    private let fm = FileManager.default

    public init(directory: URL, files: FileProtecting = NoProtection(), now: @escaping @Sendable () -> Date = { Date() }) throws {
        self.directory = directory
        self.files = files
        self.now = now
        try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        try files.protect(directory)
        // The app and the share extension both change the outbox: one lock file for both processes.
        self.lock = CrossProcessLock(path: directory.appendingPathComponent(".lock").path)
    }

    public func sealedURL(_ id: String) -> URL { directory.appendingPathComponent(id + ".inb") }
    private func itemURL(_ id: String) -> URL { directory.appendingPathComponent(id + ".json") }
    private var historyURL: URL { directory.appendingPathComponent("history.json") }
    /// Where a seal in progress writes before the id is known.
    public func newTempURL() -> URL { directory.appendingPathComponent(".sealing-" + UUID().uuidString + ".tmp") }

    static func validID(_ s: String) -> Bool {
        s.utf8.count == 32 && s.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    // MARK: Items

    /// Adds a freshly sealed file (already moved to `sealedURL(id)`).
    public func add(id: String, displayName: String, size: Int64, sealedSize: Int64, pairingFP: String? = nil) throws -> SealedItem {
        guard Self.validID(id) else { throw OutboxError.badID }
        let t = now()
        let item = SealedItem(id: id, displayName: displayName, size: size, sealedSize: sealedSize, state: .sealed,
                              failure: nil, attempts: 0, createdAt: t, updatedAt: t, pairingFP: pairingFP)
        lock.lock(); defer { lock.unlock() }
        do { try write(item) } catch { try? fm.removeItem(at: itemURL(id)); throw error }
        return item
    }

    public func items() -> [SealedItem] {
        lock.lock(); defer { lock.unlock() }
        return readAllItems().sorted { ($0.createdAt, $0.id) < ($1.createdAt, $1.id) }
    }

    public func item(_ id: String) -> SealedItem? {
        lock.lock(); defer { lock.unlock() }
        return Self.validID(id) ? read(id) : nil
    }

    /// Items that should be uploaded now: sealed ones whose file is still there.
    public func pending() -> [SealedItem] {
        let t = now()
        return items().filter { $0.state == .sealed && ($0.notBefore.map { $0 <= t } ?? true) }
    }

    /// sealed -> uploading. False if the item is not in the state `sealed` (another process took it).
    @discardableResult
    public func markUploading(_ id: String, session: String = "app") -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard var it = read(id), it.state == .sealed else { return false }
        guard fm.fileExists(atPath: sealedURL(id).path) else {
            it.state = .failed; it.failure = .fileMissing; it.updatedAt = now()
            try? write(it); appendHistory(it, .failed)
            return false
        }
        it.state = .uploading; it.attempts += 1; it.updatedAt = now(); it.session = session; it.notBefore = nil
        try? write(it)
        return true
    }

    /// Records what the server (or the network) said. Stored deletes the sealed file at once.
    public func apply(_ outcome: UploadOutcome, to id: String) {
        lock.lock(); defer { lock.unlock() }
        guard var it = read(id) else { return }
        it.updatedAt = now()
        switch outcome {
        case .stored:
            // History first, then the record, then the sealed file: a crash in between never shows a stored file as lost.
            it.state = .stored; it.failure = nil
            appendHistory(it, .stored)
            try? fm.removeItem(at: itemURL(id))
            try? fm.removeItem(at: sealedURL(id))
            return
        case .retryLater:
            // Wait longer after each failed attempt (30 s, 1 min, 2 min ... at most an hour).
            let wait = min(3600, 30 * pow(2, Double(max(0, min(it.attempts - 1, 7)))))
            it.state = .sealed; it.notBefore = now().addingTimeInterval(wait)
        case .failed(let reason):
            it.state = .failed; it.failure = reason
            appendHistory(it, .failed)
        }
        try? write(it)
    }

    /// failed -> sealed again, same file, same id.
    @discardableResult
    public func retry(_ id: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard var it = read(id), it.state == .failed, fm.fileExists(atPath: sealedURL(id).path) else { return false }
        it.state = .sealed; it.failure = nil; it.updatedAt = now()
        try? write(it)
        return true
    }

    /// Removes an item's record and file without a history entry (a seal that failed half way).
    public func discardQuietly(_ id: String) {
        lock.lock(); defer { lock.unlock() }
        guard Self.validID(id) else { return }
        try? fm.removeItem(at: sealedURL(id))
        try? fm.removeItem(at: itemURL(id))
    }

    public func discard(_ id: String) {
        lock.lock(); defer { lock.unlock() }
        guard Self.validID(id) else { return }
        if let it = read(id) { appendHistory(it, .discarded) }
        try? fm.removeItem(at: sealedURL(id))
        try? fm.removeItem(at: itemURL(id))
    }

    // MARK: Recovery and housekeeping

    /// After a crash or a relaunch: items marked `uploading` whose upload task no longer exists go back to
    /// `sealed`; they will be sent again (same bytes, same id). Stray temp files and orphans are removed.
    public func recover(activeTaskIDs: Set<String>, ownSession: String = "app") {
        lock.lock(); defer { lock.unlock() }
        let t = now()
        for it in readAllItems() {
            var it = it
            // Only this process's own session is known here. An upload owned by the other session (the share
            // extension's) is left alone unless it has been "running" for hours, which means it is gone.
            let mine = (it.session ?? ownSession) == ownSession
            let stale = t.timeIntervalSince(it.updatedAt) > 2 * 3600
            if it.state == .uploading, !activeTaskIDs.contains(it.id), mine || stale {
                it.state = .sealed; it.updatedAt = t; try? write(it)
            }
            if (it.state == .sealed || it.state == .uploading), !fm.fileExists(atPath: sealedURL(it.id).path) {
                it.state = .failed; it.failure = .fileMissing; it.updatedAt = now(); try? write(it)
                appendHistory(it, .failed)
            }
        }
        let known = Set(readAllItems().map(\.id))
        // The other process may be sealing right now: only old leftovers are removed.
        func age(_ u: URL) -> TimeInterval {
            let m = (try? u.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate
            return m.map { t.timeIntervalSince($0) } ?? .infinity
        }
        for u in (try? fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [] {
            let n = u.lastPathComponent
            if n.hasPrefix(".sealing-"), age(u) > 3600 { try? fm.removeItem(at: u); continue }
            if n.hasSuffix(".inb"), !known.contains(String(n.dropLast(4))), age(u) > 600 { try? fm.removeItem(at: u) }
        }
    }

    /// Failed items older than seven days are discarded.
    public func expireOldFailures() {
        lock.lock(); defer { lock.unlock() }
        let t = now()
        for it in readAllItems() where it.state == .failed && t.timeIntervalSince(it.updatedAt) >= SenderLimits.failedItemLifetime {
            appendHistory(it, .expired)
            try? fm.removeItem(at: sealedURL(it.id))
            try? fm.removeItem(at: itemURL(it.id))
        }
    }

    /// Everything: sealed files, items and history ("Remove configuration").
    public func wipeAll() {
        lock.lock(); defer { lock.unlock() }
        for u in (try? fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? [] where u.lastPathComponent != ".lock" { try? fm.removeItem(at: u) }
    }

    // MARK: History

    public func history() -> [HistoryEntry] {
        lock.lock(); defer { lock.unlock() }
        return readHistory().sorted { ($0.date, $0.id) > ($1.date, $1.id) }
    }

    public func clearHistory() {
        lock.lock(); defer { lock.unlock() }
        try? fm.removeItem(at: historyURL)
    }

    // MARK: Files

    private func readAllItems() -> [SealedItem] {
        let urls = (try? fm.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)) ?? []
        return urls.compactMap { u in
            let n = u.lastPathComponent
            guard n.hasSuffix(".json"), n != "history.json", Self.validID(String(n.dropLast(5))) else { return nil }
            return read(String(n.dropLast(5)))
        }
    }

    private func read(_ id: String) -> SealedItem? {
        guard let d = try? Data(contentsOf: itemURL(id)), let it = try? JSONDecoder.outbox.decode(SealedItem.self, from: d), it.id == id else { return nil }
        return it
    }

    private func write(_ it: SealedItem) throws {
        try JSONEncoder.outbox.encode(it).write(to: itemURL(it.id), options: .atomic)
        try files.protect(itemURL(it.id))
    }

    private func readHistory() -> [HistoryEntry] {
        guard let d = try? Data(contentsOf: historyURL) else { return [] }
        return (try? JSONDecoder.outbox.decode([HistoryEntry].self, from: d)) ?? []
    }

    private func appendHistory(_ it: SealedItem, _ status: HistoryEntry.Status) {
        var h = readHistory()
        h.removeAll { $0.id == it.id }
        h.append(HistoryEntry(id: it.id, name: it.displayName, size: it.size, status: status, date: now()))
        if h.count > 500 { h = Array(h.suffix(500)) }
        if let d = try? JSONEncoder.outbox.encode(h) {
            try? d.write(to: historyURL, options: .atomic)
            try? files.protect(historyURL)
        }
    }
}

public enum OutboxError: Error, Equatable, Sendable { case badID }

private extension JSONEncoder {
    static var outbox: JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e }
}
private extension JSONDecoder {
    static var outbox: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }
}

/// What an upload attempt came to.
public enum UploadOutcome: Equatable, Sendable {
    case stored
    case retryLater
    case failed(SealedItem.FailureReason)

    /// Server answers (SPEC 8): 200 and 201 are stored; 401 and 403 are a rejected token; 409 a conflicting
    /// file; 507 a full server; 413 too large; 429, 408 and every 5xx a later retry; the rest a refusal.
    public static func classify(status: Int, body: Data = Data(), forID id: String) -> UploadOutcome {
        switch status {
        // Stored only if the answer really is ndesd's `{"id":"<this id>"}`: a login page or a redirect target that
        // answers 200 must never make a file look delivered.
        case 200, 201: return storedBody(body, id: id) ? .stored : .failed(.unexpected)
        case 401: return .failed(.tokenRejected)
        case 403: return .failed(.tokenRejected)
        case 409: return .failed(.conflict)
        case 413: return .failed(.tooLargeForServer)
        case 507: return .failed(.serverFull)
        case 408, 429: return .retryLater
        case 500...599: return .retryLater
        case 400...499: return .failed(.rejectedByServer)
        default: return .failed(.unexpected)
        }
    }
}

extension UploadOutcome {
    static func storedBody(_ body: Data, id: String) -> Bool {
        guard body.count <= 256, let o = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any],
              o.count == 1, o["id"] as? String == id else { return false }
        return true
    }
}

/// An exclusive lock on a file, held across processes (the app and the share extension) and threads.
final class CrossProcessLock: @unchecked Sendable {
    private let inner = NSLock()
    private let path: String
    private var fd: Int32 = -1

    init(path: String) { self.path = path }

    func lock() {
        inner.lock()
        fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        if fd >= 0 { while flock(fd, LOCK_EX) != 0 && errno == EINTR {} }
    }

    func unlock() {
        if fd >= 0 { flock(fd, LOCK_UN); close(fd); fd = -1 }
        inner.unlock()
    }
}
