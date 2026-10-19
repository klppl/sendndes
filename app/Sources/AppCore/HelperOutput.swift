import Foundation

private let idPattern = try! NSRegularExpression(pattern: "^[0-9a-f]{32}$")

func isValidID(_ s: String) -> Bool {
    idPattern.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
}

/// One line of `valv ... --json`. Unknown keys are ignored; wrong types make the
/// whole line invalid.
struct RawRecord: Decodable {
    var type: String
    var id: String?
    var size: Int64?
    var mtime: Int64?
    var name: String?
    var dir: String?
    var code: String?
    var files: Int?
    var problems: Int?
    var ingested: Int?
    var already: Int?
    var failed: Int?
    var delete_failed: Int?
    var item: Bool?
}

func decodeRaw(_ line: Data) -> RawRecord? {
    try? JSONDecoder().decode(RawRecord.self, from: line)
}

public struct FileEntry: Identifiable, Hashable {
    public let id: String
    public let size: Int64
    public let mtime: Date
    public let name: String   // already sanitized for display
    public let dir: String    // already sanitized for display
    public var shortID: String { String(id.prefix(8)) }
}

public struct ListingResult {
    public var entries: [FileEntry] = []
    public var problems = 0
    public var invalidRecords = 0
    public var endSeen = false
    /// Code of the final `error` record, if any.
    public var errorCode: String?
    public var complete: Bool { endSeen && errorCode == nil && invalidRecords == 0 }
}

/// Collects `valv ls --json` output. `feed` returns false to stop the helper.
public final class ListingAccumulator {
    public static let maxFiles = 200_000
    public private(set) var result = ListingResult()
    private let lock = NSLock()

    public init() {}

    public func feed(_ line: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let r = decodeRaw(line) else { result.invalidRecords += 1; return true }
        switch r.type {
        case "file":
            guard let id = r.id, isValidID(id), let size = r.size, size >= 0, let mt = r.mtime,
                  let name = r.name, let dir = r.dir else { result.invalidRecords += 1; return true }
            if result.entries.count >= ListingAccumulator.maxFiles { return false }
            result.entries.append(FileEntry(
                id: id, size: size, mtime: Date(timeIntervalSince1970: Double(mt) / 1e9),
                name: DisplayName.sanitize(name), dir: dir.isEmpty ? "" : DisplayName.sanitize(dir)))
        case "warning":
            break // the final `end` record carries the problem count
        case "end":
            guard let p = r.problems, r.files != nil else { result.invalidRecords += 1; return true }
            result.endSeen = true
            result.problems = p
        case "error":
            result.errorCode = r.code ?? "other"
        default:
            result.invalidRecords += 1
        }
        return true
    }
}

public enum PullKind: String {
    case ingested, alreadyIngested = "already-ingested", notAuthentic = "not-authentic", conflict, error
}

public struct PullItem: Identifiable, Hashable {
    public let id: String      // 32-hex file id, or a synthetic value for an id-less error
    public let kind: PullKind
}

public struct PullResult {
    public var started = false
    public var items: [PullItem] = []
    public var invalidRecords = 0
    public var endSeen = false
    public var ingested = 0, already = 0, failed = 0, deleteFailed = 0
    public var errorCode: String?
    public var complete: Bool { started && endSeen && errorCode == nil && invalidRecords == 0 }
}

/// Collects `valv pull --json` output. `onStarted` runs on the helper's `started` record
/// (the token file has been read; the caller deletes it).
public final class PullAccumulator {
    public static let maxItems = 200_000
    public private(set) var result = PullResult()
    private let lock = NSLock()
    private let onStarted: @Sendable () -> Void

    public init(onStarted: @escaping @Sendable () -> Void) { self.onStarted = onStarted }

    public func feed(_ line: Data) -> Bool {
        lock.lock()
        var fireStarted = false
        let keepGoing = process(line, &fireStarted)
        lock.unlock()
        if fireStarted { onStarted() }
        return keepGoing
    }

    private func process(_ line: Data, _ fireStarted: inout Bool) -> Bool {
        guard let r = decodeRaw(line) else { result.invalidRecords += 1; return true }
        switch r.type {
        case "started":
            if !result.started { result.started = true; fireStarted = true }
        case "ingested", "already-ingested", "not-authentic", "conflict":
            guard let id = r.id, isValidID(id), let kind = PullKind(rawValue: r.type) else { result.invalidRecords += 1; return true }
            return add(PullItem(id: id, kind: kind))
        case "error":
            if r.id != nil || r.item == true {
                // Per-file error; the id may be missing when the server sent a bad one.
                if let id = r.id, isValidID(id) { return add(PullItem(id: id, kind: .error)) }
                result.failed += 0
                return add(PullItem(id: "invalid-\(result.items.count)", kind: .error))
            }
            result.errorCode = r.code ?? "other"
        case "end":
            guard let a = r.ingested, let b = r.already, let c = r.failed, let d = r.delete_failed else { result.invalidRecords += 1; return true }
            result.endSeen = true
            (result.ingested, result.already, result.failed, result.deleteFailed) = (a, b, c, d)
        default:
            result.invalidRecords += 1
        }
        return true
    }

    private func add(_ item: PullItem) -> Bool {
        if result.items.count >= PullAccumulator.maxItems { return false }
        result.items.append(item)
        return true
    }
}
