import Foundation

public struct UploadTask: Sendable {
    public let id: String
    public let fileURL: URL
    public let request: URLRequest
}

public enum TransportResult: Sendable, Equatable {
    case response(status: Int, body: Data)
    case networkError
    case cancelled
    /// The request was redirected (background sessions follow redirects on their own): the answer is not the server's.
    case redirected
}

/// Starts uploads. The real one is a background URLSession (`BackgroundUploader`); tests use a fake.
public protocol UploadTransport: AnyObject, Sendable {
    func start(_ task: UploadTask)
    /// Ids of the uploads the system is still running (after a relaunch).
    func activeTaskIDs() async -> Set<String>
}

/// Glue between the outbox, the pairing and the transport. The state machine itself lives in `Outbox`.
public final class UploadCoordinator: @unchecked Sendable {
    private let outbox: Outbox
    private let pairings: PairingStore
    private let transport: UploadTransport
    private let wifiOnly: @Sendable () -> Bool
    private let maxParallel: Int
    private let session: String

    /// `maxParallel` stays at or below the server's per-token limit (2) so a share of 20 files is sent two at a
    /// time and never answered with 429.
    public init(outbox: Outbox, pairings: PairingStore, transport: UploadTransport, wifiOnly: @escaping @Sendable () -> Bool = { false }, maxParallel: Int = 2, session: String = "app") {
        self.session = session
        self.maxParallel = max(1, maxParallel)
        self.outbox = outbox
        self.pairings = pairings
        self.transport = transport
        self.wifiOnly = wifiOnly
    }

    /// Housekeeping at launch: forget uploads the system no longer runs, expire old failures.
    public func recover() async {
        outbox.recover(activeTaskIDs: await transport.activeTaskIDs(), ownSession: session)
        outbox.expireOldFailures()
    }

    /// Starts every sealed item. Safe to call at any time (launch, foreground, after sharing, Retry).
    /// Returns the ids it started. Without a pairing nothing starts and the items wait.
    @discardableResult
    public func startPending() -> [String] {
        // Only the address and the token are needed to upload, so this works while the phone is locked.
        guard let p = pairings.loadUploadInfo() else { return [] }
        var started: [String] = []
        var running = outbox.items().filter { $0.state == .uploading }.count
        for it in outbox.pending() {
            if running >= maxParallel { break }
            // A file is only ever sent to the server it was locked for.
            if let fp = it.pairingFP, fp != p.fingerprint { outbox.apply(.failed(.pairedElsewhere), to: it.id); continue }
            guard let req = UploadRequest.make(server: p.server, id: it.id, token: p.token, length: it.sealedSize, allowsCellular: !wifiOnly()) else { continue }
            guard outbox.markUploading(it.id, session: session) else { continue }
            transport.start(UploadTask(id: it.id, fileURL: outbox.sealedURL(it.id), request: req))
            started.append(it.id)
            running += 1
        }
        return started
    }

    /// An upload finished (or failed): record it. After a success the next waiting item starts; after a
    /// failure or a retry-later nothing starts by itself (no retry loop): the app tries again on its next launch,
    /// when it comes to the front, or on Retry.
    public func handle(taskID: String, result: TransportResult) {
        if Self.record(result, for: taskID, in: outbox) == .stored { startPending() }
    }

    /// Applies an upload result to the outbox, from whichever session it came. Never starts anything.
    @discardableResult
    public static func record(_ result: TransportResult, for taskID: String, in outbox: Outbox) -> UploadOutcome {
        let outcome: UploadOutcome
        switch result {
        case .response(let status, let body): outcome = .classify(status: status, body: body, forID: taskID)
        case .redirected: outcome = .failed(.unexpected)   // something in front of the server answered; the file is kept
        case .networkError, .cancelled: outcome = .retryLater
        }
        outbox.apply(outcome, to: taskID)
        return outcome
    }
}
