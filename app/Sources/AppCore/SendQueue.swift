import Foundation
import Observation

public enum SendState: Equatable {
    case waiting, sending, sent, failed(String)
}

public struct SendItem: Identifiable, Equatable {
    public let id = UUID()
    public let spec: UploadSpec
    public let displayName: String   // sanitized
    public var state: SendState = .waiting
    public static func == (a: SendItem, b: SendItem) -> Bool { a.id == b.id && a.state == b.state }
}

/// Sequential uploads with per-file state. No automatic retry: "Retry" resends from the start (a lost
/// response can leave a duplicate in the vault). 401, 429, 507 and "can't reach the server" pause the
/// whole queue; 400, 413 and local problems fail only that file.
@MainActor @Observable
public final class SendQueue {
    public private(set) var items: [SendItem] = []
    public private(set) var pausedReason: String?
    public private(set) var notes: [String] = []
    public private(set) var running = false

    private let client: ServerClient
    public var credentials: () -> (ServerURL, String)?
    private var activity: NSObjectProtocol?

    public init(client: ServerClient = ServerClient(), credentials: @escaping () -> (ServerURL, String)?) {
        self.client = client
        self.credentials = credentials
    }

    public var isIdle: Bool { !running }

    public func add(urls: [URL]) {
        let exp = InputExpander.expand(urls)
        notes = []
        if exp.tooMany { notes.append("More than \(InputExpander.maxFiles) files: nothing beyond the first \(InputExpander.maxFiles) was added.") }
        if !exp.skipped.isEmpty {
            notes.append("Skipped (not regular files): " + exp.skipped.prefix(5).joined(separator: ", ") + (exp.skipped.count > 5 ? " …" : ""))
        }
        for s in exp.specs {
            let shown = DisplayName.sanitize(s.dir.isEmpty ? s.name : s.dir + "/" + s.name)
            items.append(SendItem(spec: s, displayName: shown))
        }
        start()
    }

    public func retry(_ id: UUID) {
        guard let i = items.firstIndex(where: { $0.id == id }), case .failed = items[i].state else { return }
        items[i].state = .waiting
        start()
    }

    public func resume() {
        pausedReason = nil
        start()
    }

    public func clearFinished() {
        items.removeAll { $0.state == .sent }
    }

    private func start() {
        guard !running, pausedReason == nil, items.contains(where: { $0.state == .waiting }) else { return }
        running = true
        activity = ProcessInfo.processInfo.beginActivity(options: .idleSystemSleepDisabled, reason: "Sending files")
        Task { await self.loop() }
    }

    /// Waits until the queue has nothing left to do (for tests).
    public func waitUntilIdle() async {
        while running { try? await Task.sleep(nanoseconds: 20_000_000) }
    }

    private func loop() async {
        defer {
            running = false
            if let a = activity { ProcessInfo.processInfo.endActivity(a); activity = nil }
        }
        while pausedReason == nil, let i = items.firstIndex(where: { $0.state == .waiting }) {
            guard let (server, token) = credentials() else {
                pausedReason = "Set the server address and token in Settings first."
                return
            }
            items[i].state = .sending
            let spec = items[i].spec
            let result = await client.upload(file: spec.url, name: spec.name, dir: spec.dir, server: server, token: token)
            guard let j = items.firstIndex(where: { $0.spec == spec && $0.state == .sending }) else { continue }
            switch result {
            case .success:
                items[j].state = .sent
            case .failure(let f) where f.pausesQueue:
                items[j].state = .waiting
                pausedReason = f.message
            case .failure(let f):
                items[j].state = .failed(f.message)
            }
        }
    }
}
