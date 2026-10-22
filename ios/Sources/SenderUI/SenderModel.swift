import Foundation
import Observation
import SenderCore

/// What the app shows and does. All rules live in SenderCore; this holds screen state.
@MainActor @Observable
public final class SenderModel {
    public enum Screen: Equatable { case welcome, scanning, confirm(SenderPayload), waiting(code: String, host: String), home }

    public private(set) var screen: Screen
    public private(set) var items: [SealedItem] = []
    public private(set) var history: [HistoryEntry] = []
    public private(set) var pairing: Pairing?
    /// Saved address and name even while the Keychain is locked (the keys are not readable then).
    public private(set) var pairedInfo: PublicPairing?
    public private(set) var keychainLocked = false
    public var settings: SenderSettings
    public var pairingError: String?
    public var pingResult: (ok: Bool, text: String)?
    public private(set) var pinging = false
    public private(set) var uploader: BackgroundUploader?

    public let env: SenderEnvironment
    private let wifi = FlagBox()
    let secrets: SecretStoring
    let outbox: Outbox
    let store: PairingStore
    private var coordinator: UploadCoordinator?
    private let files: FileProtecting = StandardFileProtection()

    public init(env: SenderEnvironment, secrets: SecretStoring? = nil) throws {
        self.env = env
        let sec = secrets ?? KeychainSecrets(accessGroup: env.keychainGroup)
        self.secrets = sec
        outbox = try Outbox(directory: env.outboxDirectory, files: StandardFileProtection())
        store = PairingStore(directory: env.configDirectory, secrets: sec, files: StandardFileProtection())
        let loaded = SenderSettings.load(env)
        settings = loaded
        screen = .welcome
        wifi.value = loaded.wifiOnly
        reloadPairing()
        screen = pairedInfo == nil ? .welcome : .home
        refresh()
    }

    /// Reads the pairing again. A phone that is still locked (a background launch) is not "not paired".
    func reloadPairing() {
        pairedInfo = store.publicInfo()
        switch store.state() {
        case .paired(let p): pairing = p; keychainLocked = false
        case .keychainLocked: pairing = nil; keychainLocked = true
        case .notPaired: pairing = nil; keychainLocked = false; pairedInfo = nil
        }
        if case .welcome = screen, pairedInfo != nil { screen = .home }
    }


    /// Starts the background session. Safe to call again (it only ever makes one).
    public func startUploads() {
        guard uploader == nil else { coordinator?.startPending(); refresh(); return }
        let box = ResultBox()
        let up = BackgroundUploader(identifier: env.uploadSessionIdentifier, groupIdentifier: env.appGroup) { id, result in
            Task { @MainActor in box.model?.handle(id: id, result: result) }
        }
        box.model = self
        resultBox = box
        uploader = up
        let flag = wifi
        let c = UploadCoordinator(outbox: outbox, pairings: store, transport: up, wifiOnly: { flag.value })
        coordinator = c
        Task {
            await c.recover()
            c.startPending()
            refresh()
        }
    }

    private final class ResultBox: @unchecked Sendable { weak var model: SenderModel? }
    private var resultBox: ResultBox?

    func handle(id: String, result: TransportResult) {
        // Whichever session the result came from: record it, then let the main coordinator continue the queue.
        if UploadCoordinator.record(result, for: id, in: outbox) == .stored { coordinator?.startPending() }
        refresh()
    }

    private var extraUploaders: [String: BackgroundUploader] = [:]

    /// iOS woke the app for events of a background session (the share extension's own session has another
    /// identifier). A session needs a delegate with the same identifier to hear them; `completion` tells the
    /// system we are done.
    public func handleBackgroundEvents(identifier: String, completion: @escaping @Sendable () -> Void) {
        if identifier == env.uploadSessionIdentifier { startUploads(); uploader?.setFinishedEventsHandler(completion); return }
        let box = resultBox ?? ResultBox()
        box.model = self
        resultBox = box
        // The session is released once the system has delivered everything, so the next extension run can own the identifier.
        let holder = UploaderHolder()
        let up = BackgroundUploader(identifier: identifier, groupIdentifier: env.appGroup, onFinishedEvents: {
            completion()
            Task { @MainActor in holder.uploader?.finish() }
        }) { id, result in
            Task { @MainActor in box.model?.handle(id: id, result: result) }
        }
        holder.uploader = up
        extraUploaders[identifier] = up
    }

    private final class UploaderHolder: @unchecked Sendable { var uploader: BackgroundUploader? }

    public func refresh() {
        items = outbox.items()
        history = outbox.history()
    }

    // MARK: Pairing

    public func beginScanning() { pairingError = nil; screen = .scanning }
    public func cancelPairing() { pairingError = nil; screen = pairing == nil ? .welcome : .home }

    /// A scanned QR code. Nothing is saved until the owner confirms host and check value.
    public func scanned(_ text: String) {
        do {
            screen = .confirm(try SenderPayload.parse(text))
            pairingError = nil
        } catch let e as SenderPayload.Failure {
            pairingError = Self.message(for: e)
            screen = pairing == nil ? .welcome : .home
        } catch {
            pairingError = "That is not a send n*des pairing code."
            screen = pairing == nil ? .welcome : .home
        }
    }

    private var pairTask: Task<Void, Never>?
    var pairPollInterval: TimeInterval = 2

    /// A pairing code without a token: ask the server to connect this phone. The owner compares the code shown here
    /// with the one on the Mac and approves; the token then arrives here and goes straight into the Keychain.
    func beginServerPairing(_ p: SenderPayload) {
        guard pairTask == nil else { return }
        screen = .waiting(code: "", host: p.server.host)
        let interval = pairPollInterval
        pairTask = Task { [weak self] in
            defer { self?.pairTask = nil }
            let fail: (String) -> Void = { msg in self?.pairingError = msg; self?.screen = self?.pairedInfo == nil ? .welcome : .home }
            let req: PairRequest
            switch await PairClient.request(server: p.server, label: p.label) {
            case .failure(let f): fail(f.message); return
            case .success(let r): req = r
            }
            self?.screen = .waiting(code: req.spacedCode, host: p.server.host)
            let deadline = Date().addingTimeInterval(5 * 60)
            var failures = 0
            while !Task.isCancelled, Date() < deadline {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                if Task.isCancelled { return }
                switch await PairClient.status(server: p.server, request: req) {
                case .success(.pending): failures = 0
                case .success(.approved(let token)):
                    guard let self else { return }
                    do {
                        try self.store.save(p.withToken(token))
                        self.reloadPairing()
                        self.pingResult = nil
                        self.screen = .home
                        self.startUploads()
                    } catch { fail("The pairing could not be saved on this phone.") }
                    return
                case .failure(let f):
                    if f == .unreachable || f == .busy { failures += 1; if failures < 5 { continue } }
                    fail(f.message); return
                }
            }
            if !Task.isCancelled { fail(PairFailure.expired.message) }
        }
    }

    public func cancelServerPairing() {
        pairTask?.cancel()
        pairTask = nil
        screen = pairedInfo == nil ? .welcome : .home
    }

    public func confirm(_ p: SenderPayload) {
        if p.token == nil { beginServerPairing(p); return }
        do {
            try store.save(p)
            reloadPairing()
            pingResult = nil
            screen = .home
            startUploads()
        } catch {
            pairingError = "The pairing could not be saved on this phone."
            screen = .welcome
        }
    }

    static func message(for f: SenderPayload.Failure) -> String {
        switch f {
        case .notAPairingCode: return "That is not a send n*des pairing code."
        case .tooLarge, .badEncoding, .badJSON: return "That pairing code is damaged. Make a new one on your Mac."
        case .unsupportedVersion: return "This pairing code is from a newer version. Update send n*des."
        case .badField, .fingerprintMismatch: return "That pairing code is damaged. Make a new one on your Mac."
        case .badURL(let u):
            switch u {
            case .notHTTPS: return "The server address must start with https://. Set up https first (see the Cloudflare guide)."
            default: return "The server address in that code is not accepted."
            }
        }
    }

    // MARK: Settings and removal

    public func saveSettings() {
        settings.folder = FileNames.validateFolder(settings.folder) ?? SenderLimits.defaultFolder
        wifi.value = settings.wifiOnly
        settings.save(env)
    }

    public func folderIsValid(_ s: String) -> Bool { FileNames.validateFolder(s) != nil }

    /// "Remove configuration": the Keychain items, the saved address, every sealed file, the history.
    public func removeConfiguration() {
        // Stop every upload first (both sessions, even ones this process has not opened), so nothing keeps sending
        // with the token that is about to be deleted.
        uploader?.cancelAllAndInvalidate(); uploader = nil; coordinator = nil
        for (_, u) in extraUploaders { u.cancelAllAndInvalidate() }
        extraUploaders = [:]
        for id in [env.uploadSessionIdentifier, env.uploadSessionIdentifier + ".share"] {
            BackgroundUploader(identifier: id, groupIdentifier: env.appGroup) { _, _ in }.cancelAllAndInvalidate()
        }
        outbox.wipeAll()
        sweepTemporaryFiles()
        try? FileManager.default.removeItem(at: env.settingsURL)
        settings = SenderSettings()
        wifi.value = false
        pingResult = nil
        do {
            try store.remove()
        } catch {
            pairingError = "The keys could not be deleted from the Keychain. Remove the app's data in Settings, or delete the app."
            reloadPairing()
            refresh()
            return
        }
        pairing = nil
        pairedInfo = nil
        keychainLocked = false
        screen = .welcome
        refresh()
    }

    /// Plaintext leftovers of text and link shares (a crash could leave one).
    func sweepTemporaryFiles() {
        let tmp = FileManager.default.temporaryDirectory
        for u in (try? FileManager.default.contentsOfDirectory(at: tmp, includingPropertiesForKeys: nil)) ?? [] where u.lastPathComponent.hasPrefix("share-") {
            try? FileManager.default.removeItem(at: u)
        }
    }

    // MARK: Test connection and queue actions

    public func testConnection() {
        // Address and token are enough (they stay readable while the phone is locked).
        guard let p = store.loadUploadInfo(), let req = UploadRequest.ping(server: p.server, token: p.token), !pinging else { return }
        pinging = true
        pingResult = nil
        Task {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 15
            let session = URLSession(configuration: cfg, delegate: NoRedirect(), delegateQueue: nil)
            defer { session.finishTasksAndInvalidate() }
            var status: Int?
            // The answer is 204 with no body; anything bigger is not looked at.
            if let (bytes, resp) = try? await session.bytes(for: req) {
                status = (resp as? HTTPURLResponse)?.statusCode
                bytes.task.cancel()
            }
            pingResult = UploadRequest.pingMessage(status: status)
            pinging = false
        }
    }

    public func retry(_ id: String) { if outbox.retry(id) { startUploads() }; refresh() }
    public func discard(_ id: String) { outbox.discard(id); refresh() }
    public func clearHistory() { outbox.clearHistory(); refresh() }

    /// Called when the app comes to the front.
    public func didBecomeActive() {
        reloadPairing()
        outbox.expireOldFailures()
        sweepTemporaryFiles()
        if pairedInfo != nil { startUploads() }
        refresh()
    }
}

final class NoRedirect: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}

/// A flag that closures on other threads can read.
final class FlagBox: @unchecked Sendable {
    private let lock = NSLock()
    private var v = false
    var value: Bool { get { lock.lock(); defer { lock.unlock() }; return v } set { lock.lock(); v = newValue; lock.unlock() } }
}
