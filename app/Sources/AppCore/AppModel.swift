import Foundation
import Observation

/// Holds the passphrase between unlock and lock. A Swift String cannot be wiped; dropping the
/// reference is the most that can be done.
final class PassphraseBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?
    func get() -> String? { lock.lock(); defer { lock.unlock() }; return value }
    func set(_ v: String?) { lock.lock(); value = v; lock.unlock() }
}

public enum LockState: Equatable { case noFolder, locked, unlocking, unlocked }

@MainActor @Observable
public final class AppModel {
    // Settings
    public private(set) var serverURLText: String
    public private(set) var vaultPath: String
    public private(set) var tokenIsSet: Bool

    // Vault
    public private(set) var lockState: LockState
    public private(set) var entries: [FileEntry] = []
    public private(set) var listingProblems = 0
    public private(set) var listingStale = false
    public private(set) var busy = false           // a helper job is running
    public var vaultMessage: String?

    // Pull
    public private(set) var pullRunning = false
    public private(set) var pullItems: [PullItem] = []
    public private(set) var pullSummary: String?
    public private(set) var pullMessage: String?

    // Vault creation
    public private(set) var creating = false
    public private(set) var recoveryKey: String?   // shown once, until the user confirms it is stored
    public var createMessage: String?

    public let sendQueue: SendQueue

    private let defaults: UserDefaults
    private let secrets: SecretStoring
    private let runner: HelperRunner
    private let tempBase: String?
    private let box = PassphraseBox()
    private var generation = 0

    public static let urlKey = "serverURL"
    public static let vaultKey = "vaultPath"

    public init(defaults: UserDefaults = .standard, secrets: SecretStoring, runner: HelperRunner, tempBase: String? = nil) {
        self.defaults = defaults
        self.secrets = secrets
        self.runner = runner
        self.tempBase = tempBase
        let url = defaults.string(forKey: Self.urlKey) ?? ""
        let vault = defaults.string(forKey: Self.vaultKey) ?? ""
        serverURLText = url
        vaultPath = vault
        tokenIsSet = false
        lockState = vault.isEmpty ? .noFolder : .locked
        sendQueue = SendQueue(credentials: { nil })
        sendQueue.credentials = { [weak self] in self?.credentials() }
        tokenIsSet = secrets.token() != nil
    }

    /// The server URL (validated again) and token for an upload or pull.
    func credentials() -> (ServerURL, String)? {
        guard let u = try? URLPolicy.parse(serverURLText), let t = secrets.token() else { return nil }
        return (u, t)
    }

    // MARK: Settings

    public enum SettingsError: Error, Equatable {
        case badURL(String), badToken, tokenRequiredForNewHost, keychain
        public var message: String {
            switch self {
            case .badURL(let m): return m
            case .badToken: return "The token must be 32–512 printable characters without spaces."
            case .tokenRequiredForNewHost: return "The server address changed to a different host; enter the token again."
            case .keychain: return "The token could not be saved in the Keychain."
            }
        }
    }

    /// `token` nil keeps the stored one. A different host needs the token typed again.
    public func saveSettings(serverURL: String, token: String?, vaultPath newVault: String) throws {
        let trimmed = serverURL.trimmingCharacters(in: .whitespaces)
        let parsed: ServerURL
        do { parsed = try URLPolicy.parse(trimmed) } catch let e as URLPolicyError { throw SettingsError.badURL(e.message) }
        if let t = token, !t.isEmpty {
            guard (32...512).contains(t.utf8.count), t.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else { throw SettingsError.badToken }
        }
        let oldHost = (try? URLPolicy.parse(serverURLText))?.host
        let hostChanged = oldHost != parsed.host
        if hostChanged && secrets.token() != nil && (token ?? "").isEmpty { throw SettingsError.tokenRequiredForNewHost }
        if let t = token, !t.isEmpty {
            do { try secrets.setToken(t) } catch { throw SettingsError.keychain }
        } else if hostChanged {
            secrets.deleteToken()
        }
        serverURLText = parsed.canonical
        defaults.set(parsed.canonical, forKey: Self.urlKey)
        tokenIsSet = secrets.token() != nil
        if newVault != vaultPath {
            lock()
            vaultPath = newVault
            defaults.set(newVault, forKey: Self.vaultKey)
            lockState = newVault.isEmpty ? .noFolder : .locked
        }
    }

    // MARK: Create a vault

    public static let minPassphraseCharacters = 12

    /// Runs `valv init` in an empty (or new) folder, then unlocks the new vault. The recovery key is kept in
    /// `recoveryKey` until `acknowledgeRecoveryKey()`; the vault already exists at that point.
    public func createVault(at folder: String, passphrase: String, repeated: String) async {
        guard lockState == .noFolder || lockState == .locked, !creating, recoveryKey == nil else { return }
        createMessage = nil
        guard !folder.isEmpty else { createMessage = "Choose a folder for the vault."; return }
        guard passphrase == repeated else { createMessage = "The two passphrases are different."; return }
        guard !passphrase.contains("\n"), !passphrase.contains("\r") else {
            createMessage = "The passphrase can't contain line breaks."; return
        }
        guard passphrase.precomposedStringWithCanonicalMapping.unicodeScalars.count >= Self.minPassphraseCharacters else {
            createMessage = "Use at least \(Self.minPassphraseCharacters) characters."; return
        }
        creating = true
        defer { creating = false }
        let acc = InitAccumulator()
        do {
            let o = try await runner.run(args: ["init", "--json", "--passphrase-stdin", "--", folder],
                                         passphrase: { passphrase }, onLine: { acc.feed($0) })
            guard !o.outputViolation, acc.endSeen, acc.errorCode == nil, let key = acc.recoveryKey else {
                createMessage = acc.errorCode == "not-empty"
                    ? "That folder isn't empty. Choose or create an empty folder."
                    : "The vault could not be created."
                return
            }
            recoveryKey = key
        } catch {
            createMessage = Self.message(for: error)
            return
        }
        setVaultPath(folder)
        await unlock(passphrase: passphrase)
    }

    /// The user has stored the recovery key; this app does not keep it.
    public func acknowledgeRecoveryKey() { recoveryKey = nil }

    public func setVaultPath(_ path: String) {
        lock()
        vaultPath = path
        defaults.set(path, forKey: Self.vaultKey)
        lockState = path.isEmpty ? .noFolder : .locked
    }

    // MARK: Lock / unlock

    public func unlock(passphrase: String) async {
        guard lockState == .locked, !vaultPath.isEmpty else { return }
        guard !passphrase.isEmpty, !passphrase.contains("\n"), !passphrase.contains("\r") else {
            vaultMessage = "The passphrase can't be empty or contain line breaks."
            return
        }
        lockState = .unlocking
        vaultMessage = nil
        let gen = generation
        box.set(passphrase)
        let r = await runListing()
        guard gen == generation else { return } // locked meanwhile
        switch r {
        case .success(let res) where res.endSeen && res.errorCode == nil:
            apply(res)
            lockState = .unlocked
        case .success(let res):
            box.set(nil)
            lockState = .locked
            vaultMessage = Self.message(forListingError: res.errorCode)
        case .failure(let m):
            box.set(nil)
            lockState = .locked
            vaultMessage = m
        }
    }

    public func lock() {
        generation += 1
        box.set(nil)
        runner.terminateNow()
        Task { await runner.terminateAll() }
        TokenFile.removeAll()
        entries = []
        listingProblems = 0
        listingStale = false
        pullItems = []
        pullSummary = nil
        pullMessage = nil
        pullRunning = false
        busy = false
        vaultMessage = nil
        if lockState != .noFolder { lockState = vaultPath.isEmpty ? .noFolder : .locked }
    }

    public func rebuildListing() async {
        guard lockState == .unlocked, !busy else { return }
        let gen = generation
        busy = true
        vaultMessage = nil
        let r = await runListing()
        guard gen == generation else { return }
        busy = false
        switch r {
        case .success(let res) where res.endSeen && res.errorCode == nil: apply(res)
        case .success(let res): vaultMessage = Self.message(forListingError: res.errorCode)
        case .failure(let m): vaultMessage = m
        }
    }

    private func apply(_ res: ListingResult) {
        entries = res.entries.sorted { ($0.dir, $0.name, $0.id) < ($1.dir, $1.name, $1.id) }
        listingProblems = res.problems
        listingStale = false
        vaultMessage = res.invalidRecords > 0 ? "\(res.invalidRecords) lines of the helper's output were not understood." : nil
    }

    enum ListingOutcome { case success(ListingResult), failure(String) }

    private func runListing() async -> ListingOutcome {
        let acc = ListingAccumulator()
        do {
            let o = try await runner.run(
                args: ["ls", "--json", "--passphrase-stdin", "--vault=\(vaultPath)"],
                passphrase: { [box] in box.get() },
                onLine: { acc.feed($0) })
            if o.outputViolation { return .failure("The helper produced unexpected output.") }
            let res = acc.result
            if !res.endSeen && res.errorCode == nil { return .failure("The listing is incomplete (the helper failed, exit \(o.exitStatus)).") }
            return .success(res)
        } catch { return .failure(Self.message(for: error)) }
    }

    static func message(for error: Error) -> String {
        switch error as? HelperError {
        case .locked?, .cancelled?: return "Locked."
        case .refused?: return "The bundled helper failed its integrity check; rebuild the app."
        default: return "The helper could not be started."
        }
    }

    static func message(forListingError code: String?) -> String {
        switch code {
        case "wrong-passphrase": return "Wrong passphrase."
        case "not-a-vault": return "This folder is not a vault. Create one in Terminal with `valv init`."
        case "vault-unreadable": return "The vault could not be read (damaged or unsupported)."
        default: return "The helper failed."
        }
    }

    // MARK: Pull

    public func pull() async {
        guard lockState == .unlocked, !pullRunning else { return }
        guard let (server, token) = credentials() else {
            pullMessage = "Set the server address and token in Settings first."
            return
        }
        let gen = generation
        pullRunning = true
        pullItems = []; pullSummary = nil; pullMessage = nil
        defer { if gen == generation { pullRunning = false } }

        let tf: TokenFile
        do { tf = try TokenFile.create(token: token, base: tempBase) } catch {
            pullMessage = "Could not create the temporary token file."
            return
        }
        defer { tf.remove() }
        let acc = PullAccumulator(onStarted: { tf.remove() })
        let outcome: HelperOutcome
        do {
            outcome = try await runner.run(
                args: ["pull", "--json", "--passphrase-stdin", "--vault=\(vaultPath)",
                       "--server=\(server.canonical)", "--token-file=\(tf.filePath)"],
                passphrase: { [box] in box.get() },
                onLine: { acc.feed($0) })
        } catch {
            if gen == generation { pullMessage = Self.message(for: error) }
            return
        }
        guard gen == generation else { return }
        let r = acc.result
        pullItems = r.items
        if outcome.outputViolation { pullMessage = "The helper produced unexpected output."; return }
        if let code = r.errorCode {
            pullMessage = Self.message(forPullError: code)
            return
        }
        guard r.endSeen else {
            pullMessage = "The pull did not finish (the helper failed, exit \(outcome.exitStatus))."
            return
        }
        var parts = ["\(r.ingested) added", "\(r.already) already in the vault"]
        let na = r.items.filter { $0.kind == .notAuthentic }.count
        if na > 0 { parts.append("\(na) rejected as not authentic and left on the server") }
        let other = r.failed - na
        if other > 0 { parts.append("\(other) failed") }
        if r.deleteFailed > 0 { parts.append("\(r.deleteFailed) could not be deleted from the server (the next pull will absorb them)") }
        pullSummary = parts.joined(separator: ", ") + "."
        listingStale = r.ingested > 0 || r.already > 0
    }

    static func message(forPullError code: String) -> String {
        switch code {
        case "wrong-passphrase": return "Wrong passphrase."
        case "not-a-vault": return "This folder is not a vault. Create one in Terminal with `valv init`."
        case "vault-unreadable": return "The vault could not be read (damaged or unsupported)."
        case "token-file": return "The helper could not read the temporary token file."
        case "server-url": return "The helper refused the server address."
        case "unauthorized": return "The server rejected the token."
        case "rate-limited": return "The server is refusing requests for a while (too many failed logins or uploads)."
        case "unreachable": return "Can't reach the server. Is Tailscale on?"
        default: return "The pull failed."
        }
    }
}
