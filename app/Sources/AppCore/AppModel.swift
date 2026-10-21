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
    /// M3: a token is saved but not for the server address now configured (for example UserDefaults was
    /// edited from outside). The token is not sent until it is typed in again in Settings.
    public private(set) var tokenNeedsReentry = false

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
    public var recoveryMessage: String?

    // Add to vault (encrypted locally by `ndes add`; the server is not involved)
    public private(set) var addItems: [SendItem] = []
    public private(set) var adding = false
    public private(set) var addNotes: [String] = []

    // Export and open (decrypted copies leave the vault; see the notes in the UI)
    public private(set) var exporting = false
    public private(set) var exportMessage: String?
    public private(set) var exportFolder: String?
    public var openMessage: String?

    // Touch ID
    public private(set) var touchIDAvailable = false
    public private(set) var touchIDEnabled = false     // a passphrase is saved for the current vault
    public var touchIDMessage: String?

    public let sendQueue: SendQueue

    // Auto-lock (M1): minutes without input in the app; default 10.
    public static let autoLockKey = "autoLockMinutes"
    public static let autoLockRange = 1...120
    public var autoLockMinutes: Int {
        didSet {
            let v = min(max(autoLockMinutes, Self.autoLockRange.lowerBound), Self.autoLockRange.upperBound)
            if v != autoLockMinutes { autoLockMinutes = v; return }
            defaults.set(v, forKey: Self.autoLockKey)
        }
    }
    private var lastActivity = Date()

    private let defaults: UserDefaults
    private let secrets: SecretStoring
    private let runner: HelperRunner
    private let biometric: BiometricUnlocking?
    private let tempBase: String?
    private let box = PassphraseBox()
    private var generation = 0

    let routeGuard: RouteGuard
    public static let urlKey = "serverURL"
    public static let vaultKey = "vaultPath"

    public init(defaults: UserDefaults = .standard, secrets: SecretStoring, runner: HelperRunner, biometric: BiometricUnlocking? = nil, tempBase: String? = nil) {
        self.defaults = defaults
        self.biometric = biometric
        self.secrets = secrets
        self.runner = runner
        self.tempBase = tempBase
        let url = defaults.string(forKey: Self.urlKey) ?? ""
        let vault = defaults.string(forKey: Self.vaultKey) ?? ""
        let stored = defaults.integer(forKey: Self.autoLockKey)
        autoLockMinutes = stored == 0 ? 10 : min(max(stored, Self.autoLockRange.lowerBound), Self.autoLockRange.upperBound)
        serverURLText = url
        vaultPath = vault
        tokenIsSet = false
        lockState = vault.isEmpty ? .noFolder : .locked
        let defs = defaults
        routeGuard = RouteGuard(extraInterfaces: { RouteGuard.parseInterfaceList(defs.string(forKey: RouteGuard.defaultsKey) ?? "") })
        sendQueue = SendQueue(client: ServerClient(route: routeGuard), credentials: { nil })
        sendQueue.credentials = { [weak self] in self?.sendCredentials() }
        sendQueue.credentialsProblem = { [weak self] in self?.credentialsProblem() ?? "Set the server address and token in Settings first." }
        refreshTokenState()
        refreshTouchID()
    }

    private func refreshTokenState() {
        let c = secrets.credential()
        tokenIsSet = c != nil
        let u = try? URLPolicy.parse(serverURLText)
        tokenNeedsReentry = c != nil && (u == nil || c?.server != u?.canonical)
    }

    /// The server URL (validated again) and token for an upload or pull. The token is only returned for
    /// the server it was saved with (M3); otherwise nil.
    func credentials() -> (ServerURL, String)? {
        guard let u = try? URLPolicy.parse(serverURLText), let c = secrets.credential() else { return nil }
        guard c.server == u.canonical else { refreshTokenState(); return nil }
        return (u, c.token)
    }

    /// The credentials for SendQueue: server URL, bearer token, and optional client-sealing ServerKeys.
    func sendCredentials() -> (ServerURL, String, ServerKeys?)? {
        guard let u = try? URLPolicy.parse(serverURLText), let c = secrets.credential() else { return nil }
        guard c.server == u.canonical else { refreshTokenState(); return nil }
        return (u, c.token, c.serverKeys)
    }

    public var hasServerKeys: Bool {
        secrets.credential()?.serverKeys != nil
    }

    /// Why `credentials()` is nil.
    func credentialsProblem() -> String {
        refreshTokenState()
        return tokenNeedsReentry
            ? "The server address no longer matches the one the token was saved for. Enter the token again in Settings."
            : "Set the server address and token in Settings first."
    }

    // MARK: Settings

    public enum SettingsError: Error, Equatable {
        case badURL(String), badToken, tokenRequiredForNewHost, keychain
        public var message: String {
            switch self {
            case .badURL(let m): return m
            case .badToken: return "The token must be 32–512 printable characters without spaces."
            case .tokenRequiredForNewHost: return "The server address is not the one the token was saved for; enter the token again."
            case .keychain: return "The token could not be saved in the Keychain."
            }
        }
    }

    /// `token` nil keeps the stored one. A different host needs the token typed again.
    public func saveSettings(serverURL: String, token: String?, serverKeys: ServerKeys? = nil, vaultPath newVault: String) throws {
        let trimmed = serverURL.trimmingCharacters(in: .whitespaces)
        let parsed: ServerURL
        do { parsed = try URLPolicy.parse(trimmed) } catch let e as URLPolicyError { throw SettingsError.badURL(e.message) }
        if let t = token, !t.isEmpty {
            guard (32...512).contains(t.utf8.count), t.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else { throw SettingsError.badToken }
        }
        // M3: the token belongs to scheme+host+port as saved. Any other address needs the token typed again.
        let stored = secrets.credential()
        if let stored, stored.server != parsed.canonical, (token ?? "").isEmpty { throw SettingsError.tokenRequiredForNewHost }
        let effectiveToken = (token != nil && !token!.isEmpty) ? token! : stored?.token
        let effectiveKeys = serverKeys ?? (stored?.server == parsed.canonical ? stored?.serverKeys : nil)
        if let t = effectiveToken {
            do { try secrets.setCredential(token: t, server: parsed.canonical, serverKeys: effectiveKeys) } catch { throw SettingsError.keychain }
        }
        serverURLText = parsed.canonical
        defaults.set(parsed.canonical, forKey: Self.urlKey)
        refreshTokenState()
        if newVault != vaultPath {
            lock()
            vaultPath = newVault
            defaults.set(newVault, forKey: Self.vaultKey)
            lockState = newVault.isEmpty ? .noFolder : .locked
            refreshTouchID()
        }
    }

    public func saveSettings(serverURL: String, token: String?, vaultPath newVault: String) throws {
        try saveSettings(serverURL: serverURL, token: token, serverKeys: nil, vaultPath: newVault)
    }

    // MARK: Create a vault

    public static let minPassphraseCharacters = 12

    /// Runs `ndes init` in an empty (or new) folder, then unlocks the new vault. The recovery key is kept in
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
        refreshTouchID()
    }

    // MARK: Touch ID

    private func refreshTouchID() {
        touchIDAvailable = biometric?.isAvailable ?? false
        touchIDEnabled = touchIDAvailable && !vaultPath.isEmpty && (biometric?.hasPassphrase(vault: vaultPath) ?? false)
    }

    /// Saves the current passphrase (held while unlocked) for Touch ID unlock.
    public func enableTouchID() {
        touchIDMessage = nil
        guard lockState == .unlocked, let b = biometric, b.isAvailable, let p = box.get() else {
            touchIDMessage = "Unlock the vault first."; return
        }
        do { try b.save(passphrase: p, vault: vaultPath) } catch { touchIDMessage = "The passphrase could not be saved in the Keychain."; return }
        refreshTouchID()
    }

    public func disableTouchID() {
        touchIDMessage = nil
        biometric?.remove(vault: vaultPath)
        refreshTouchID()
    }

    /// Unlocks with the saved passphrase after a Touch ID check. A saved passphrase that no longer works
    /// (changed with `ndes passwd`) is forgotten.
    public func unlockWithTouchID() async {
        guard lockState == .locked, touchIDEnabled, let b = biometric else { return }
        guard let p = await b.load(vault: vaultPath, reason: "unlock your vault") else { return }
        await unlock(passphrase: p)
        if lockState == .locked, vaultMessage == "Wrong passphrase." {
            b.remove(vault: vaultPath)
            refreshTouchID()
            vaultMessage = "The saved passphrase no longer works. Type the passphrase."
        }
    }

    // MARK: Recovery key (shown again on request)

    /// The recovery key is the vault key in another encoding, so the helper can print it again for an unlocked
    /// vault. Needs the passphrase typed again (or Touch ID, when enabled). The key is returned, never stored.
    public func revealRecoveryKey(passphrase: String?) async -> String? {
        touchIDMessage = nil
        guard lockState == .unlocked, !vaultPath.isEmpty, let held = box.get() else { return nil }
        if let typed = passphrase {
            guard Self.sameSecret(typed, held) else { recoveryMessage = "Wrong passphrase."; return nil }
        } else {
            guard touchIDEnabled, let b = biometric,
                  let p = await b.load(vault: vaultPath, reason: "show your recovery key"),
                  Self.sameSecret(p, held) else { return nil }
        }
        let lines = LineCollector()
        do {
            let o = try await runner.run(
                args: ["recovery-key", "--passphrase-stdin", "--vault=\(vaultPath)"],
                passphrase: { [box] in box.get() },
                onLine: { lines.add($0) })
            guard !o.outputViolation, o.exitStatus == 0, lines.values.count == 1,
                  InitAccumulator.plausibleKey(lines.values[0]) else {
                recoveryMessage = "Could not read the recovery key."; return nil
            }
            recoveryMessage = nil
            return lines.values[0]
        } catch { recoveryMessage = Self.message(for: error); return nil }
    }

    static func sameSecret(_ a: String, _ b: String) -> Bool {
        let (x, y) = (Array(a.utf8), Array(b.utf8))
        guard x.count == y.count else { return false }
        return zip(x, y).reduce(0) { $0 | ($1.0 ^ $1.1) } == 0
    }

    // MARK: Add files straight into the vault

    /// Files and folders are encrypted one by one with `ndes add`. Each run re-derives the key (about half a
    /// second), so a large folder takes a while.
    public func addToVault(urls: [URL]) {
        guard lockState == .unlocked else { return }
        let exp = InputExpander.expand(urls)
        addNotes = []
        if exp.tooMany { addNotes.append("More than \(InputExpander.maxFiles) files: nothing beyond the first \(InputExpander.maxFiles) was added.") }
        if !exp.skipped.isEmpty {
            addNotes.append("Skipped (not regular files): " + exp.skipped.prefix(5).joined(separator: ", ") + (exp.skipped.count > 5 ? " …" : ""))
        }
        for s in exp.specs {
            addItems.append(SendItem(spec: s, displayName: DisplayName.sanitize(s.dir.isEmpty ? s.name : s.dir + "/" + s.name)))
        }
        guard !adding else { return }
        let gen = generation
        adding = true
        busy = true
        Task { await runAdds(gen) }
    }

    public func clearAddFinished() { addItems.removeAll { $0.state == .sent } }

    /// Waits until no add is running (for tests).
    public func waitForAdds() async {
        while adding || busy { try? await Task.sleep(nanoseconds: 20_000_000) }
    }

    private func runAdds(_ gen: Int) async {
        var any = false
        while gen == generation, let i = addItems.firstIndex(where: { $0.state == .waiting }) {
            addItems[i].state = .sending
            let spec = addItems[i].spec
            let acc = AddAccumulator()
            var failure: String?
            do {
                let o = try await runner.run(
                    args: ["add", "--json", "--passphrase-stdin", "--vault=\(vaultPath)",
                           "--name=\(spec.name)", "--dir=\(spec.dir)", "--", spec.url.path],
                    passphrase: { [box] in box.get() },
                    onLine: { acc.feed($0) })
                if o.outputViolation { failure = "The helper produced unexpected output." }
                else if !acc.succeeded { failure = Self.message(forAddError: acc.errorCode) }
            } catch { failure = Self.message(for: error) }
            guard gen == generation else { return } // locked meanwhile: lock() reset the state
            guard let j = addItems.firstIndex(where: { $0.id == addItems[i].id }) else { continue }
            if let f = failure { addItems[j].state = .failed(f) } else { addItems[j].state = .sent; any = true }
        }
        guard gen == generation else { return }
        adding = false
        busy = false
        if any { await rebuildListing() }
    }

    static func message(forAddError code: String?) -> String {
        switch code {
        case "bad-name": return "The name or folder isn't allowed in a vault."
        case "file-changed": return "The file changed while it was being read; nothing was added."
        case "wrong-passphrase": return "Wrong passphrase."
        default: return "Could not add this file."
        }
    }

    // MARK: Export and open

    /// A safe file name for a decrypted copy: display-cleaned, no path separators, never "." or "..",
    /// at most about 200 bytes, and never an existing name in the folder.
    static func exportFileName(for e: FileEntry, taken: Set<String>, folder: String) -> String {
        var base = e.name.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
        if base == "." || base == ".." || base == "(unnamed)" { base = "file" }
        if base.utf8.count > 200 {
            let ext = (base as NSString).pathExtension
            let stem = String((base as NSString).deletingPathExtension.prefix(60))
            base = ext.isEmpty || ext.utf8.count > 20 ? stem : stem + "." + ext
        }
        func free(_ n: String) -> Bool { !taken.contains(n) && lstatMissing(folder + "/" + n) }
        if free(base) { return base }
        let ext = (base as NSString).pathExtension
        let stem = (base as NSString).deletingPathExtension
        let alt = ext.isEmpty ? "\(stem) (\(e.shortID))" : "\(stem) (\(e.shortID)).\(ext)"
        if free(alt) { return alt }
        return "\(e.id)" + (ext.isEmpty ? "" : "." + ext)
    }

    private static func lstatMissing(_ p: String) -> Bool { var st = stat(); return lstat(p, &st) != 0 && errno == ENOENT }

    private func get(_ e: FileEntry, to path: String) async -> String? {
        do {
            let o = try await runner.run(
                args: ["get", "--passphrase-stdin", "--vault=\(vaultPath)", "-o=\(path)", "--", e.id],
                passphrase: { [box] in box.get() }, onLine: { _ in true })
            if o.exitStatus == 0 && !o.outputViolation && !o.killedByUs { return nil }
            if o.killedByUs { return "Locked." }
            let last = String(decoding: o.stderrTail, as: UTF8.self).split(separator: "\n").last.map(String.init) ?? ""
            switch last {
            case "ndes: wrong passphrase or altered vault.json": return "Wrong passphrase."
            case "ndes: the output file already exists (use --force to replace it)": return "A file with that name already exists."
            case "ndes: refusing to write inside the vault directory; choose another output location with -o":
                return "Choose a folder outside the vault."
            default: return "The helper failed (exit \(o.exitStatus))."
            }
        } catch { return Self.message(for: error) }
    }

    /// Writes decrypted copies into `folder` (chosen by the user). Never replaces an existing file.
    public func export(_ entries: [FileEntry], toFolder folder: String) async {
        guard lockState == .unlocked, !exporting, !entries.isEmpty else { return }
        let gen = generation
        exporting = true
        exportMessage = nil
        exportFolder = folder
        defer { if gen == generation { exporting = false } }
        var ok = 0
        var failures: [String] = []
        var taken = Set<String>()
        for e in entries {
            let name = Self.exportFileName(for: e, taken: taken, folder: folder)
            taken.insert(name)
            let err = await get(e, to: folder + "/" + name)
            guard gen == generation else { return }
            if let err { failures.append(err) } else { ok += 1 }
        }
        var m = "\(ok) exported"
        if !failures.isEmpty { m += ", \(failures.count) failed (\(failures[0]))" }
        exportMessage = m + "."
    }

    /// Decrypts one file into a private temporary folder and returns its URL for the caller to open. The copy is
    /// deleted on lock and quit. Only harmless file types are offered (see `OpenPolicy`).
    public func prepareOpen(_ e: FileEntry) async -> URL? {
        guard lockState == .unlocked, !busy else { return nil }
        openMessage = nil
        let name = Self.exportFileName(for: e, taken: [], folder: "/nonexistent")
        guard OpenPolicy.canOpen(fileName: name) else {
            openMessage = "This file type isn't opened automatically (it could run code). Use Export instead."
            return nil
        }
        let gen = generation
        let dir: PrivateDir
        do { dir = try PrivateDir.create(base: tempBase) } catch { openMessage = "Could not create the temporary folder."; return nil }
        let path = dir.path + "/" + name
        let err = await get(e, to: path)
        guard gen == generation else { dir.remove(); return nil }
        if let err { openMessage = err; dir.remove(); return nil }
        return URL(fileURLWithPath: path)
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
            Task { await self.updateServerKeysFromVault() }
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

    /// User input in the app resets the inactivity timer.
    public func noteActivity() { lastActivity = Date() }

    /// True while something that uses the passphrase or the network is running.
    public var workRunning: Bool { pullRunning || busy || adding || exporting || creating || !sendQueue.isIdle }

    /// Called every few seconds. Locks after `autoLockMinutes` without input, but not while work is running
    /// (the lock then comes on the first tick after it finishes). Sleep, screen lock and session resign
    /// do not wait: see `lockForSystemEvent`. Returns true if it locked.
    @discardableResult
    public func inactivityTick(now: Date = Date()) -> Bool {
        guard lockState == .unlocked || lockState == .unlocking else { return false }
        guard now.timeIntervalSince(lastActivity) >= Double(autoLockMinutes) * 60 else { return false }
        guard !workRunning else { return false }
        lock()
        return true
    }

    /// Sleep, screen sleep/lock, screensaver, fast user switch: lock now and cancel whatever is running.
    public func lockForSystemEvent() { lock() }

    public func lock() {
        let wasActive = lockState == .unlocked || lockState == .unlocking
        let hadPull = pullRunning
        let hadVaultJob = adding || exporting
        if wasActive { sendQueue.interrupt("Interrupted: the app was locked. Resume to continue sending.") }
        lastActivity = Date()
        generation += 1
        box.set(nil)
        runner.terminateNow()
        Task { await runner.terminateAll() }
        TokenFile.removeAll()
        PrivateDir.removeAll()
        exportMessage = nil
        exportFolder = nil
        exporting = false
        openMessage = nil
        entries = []
        listingProblems = 0
        listingStale = false
        pullItems = []
        pullSummary = nil
        pullMessage = nil
        pullRunning = false
        busy = false
        adding = false
        addItems = []
        addNotes = []
        vaultMessage = nil
        recoveryMessage = nil
        if lockState != .noFolder { lockState = vaultPath.isEmpty ? .noFolder : .locked }
        // Say what was cut off; the messages show after the next unlock.
        if hadPull { pullMessage = "Interrupted: the app was locked during the pull. Files already ingested stay in the vault; the rest are still on the server." }
        if hadVaultJob { vaultMessage = "Interrupted: the app was locked while files were being added or exported." }
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

    /// Asks the helper for the inbox server's keys (the unlocked vault's passphrase is already held).
    public func serverKeys() async -> ServerKeys? {
        guard lockState == .unlocked, !vaultPath.isEmpty else { return nil }
        let lines = LineCollector()
        do {
            let o = try await runner.run(
                args: ["server-config", "--passphrase-stdin", "--vault=\(vaultPath)"],
                passphrase: { [box] in box.get() },
                onLine: { lines.add($0) })
            guard !o.outputViolation, o.exitStatus == 0 else { return nil }
            return ServerKeys(lines: lines.values)
        } catch { return nil }
    }

    /// Automatically stores the vault's server keys into the Keychain if a server token is configured.
    func updateServerKeysFromVault() async {
        guard lockState == .unlocked, let cred = secrets.credential(), let s = cred.server else { return }
        if cred.serverKeys != nil { return }
        if let keys = await serverKeys() {
            try? secrets.setCredential(token: cred.token, server: s, serverKeys: keys)
        }
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
        case "not-a-vault": return "This folder is not a vault. Create one in Terminal with `ndes init`."
        case "vault-unreadable": return "The vault could not be read (damaged or unsupported)."
        default: return "The helper failed."
        }
    }

    // MARK: Pull

    public func pull() async {
        guard lockState == .unlocked, !pullRunning else { return }
        guard let (server, token) = credentials() else {
            pullMessage = credentialsProblem()
            return
        }
        guard routeGuard.allows(server) else {
            pullMessage = RouteGuard.routeMessage
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
                       "--server=\(server.canonical)", "--token-file=\(tf.filePath)"]
                    + (routeGuard.extraInterfaces().isEmpty ? [] : ["--tailscale-interfaces=\(routeGuard.extraInterfaces().joined(separator: ","))"]),
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
        case "not-a-vault": return "This folder is not a vault. Create one in Terminal with `ndes init`."
        case "vault-unreadable": return "The vault could not be read (damaged or unsupported)."
        case "token-file": return "The helper could not read the temporary token file."
        case "server-url": return "The helper refused the server address."
        case "unauthorized": return "The server rejected the token."
        case "rate-limited": return "The server is refusing requests for a while (too many failed logins or uploads)."
        case "unreachable": return "Can't reach the server. Is Tailscale on?"
        case "route": return RouteGuard.routeMessage
        default: return "The pull failed."
        }
    }
}

final class LineCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func add(_ d: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard lines.count < 4, let s = String(data: d, encoding: .utf8) else { return false }
        lines.append(s); return true
    }
    var values: [String] { lock.lock(); defer { lock.unlock() }; return lines }
}
