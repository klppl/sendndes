import AppCore
import AppKit
import SwiftUI
import UniformTypeIdentifiers

enum Section: String, CaseIterable, Identifiable {
    case vault = "Vault", send = "Send", pull = "Pull"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .vault: return "lock.shield"
        case .send: return "paperplane"
        case .pull: return "tray.and.arrow.down"
        }
    }
}

struct ContentView: View {
    @Bindable var model: AppModel
    @State private var section: Section? = .vault
    @State private var showSettings = false
    @State private var showCreate = false

    var body: some View {
        NavigationSplitView {
            List(Section.allCases, selection: $section) { s in
                Label(s.rawValue, systemImage: s.icon).tag(s)
            }
            .navigationSplitViewColumnWidth(min: 140, ideal: 160)
        } detail: {
            switch section ?? .vault {
            case .vault: VaultView(model: model, openSettings: { showSettings = true }, openCreate: { showCreate = true })
            case .send: SendView(model: model, queue: model.sendQueue, openSettings: { showSettings = true })
            case .pull: PullView(model: model, openSettings: { showSettings = true })
            }
        }
        .toolbar {
            ToolbarItemGroup {
                if model.lockState == .unlocked {
                    Button { model.lock() } label: { Label("Lock", systemImage: "lock") }
                        .keyboardShortcut("l", modifiers: .command)
                        .help("Lock the vault (⌘L)")
                }
                Button { showSettings = true } label: { Label("Settings", systemImage: "gearshape") }
            }
        }
        .sheet(isPresented: Binding(get: { model.recoveryKey != nil }, set: { _ in })) {
            RecoveryKeyView(model: model).interactiveDismissDisabled()
        }
        .sheet(isPresented: $showCreate) { CreateVaultView(model: model, close: { showCreate = false }) }
        .sheet(isPresented: $showSettings) { SettingsView(model: model, close: { showSettings = false }) }
        .onAppear { if model.serverURLText.isEmpty && model.vaultPath.isEmpty { showSettings = true } }
    }
}

// MARK: Settings

struct SettingsView: View {
    let model: AppModel
    let close: () -> Void
    @State private var url = ""
    @State private var token = ""
    @State private var vault = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Settings").font(.title2.bold())
            Form {
                TextField("Server address", text: $url, prompt: Text(verbatim: "http://100.x.y.z:8485 or https://…"))
                SecureField("Bearer token", text: $token,
                            prompt: Text(model.tokenIsSet ? "Saved in the Keychain; type to replace" : "Paste the token"))
                LabeledContent("Vault folder") {
                    HStack {
                        Text(verbatim: vault.isEmpty ? "None chosen" : vault)
                            .lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                        Button("Choose…") { chooseVault() }
                    }
                }
            }
            Text("The token is kept in your login keychain: not synchronizable, not iCloud-synced, readable while the login keychain is unlocked (normally the whole login session). macOS may ask you to allow access after each rebuild of this app.")
                .font(.caption).foregroundStyle(.secondary)
            if let error { Text(verbatim: error).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancel", action: close).keyboardShortcut(.cancelAction)
                Button("Save") { save() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20).frame(width: 560)
        .onAppear { url = model.serverURLText; vault = model.vaultPath }
    }

    private func chooseVault() {
        let p = NSOpenPanel()
        p.canChooseDirectories = true; p.canChooseFiles = false; p.allowsMultipleSelection = false
        p.prompt = "Choose vault folder"
        if p.runModal() == .OK, let u = p.url { vault = u.path }
    }

    private func save() {
        do {
            try model.saveSettings(serverURL: url, token: token.isEmpty ? nil : token, vaultPath: vault)
            token = ""
            close()
        } catch let e as AppModel.SettingsError { error = e.message } catch { self.error = "Could not save." }
    }
}

// MARK: Create vault

struct CreateVaultView: View {
    @Bindable var model: AppModel
    let close: () -> Void
    @State private var folder = ""
    @State private var pass = ""
    @State private var again = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Create a vault").font(.title2.bold())
            LabeledContent("Folder") {
                HStack {
                    Text(verbatim: folder.isEmpty ? "None chosen" : folder)
                        .lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                    Button("Choose…", action: choose)
                }
            }
            Text("Pick an empty folder, or make a new one in the dialog. If it is inside Google Drive or Dropbox, the sealed files will sync there.")
                .font(.caption).foregroundStyle(.secondary)
            SecureField("Passphrase (at least \(AppModel.minPassphraseCharacters) characters)", text: $pass)
            SecureField("Repeat passphrase", text: $again)
            Text("Nobody can reset the passphrase. You will get a recovery key once; it is the only way back in if you forget the passphrase.")
                .font(.caption).foregroundStyle(.secondary)
            if let m = model.createMessage { Text(verbatim: m).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancel") { model.createMessage = nil; close() }.keyboardShortcut(.cancelAction)
                Button(model.creating ? "Creating…" : "Create vault") { create() }
                    .keyboardShortcut(.defaultAction).disabled(model.creating)
            }
        }
        .padding(20).frame(width: 540)
        .onAppear { model.createMessage = nil }
        .onChange(of: model.recoveryKey) { _, new in if new != nil { pass = ""; again = ""; close() } }
    }

    private func choose() {
        let p = NSOpenPanel()
        p.canChooseDirectories = true; p.canChooseFiles = false; p.allowsMultipleSelection = false
        p.canCreateDirectories = true
        p.prompt = "Use this folder"
        if p.runModal() == .OK, let u = p.url { folder = u.path }
    }

    private func create() {
        let (a, b, f) = (pass, again, folder)
        Task { await model.createVault(at: f, passphrase: a, repeated: b) }
    }
}

/// Shown once after creation. It cannot be dismissed until the key has been typed back correctly.
struct RecoveryKeyView: View {
    let model: AppModel
    @State private var typed = ""

    private func normalized(_ s: String) -> String {
        s.uppercased().filter { !$0.isWhitespace && $0 != "-" }
    }

    var body: some View {
        let key = model.recoveryKey ?? ""
        VStack(alignment: .leading, spacing: 12) {
            Text("Your recovery key").font(.title2.bold())
            Text("The vault is created. Write this key down or store it in a password manager now. It is shown only once, this app does not keep it, and without it a forgotten passphrase cannot be undone.")
            Text(verbatim: key)
                .font(.system(.title3, design: .monospaced)).textSelection(.enabled)
                .padding(10).frame(maxWidth: .infinity).background(.quaternary, in: RoundedRectangle(cornerRadius: 6))
            TextField("Type the key again to confirm", text: $typed)
                .font(.system(.body, design: .monospaced)).autocorrectionDisabled()
            HStack {
                if !typed.isEmpty && normalized(typed) != normalized(key) {
                    Text("That doesn't match yet.").foregroundStyle(.secondary)
                }
                Spacer()
                Button("I have stored it") { model.acknowledgeRecoveryKey() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(normalized(typed) != normalized(key))
            }
        }
        .padding(20).frame(width: 560)
    }
}

// MARK: Vault

struct VaultView: View {
    @Bindable var model: AppModel
    let openSettings: () -> Void
    let openCreate: () -> Void
    @State private var passphrase = ""
    @State private var selection = Set<FileEntry.ID>()

    var body: some View {
        switch model.lockState {
        case .noFolder:
            Placeholder(title: "No vault folder chosen",
                        text: "Create a new vault, or choose the folder of an existing one in Settings.",
                        button: "Create a vault…", action: openCreate)
        case .locked, .unlocking:
            VStack(spacing: 12) {
                Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.secondary)
                Text("The vault is locked").font(.title3)
                Text(verbatim: model.vaultPath).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                SecureField("Passphrase", text: $passphrase)
                    .textFieldStyle(.roundedBorder).frame(width: 280)
                    .onSubmit(unlock)
                Button(model.lockState == .unlocking ? "Unlocking…" : "Unlock", action: unlock)
                    .disabled(model.lockState == .unlocking || passphrase.isEmpty)
                    .keyboardShortcut(.defaultAction)
                if let m = model.vaultMessage { Text(verbatim: m).foregroundStyle(.red).multilineTextAlignment(.center) }
                Button("Create a new vault instead…", action: openCreate).buttonStyle(.link)
                Text("Listing opens every file in the vault. In Google Drive “stream” mode or Dropbox online-only folders this can download files and take a while.")
                    .font(.caption).foregroundStyle(.secondary).frame(maxWidth: 420).multilineTextAlignment(.center)
            }
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .unlocked:
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("\(model.entries.count) files").font(.headline)
                    if model.listingProblems > 0 {
                        Text("\(model.listingProblems) problems — run `valv verify` in Terminal.").foregroundStyle(.orange)
                    }
                    if model.listingStale { Text("List may be out of date after the pull.").foregroundStyle(.secondary) }
                    Spacer()
                    Button("Open") { openSelected() }.disabled(selection.count != 1 || model.busy)
                    Button("Export…") { exportSelected() }.disabled(selection.isEmpty || model.exporting)
                    Button("Add files…", action: addFiles).disabled(model.adding)
                    Button(model.busy ? "Working…" : "Rebuild listing") { Task { await model.rebuildListing() } }
                        .disabled(model.busy)
                }
                if !model.addItems.isEmpty {
                    HStack {
                        Text("Adding to the vault").font(.subheadline.bold())
                        Spacer()
                        if model.addItems.contains(where: { $0.state == .sent }) { Button("Clear finished") { model.clearAddFinished() } }
                    }
                    List(model.addItems) { item in
                        HStack {
                            Text(verbatim: item.displayName).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            switch item.state {
                            case .waiting: Text("waiting").foregroundStyle(.secondary)
                            case .sending: ProgressView().controlSize(.small); Text("encrypting")
                            case .sent: Label("added", systemImage: "checkmark.circle").foregroundStyle(.green)
                            case .failed(let m): Text(verbatim: m).foregroundStyle(.red).lineLimit(2)
                            }
                        }
                    }
                    .frame(maxHeight: 130)
                }
                ForEach(model.addNotes, id: \.self) { Text(verbatim: $0).font(.caption).foregroundStyle(.secondary) }
                if let m = model.vaultMessage { Text(verbatim: m).foregroundStyle(.red) }
                if let m = model.openMessage { Text(verbatim: m).foregroundStyle(.orange) }
                if let m = model.exportMessage {
                    HStack {
                        Text(verbatim: m)
                        if let f = model.exportFolder { Button("Show in Finder") { NSWorkspace.shared.open(URL(fileURLWithPath: f)) } }
                    }
                }
                Table(model.entries, selection: $selection) {
                    TableColumn("Name") { e in Text(verbatim: e.name) }
                    TableColumn("Folder") { e in Text(verbatim: e.dir) }
                    TableColumn("Size") { e in Text(verbatim: ByteCountFormatter.string(fromByteCount: e.size, countStyle: .file)) }
                        .width(80)
                    TableColumn("Modified") { e in Text(verbatim: e.mtime.formatted(date: .abbreviated, time: .shortened)) }
                        .width(130)
                    TableColumn("ID") { e in Text(verbatim: e.shortID).font(.system(.body, design: .monospaced)) }
                        .width(80)
                }
                .contextMenu(forSelectionType: FileEntry.ID.self) { ids in
                    if ids.count == 1 { Button("Open") { selection = ids; openSelected() } }
                    Button("Export…") { selection = ids; exportSelected() }
                } primaryAction: { ids in
                    if ids.count == 1 { selection = ids; openSelected() }
                }
                Text("Open and Export hand you a decrypted copy that the vault no longer protects. Opened copies are kept in a private temporary folder and deleted when you lock or quit, but the app you open them in may keep its own copy. Exported copies stay where you put them (watch out for synced or indexed folders).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding()
            .dropDestination(for: URL.self) { urls, _ in
                model.addToVault(urls: urls.filter { $0.isFileURL })
                return true
            }
        }
    }

    private func openSelected() {
        guard selection.count == 1, let e = model.entries.first(where: { selection.contains($0.id) }) else { return }
        Task { if let url = await model.prepareOpen(e) { NSWorkspace.shared.open(url) } }
    }

    private func exportSelected() {
        let chosen = model.entries.filter { selection.contains($0.id) }
        guard !chosen.isEmpty else { return }
        let p = NSOpenPanel()
        p.canChooseFiles = false; p.canChooseDirectories = true; p.canCreateDirectories = true; p.allowsMultipleSelection = false
        p.prompt = "Export here"
        p.message = "Exported files are not encrypted. Choose a folder outside the vault; avoid synced or indexed folders."
        if p.runModal() == .OK, let u = p.url { Task { await model.export(chosen, toFolder: u.path) } }
    }

    private func addFiles() {
        let p = NSOpenPanel()
        p.canChooseFiles = true; p.canChooseDirectories = true; p.allowsMultipleSelection = true
        p.prompt = "Add to vault"
        if p.runModal() == .OK { model.addToVault(urls: p.urls) }
    }

    private func unlock() {
        let p = passphrase
        passphrase = ""
        Task { await model.unlock(passphrase: p) }
    }
}

struct Placeholder: View {
    let title: String, text: String, button: String?, action: () -> Void
    init(title: String, text: String, button: String? = nil, action: @escaping () -> Void = {}) {
        self.title = title; self.text = text; self.button = button; self.action = action
    }
    var body: some View {
        VStack(spacing: 10) {
            Text(title).font(.title3)
            Text(text).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 420)
            if let button { Button(button, action: action) }
        }
        .padding().frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: Send

struct SendView: View {
    let model: AppModel
    @Bindable var queue: SendQueue
    let openSettings: () -> Void
    @State private var targeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !model.tokenIsSet || model.serverURLText.isEmpty {
                Placeholder(title: "Server not set up", text: "Enter the server address and token in Settings.", button: "Open Settings", action: openSettings)
            } else {
                HStack {
                    Text("Drop files or folders here, or").foregroundStyle(.secondary)
                    Button("Add files…", action: addFiles)
                    Spacer()
                    if queue.items.contains(where: { $0.state == .sent }) { Button("Clear finished") { queue.clearFinished() } }
                }
                if let r = queue.pausedReason {
                    HStack {
                        Text(verbatim: r).foregroundStyle(.orange)
                        Button("Resume") { queue.resume() }
                    }
                }
                ForEach(queue.notes, id: \.self) { Text(verbatim: $0).font(.caption).foregroundStyle(.secondary) }
                List(queue.items) { item in
                    HStack {
                        Text(verbatim: item.displayName).lineLimit(1).truncationMode(.middle)
                        Spacer()
                        switch item.state {
                        case .waiting: Text("waiting").foregroundStyle(.secondary)
                        case .sending: ProgressView().controlSize(.small); Text("sending")
                        case .sent: Label("sent", systemImage: "checkmark.circle").foregroundStyle(.green)
                        case .failed(let m):
                            Text(verbatim: m).foregroundStyle(.red).lineLimit(2)
                            Button("Retry") { queue.retry(item.id) }
                        }
                    }
                }
                .overlay { if queue.items.isEmpty { Text("Nothing queued").foregroundStyle(.secondary) } }
                Text("Files are sent one at a time. If a send fails and you retry, the vault can end up with a duplicate. Don't send files that are still being written. In this version the server briefly sees the file's contents and name while it seals them.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding()
        .dropDestination(for: URL.self) { urls, _ in
            queue.add(urls: urls.filter { $0.isFileURL })
            return true
        } isTargeted: { targeted = $0 }
        .overlay { if targeted { RoundedRectangle(cornerRadius: 8).stroke(Color.accentColor, lineWidth: 3).padding(4) } }
    }

    private func addFiles() {
        let p = NSOpenPanel()
        p.canChooseFiles = true; p.canChooseDirectories = true; p.allowsMultipleSelection = true
        if p.runModal() == .OK { queue.add(urls: p.urls) }
    }
}

// MARK: Pull

struct PullView: View {
    @Bindable var model: AppModel
    let openSettings: () -> Void

    var body: some View {
        if model.lockState != .unlocked {
            Placeholder(title: "Unlock the vault first", text: "Pulling needs the passphrase to open the sealed files. Unlock it in the Vault section.")
        } else {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Button(model.pullRunning ? "Pulling…" : "Pull from server") { Task { await model.pull() } }
                        .disabled(model.pullRunning)
                    if model.pullRunning { ProgressView().controlSize(.small) }
                }
                if let m = model.pullMessage { Text(verbatim: m).foregroundStyle(.red) }
                if let s = model.pullSummary { Text(verbatim: s) }
                List(model.pullItems) { item in
                    HStack {
                        Text(verbatim: String(item.id.prefix(8))).font(.system(.body, design: .monospaced))
                        Spacer()
                        switch item.kind {
                        case .ingested: Label("added", systemImage: "checkmark.circle").foregroundStyle(.green)
                        case .alreadyIngested: Text("already in the vault").foregroundStyle(.secondary)
                        case .notAuthentic: Label("not authentic — left on the server", systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                        case .conflict: Text("conflicts with an existing file — left on the server").foregroundStyle(.red)
                        case .error: Text("failed — left on the server").foregroundStyle(.red)
                        }
                    }
                }
                Text("Pulled files are listed by id, not name: names stay inside the vault. Rebuild the listing in Vault to see them.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding()
        }
    }
}
