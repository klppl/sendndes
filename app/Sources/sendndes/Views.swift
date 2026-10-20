import AppCore
import AppKit
import SwiftUI
import UniformTypeIdentifiers

enum Pane: String, CaseIterable, Identifiable {
    case vault, send, pull
    var id: String { rawValue }
    var title: String {
        switch self {
        case .vault: "Vault"
        case .send: "Send"
        case .pull: "Pull"
        }
    }
    var blurb: String {
        switch self {
        case .vault: "your stash"
        case .send: "toss it over"
        case .pull: "reel it in"
        }
    }
    var icon: String {
        switch self {
        case .vault: "lock.shield.fill"
        case .send: "paperplane.fill"
        case .pull: "tray.and.arrow.down.fill"
        }
    }
    var tint: Color {
        switch self {
        case .vault: Theme.grape
        case .send: Theme.pink
        case .pull: Theme.mint
        }
    }
    var key: Character {
        switch self {
        case .vault: "1"
        case .send: "2"
        case .pull: "3"
        }
    }
}

struct ContentView: View {
    @Bindable var model: AppModel
    @State private var pane: Pane = .vault
    @State private var showSettings = false
    @State private var showCreate = false

    var body: some View {
        NavigationSplitView {
            Sidebar(model: model, pane: $pane)
                .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 270)
        } detail: {
            Group {
                switch pane {
                case .vault: VaultView(model: model, openSettings: { showSettings = true }, openCreate: { showCreate = true })
                case .send: SendView(model: model, queue: model.sendQueue, openSettings: { showSettings = true })
                case .pull: PullView(model: model, openSettings: { showSettings = true }, goVault: { pane = .vault })
                }
            }
            .id(pane)
            .transition(.opacity)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Theme.paper.ignoresSafeArea())
        }
        .animation(.snappy(duration: 0.2), value: pane)
        .toolbar {
            ToolbarItemGroup {
                if model.lockState == .unlocked {
                    Button { model.lock() } label: { Label("Lock", systemImage: "lock") }
                        .keyboardShortcut("l", modifiers: .command)
                        .help("Lock the vault (⌘L)")
                }
                Button { showSettings = true } label: { Label("Settings", systemImage: "gearshape") }
                    .help("Settings")
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

// MARK: Sidebar

struct Sidebar: View {
    let model: AppModel
    @Binding var pane: Pane

    private var mood: Aster.Mood {
        switch model.lockState {
        case .locked: .asleep
        case .unlocking: .flustered
        case .unlocked: .smitten
        case .noFolder: .happy
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Aster(mood: mood, size: 40, interactive: true)
                Wordmark(size: 19)
            }
            .padding(.leading, 4).padding(.bottom, 16)
            ForEach(Pane.allCases) { row($0) }
            Spacer()
            lockChip
        }
        .padding(.horizontal, 12).padding(.bottom, 14).padding(.top, 4)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.paperDeep.ignoresSafeArea())
    }

    private func row(_ p: Pane) -> some View {
        let selected = pane == p
        return Button { pane = p } label: {
            HStack(spacing: 10) {
                Image(systemName: p.icon).font(.system(size: 14, weight: .bold))
                    .foregroundStyle(Theme.onAccent).frame(width: 30, height: 30)
                    .background(p.tint, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(Theme.ink, lineWidth: 1.5))
                VStack(alignment: .leading, spacing: 0) {
                    Text(p.title).label(.body, weight: .bold).foregroundStyle(Theme.ink)
                    Text(p.blurb).font(.caption).foregroundStyle(Theme.inkSoft)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8).padding(.vertical, 6)
            .contentShape(Rectangle())
            .sticker(radius: 13, shadow: selected ? 3 : 0, fill: selected ? Theme.card : .clear, outlined: selected)
        }
        .buttonStyle(.plain)
        .padding(.trailing, 3).padding(.bottom, 3)
        .keyboardShortcut(KeyEquivalent(p.key), modifiers: .command)
        .accessibilityLabel("\(p.title), \(p.blurb)")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    @ViewBuilder private var lockChip: some View {
        switch model.lockState {
        case .unlocked:
            Button { model.lock() } label: {
                Label("Unlocked · lock now", systemImage: "lock.open.fill").frame(maxWidth: .infinity)
            }
            .buttonStyle(.chunkySmall).help("Lock the vault")
        case .locked, .unlocking:
            chip("Locked and napping", "moon.zzz.fill", Theme.grape)
        case .noFolder:
            chip("No vault yet", "sparkles", Theme.sun)
        }
    }

    private func chip(_ text: String, _ icon: String, _ tint: Color) -> some View {
        HStack(spacing: 7) {
            Image(systemName: icon).foregroundStyle(tint)
            Text(text).label(.callout, weight: .semibold).foregroundStyle(Theme.ink)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10).padding(.vertical, 7)
        .background(tint.opacity(0.18), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(tint, lineWidth: 1.5))
    }
}

// MARK: Sheets

/// Title row shared by the sheets.
private struct SheetHeader: View {
    var mood: Aster.Mood = .happy
    let title: String
    var body: some View {
        HStack(spacing: 12) {
            Aster(mood: mood, size: 50, interactive: true)
            Text(title).display(26).foregroundStyle(Theme.ink)
            Spacer()
        }
    }
}

private struct FieldLabel<Content: View>: View {
    let title: String
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title).label(.caption, weight: .bold).foregroundStyle(Theme.inkSoft).textCase(.uppercase).tracking(0.6)
            content
        }
    }
}

/// A "folder chosen" box with a Choose… button.
private struct FolderPicker: View {
    let path: String
    let action: () -> Void
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "folder.fill").foregroundStyle(Theme.sun).frame(width: 18)
            Text(verbatim: path.isEmpty ? "None chosen" : path)
                .label(.body, weight: .medium).foregroundStyle(path.isEmpty ? Theme.inkSoft : Theme.ink)
                .lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 6)
            Button("Choose…", action: action).buttonStyle(.chunkySmall)
        }
        .padding(.leading, 12).padding(.trailing, 4).padding(.vertical, 5)
        .background(Theme.paper, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
    }
}

struct SettingsView: View {
    let model: AppModel
    let close: () -> Void
    @State private var url = ""
    @State private var token = ""
    @State private var vault = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(title: "Settings")
            FieldLabel(title: "Server address") {
                TextField("Server address", text: $url, prompt: Text(verbatim: "http://100.x.y.z:8485 or https://…"))
                    .textFieldStyle(StickerFieldStyle(icon: "network")).labelsHidden()
            }
            FieldLabel(title: "Bearer token") {
                SecureField("Bearer token", text: $token,
                            prompt: Text(model.tokenIsSet ? "Saved in the Keychain; type to replace" : "Paste the token"))
                    .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
            }
            FieldLabel(title: "Vault folder") { FolderPicker(path: vault, action: chooseVault) }
            Note(text: "The token is kept in your login keychain: not synchronizable, not iCloud-synced, readable while the login keychain is unlocked (normally the whole login session). macOS may ask you to allow access after each rebuild of this app.")
            if let error { Banner(kind: .error, text: error) }
            HStack(spacing: 10) {
                Spacer()
                Button("Cancel", action: close).buttonStyle(.chunky).keyboardShortcut(.cancelAction)
                Button("Save") { save() }.buttonStyle(.chunkyPrimary).keyboardShortcut(.defaultAction)
            }
        }
        .padding(24).frame(width: 560)
        .background(Theme.paper)
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

struct CreateVaultView: View {
    @Bindable var model: AppModel
    let close: () -> Void
    @State private var folder = ""
    @State private var pass = ""
    @State private var again = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(mood: model.creating ? .working : .happy, title: "Build a vault")
            FieldLabel(title: "Folder") { FolderPicker(path: folder, action: choose) }
            Note(text: "Pick an empty folder, or make a new one in the dialog. If it is inside Google Drive or Dropbox, the sealed files will sync there.")
            FieldLabel(title: "Passphrase") {
                SecureField("Passphrase (at least \(AppModel.minPassphraseCharacters) characters)", text: $pass)
                    .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
            }
            SecureField("Repeat passphrase", text: $again)
                .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
            Note(text: "Nobody can reset the passphrase. You will get a recovery key once; it is the only way back in if you forget the passphrase.")
            if let m = model.createMessage { Banner(kind: .error, text: m) }
            HStack(spacing: 10) {
                Spacer()
                Button("Cancel") { model.createMessage = nil; close() }.buttonStyle(.chunky).keyboardShortcut(.cancelAction)
                Button(model.creating ? "Creating…" : "Create vault") { create() }
                    .buttonStyle(.chunkyPrimary).keyboardShortcut(.defaultAction).disabled(model.creating)
            }
        }
        .padding(24).frame(width: 540)
        .background(Theme.paper)
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
        let matches = !typed.isEmpty && normalized(typed) == normalized(key)
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(mood: matches ? .happy : .wow, title: "Your recovery key")
            Text("The vault is created. Write this key down or store it in a password manager now. It is shown only once, this app does not keep it, and without it a forgotten passphrase cannot be undone.")
                .label(.body, weight: .medium).foregroundStyle(Theme.ink)
            ticket(key)
            FieldLabel(title: "Prove you wrote it down") {
                TextField("Type the key again to confirm", text: $typed)
                    .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
                    .font(.system(.body, design: .monospaced)).autocorrectionDisabled()
            }
            HStack {
                if matches {
                    Label("That's the one.", systemImage: "checkmark.circle.fill").label(.callout).foregroundStyle(Theme.mintText)
                } else if !typed.isEmpty {
                    Text("That doesn't match yet.").label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
                }
                Spacer()
                Button("I have stored it") { model.acknowledgeRecoveryKey() }
                    .buttonStyle(.chunkyPrimary).keyboardShortcut(.defaultAction).disabled(!matches)
            }
        }
        .padding(24).frame(width: 560)
        .background(Theme.paper)
        .animation(.snappy(duration: 0.2), value: matches)
    }

    private func ticket(_ key: String) -> some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "key.horizontal.fill")
                Text("RECOVERY KEY · SHOWN ONCE").tracking(1.2)
                Spacer()
            }
            .label(.caption, weight: .bold).foregroundStyle(Theme.ink.opacity(0.75))
            .padding(.horizontal, 16).padding(.vertical, 10)
            Line().stroke(Theme.ink.opacity(0.6), style: StrokeStyle(lineWidth: 2, dash: [6, 6])).frame(height: 2)
            Text(verbatim: key)
                .font(.system(size: 21, weight: .bold, design: .monospaced)).foregroundStyle(Theme.ink)
                .textSelection(.enabled).multilineTextAlignment(.center)
                .padding(.horizontal, 16).padding(.vertical, 18).frame(maxWidth: .infinity)
        }
        .background(Theme.sun.opacity(0.3), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .sticker(radius: 16, shadow: 4)
        .padding(.trailing, 4).padding(.bottom, 4)
    }
}

private struct Line: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.minX, y: r.midY)); p.addLine(to: CGPoint(x: r.maxX, y: r.midY))
        return p
    }
}

// MARK: Transfer lists (Send queue, adding to the vault)

struct TransferList: View {
    let items: [SendItem]
    let activeText: String
    let doneText: String
    var retry: ((UUID) -> Void)?

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(Array(items.enumerated()), id: \.element.id) { i, item in
                    row(item)
                    if i < items.count - 1 { Divider().overlay(Theme.ink.opacity(0.12)).padding(.horizontal, 12) }
                }
            }
        }
        .sticker(radius: 14)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
    }

    @ViewBuilder private func row(_ item: SendItem) -> some View {
        switch item.state {
        case .waiting:
            FileRow(name: item.displayName) { Pill(text: "waiting", icon: "clock", tint: Theme.inkSoft) }
        case .sending:
            FileRow(name: item.displayName) { Pill(text: activeText, tint: Theme.grape, spinner: true) }
        case .sent:
            FileRow(name: item.displayName) { Pill(text: doneText, icon: "checkmark", tint: Theme.mint) }
        case .failed(let m):
            FileRow(name: item.displayName, detail: m, detailIsError: true) {
                HStack(spacing: 8) {
                    Pill(text: "failed", icon: "xmark", tint: Theme.tomato)
                    if let retry { Button("Retry") { retry(item.id) }.buttonStyle(.chunkySmall) }
                }
            }
        }
    }
}

// MARK: Vault

struct VaultView: View {
    @Bindable var model: AppModel
    let openSettings: () -> Void
    let openCreate: () -> Void
    @State private var passphrase = ""
    @State private var selection = Set<FileEntry.ID>()
    @State private var query = ""
    @State private var targeted = false
    @State private var shakes: CGFloat = 0

    var body: some View {
        switch model.lockState {
        case .noFolder:
            EmptyState(mood: .happy, title: "Let's build you a vault",
                       text: "Create a new vault, or choose the folder of an existing one in Settings.",
                       button: "Create a vault…", action: openCreate,
                       secondaryButton: "Use an existing folder…", secondaryAction: openSettings)
        case .locked, .unlocking:
            lockedView
        case .unlocked:
            unlockedView
        }
    }

    // MARK: Locked

    private var lockedView: some View {
        let unlocking = model.lockState == .unlocking
        let mood: Aster.Mood = unlocking ? .flustered : (model.vaultMessage != nil ? .oops : .asleep)
        return ScrollView {
            VStack(spacing: 14) {
                Aster(mood: mood, size: 150, interactive: true)
                Text(unlocking ? "Ooh… getting warmed up…" : "Shh. The vault is napping.").display(28).foregroundStyle(Theme.ink)
                Text("Whisper the passphrase to wake it up.").label(.body, weight: .medium).foregroundStyle(Theme.inkSoft)
                Text(verbatim: model.vaultPath).font(.system(.caption, design: .monospaced)).foregroundStyle(Theme.inkSoft)
                    .lineLimit(1).truncationMode(.middle).frame(maxWidth: 380)
                VStack(spacing: 12) {
                    SecureField("Passphrase", text: $passphrase)
                        .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
                        .onSubmit(unlock)
                    Button(unlocking ? "Unlocking…" : "Unlock", action: unlock)
                        .buttonStyle(.chunkyPrimary)
                        .disabled(unlocking || passphrase.isEmpty)
                        .keyboardShortcut(.defaultAction)
                }
                .frame(width: 300)
                if let m = model.vaultMessage { Banner(kind: .error, text: m).frame(maxWidth: 400) }
                Button("Create a new vault instead…", action: openCreate).buttonStyle(.chunkyQuietSmall)
                Note(text: "Listing opens every file in the vault. In Google Drive “stream” mode or Dropbox online-only folders this can download files and take a while.")
                    .frame(maxWidth: 420)
            }
            .modifier(Shake(shakes: shakes))
            .padding(24)
            .frame(maxWidth: .infinity, minHeight: 440)
        }
        .onChange(of: model.vaultMessage) { _, new in
            if new != nil && model.lockState == .locked { withAnimation(.linear(duration: 0.45)) { shakes += 3 } }
        }
    }

    // MARK: Unlocked

    private var visible: [FileEntry] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return model.entries }
        return model.entries.filter { $0.name.localizedCaseInsensitiveContains(q) || $0.dir.localizedCaseInsensitiveContains(q) }
    }

    private var chosen: [FileEntry] { visible.filter { selection.contains($0.id) } }

    private var subtitle: String {
        switch model.entries.count {
        case 0: "Empty. Suspiciously tidy."
        case 1: "1 file, all tucked in."
        default: "\(model.entries.count) files tucked away."
        }
    }

    private var unlockedView: some View {
        let shown = visible
        return VStack(alignment: .leading, spacing: 12) {
            PaneHeader(mood: model.busy || model.adding ? .working : .smitten, title: "Your vault", subtitle: subtitle,
                       sparkle: model.addItems.filter { $0.state == .sent }.count) { EmptyView() }
            HStack(spacing: 10) {
                Button { addFiles() } label: { Label("Add files…", systemImage: "plus") }
                    .buttonStyle(.chunkyPrimary).disabled(model.adding)
                Button { openSelected() } label: { Label("Open", systemImage: "arrow.up.forward.app") }
                    .buttonStyle(.chunky).disabled(chosen.count != 1 || model.busy)
                Button { exportSelected() } label: { Label("Export…", systemImage: "square.and.arrow.up") }
                    .buttonStyle(.chunky).disabled(chosen.isEmpty || model.exporting)
                Spacer()
                Button { Task { await model.rebuildListing() } } label: {
                    Label(model.busy ? "Working…" : "Rebuild listing", systemImage: "arrow.clockwise")
                }
                .buttonStyle(.chunkyQuiet).disabled(model.busy)
                .help("Read the whole vault again and refresh this list")
            }
            if model.listingProblems > 0 {
                Banner(kind: .warn, text: "\(model.listingProblems) problems — run `valv verify` in Terminal.")
            }
            if model.listingStale { Banner(kind: .info, text: "List may be out of date after the pull.") }
            if !model.addItems.isEmpty {
                HStack {
                    Text("Tucking files in").label(.callout, weight: .bold).foregroundStyle(Theme.ink)
                    Spacer()
                    if model.addItems.contains(where: { $0.state == .sent }) {
                        Button("Clear finished") { model.clearAddFinished() }.buttonStyle(.chunkyQuietSmall)
                    }
                }
                TransferList(items: model.addItems, activeText: "sealing…", doneText: "tucked in")
                    .frame(maxHeight: 170)
            }
            ForEach(model.addNotes, id: \.self) { Banner(kind: .info, text: $0) }
            if let m = model.vaultMessage { Banner(kind: .error, text: m) }
            if let m = model.openMessage { Banner(kind: .warn, text: m) }
            if let m = model.exportMessage {
                Banner(kind: .success, text: m,
                       actionTitle: model.exportFolder == nil ? nil : "Show in Finder",
                       action: { if let f = model.exportFolder { NSWorkspace.shared.open(URL(fileURLWithPath: f)) } })
            }
            table(shown)
            Note(text: "Open and Export hand you a decrypted copy that the vault no longer protects. Opened copies are kept in a private temporary folder and deleted when you lock or quit, but the app you open them in may keep its own copy. Exported copies stay where you put them (watch out for synced or indexed folders).")
        }
        .padding(20)
        .overlay { if targeted { DropHint(title: "Drop to tuck it in").padding(10) } }
        .animation(.snappy(duration: 0.18), value: targeted)
        .dropDestination(for: URL.self) { urls, _ in
            model.addToVault(urls: urls.filter { $0.isFileURL })
            return true
        } isTargeted: { targeted = $0 }
        .searchable(text: $query, placement: .toolbar, prompt: "Search names and folders")
        .onChange(of: query) { _, _ in
            let ids = Set(visible.map(\.id))
            selection = selection.intersection(ids)
        }
    }

    private func table(_ shown: [FileEntry]) -> some View {
        Table(shown, selection: $selection) {
            TableColumn("Name") { e in
                HStack(spacing: 8) {
                    FileGlyph(name: e.name, size: 20)
                    Text(verbatim: e.name).label(.body, weight: .semibold).lineLimit(1).truncationMode(.middle)
                }
            }
            TableColumn("Folder") { e in Text(verbatim: e.dir).foregroundStyle(Theme.inkSoft) }
            TableColumn("Size") { e in Text(verbatim: ByteCountFormatter.string(fromByteCount: e.size, countStyle: .file)) }
                .width(80)
            TableColumn("Modified") { e in Text(verbatim: e.mtime.formatted(date: .abbreviated, time: .shortened)) }
                .width(130)
            TableColumn("ID") { e in Text(verbatim: e.shortID).font(.system(.callout, design: .monospaced)).foregroundStyle(Theme.inkSoft) }
                .width(80)
        }
        .scrollContentBackground(.hidden)
        .frame(minHeight: 180, idealHeight: 340)
        .background(Theme.card)
        .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
        .overlay {
            if shown.isEmpty {
                VStack(spacing: 8) {
                    Aster(mood: model.entries.isEmpty ? .asleep : .oops, size: 84)
                    if model.entries.isEmpty {
                        Text("Nothing in here yet").display(20).foregroundStyle(Theme.ink)
                        Text("Drop files anywhere in this window, or hit Add files.").label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
                    } else {
                        Text("No matches").display(20).foregroundStyle(Theme.ink)
                        Text(verbatim: "Nothing in the vault matches “\(query)”.").label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
                    }
                }
                .padding(.top, 24)
                .allowsHitTesting(false)
            }
        }
        .contextMenu(forSelectionType: FileEntry.ID.self) { ids in
            if ids.count == 1 { Button("Open") { selection = ids; openSelected() } }
            Button("Export…") { selection = ids; exportSelected() }
        } primaryAction: { ids in
            if ids.count == 1 { selection = ids; openSelected() }
        }
    }

    private func openSelected() {
        let c = chosen
        guard c.count == 1, let e = c.first else { return }
        Task { if let url = await model.prepareOpen(e) { NSWorkspace.shared.open(url) } }
    }

    private func exportSelected() {
        let chosen = self.chosen
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

// MARK: Send

struct SendView: View {
    let model: AppModel
    @Bindable var queue: SendQueue
    let openSettings: () -> Void
    @State private var targeted = false

    private var configured: Bool { model.tokenIsSet && !model.serverURLText.isEmpty }
    private var sentCount: Int { queue.items.filter { $0.state == .sent }.count }

    private var subtitle: String {
        if queue.items.isEmpty { return "Toss files over to the server." }
        return "\(queue.items.count) in the queue · \(sentCount) sent."
    }

    var body: some View {
        if !configured {
            EmptyState(mood: .oops, title: "Where do the files go?",
                       text: "Server not set up. Enter the server address and token in Settings.",
                       button: "Open Settings", action: openSettings)
        } else {
            content
                .dropDestination(for: URL.self) { urls, _ in
                    queue.add(urls: urls.filter { $0.isFileURL })
                    return true
                } isTargeted: { targeted = $0 }
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 12) {
            PaneHeader(mood: queue.running ? .working : .happy, title: "Send", subtitle: subtitle, sparkle: sentCount) {
                HStack(spacing: 10) {
                    if sentCount > 0 { Button("Clear finished") { queue.clearFinished() }.buttonStyle(.chunkyQuiet) }
                    Button { addFiles() } label: { Label("Add files…", systemImage: "plus") }.buttonStyle(.chunkyPrimary)
                }
            }
            if let r = queue.pausedReason { Banner(kind: .warn, text: r, actionTitle: "Resume") { queue.resume() } }
            ForEach(queue.notes, id: \.self) { Banner(kind: .info, text: $0) }
            if queue.items.isEmpty {
                dropZone
            } else {
                TransferList(items: queue.items, activeText: "sending…", doneText: "sent!") { queue.retry($0) }
            }
            Note(text: "Files are sent one at a time. If a send fails and you retry, the vault can end up with a duplicate. Don't send files that are still being written. In this version the server briefly sees the file's contents and name while it seals them.")
        }
        .padding(20)
        .overlay { if targeted && !queue.items.isEmpty { DropHint(title: "Drop to send").padding(10) } }
        .animation(.snappy(duration: 0.18), value: targeted)
    }

    private var dropZone: some View {
        VStack(spacing: 10) {
            Aster(mood: targeted ? .wow : .happy, size: 124, interactive: true)
            Text(targeted ? "Ooh. Let go!" : "Drop files here").display(28).foregroundStyle(Theme.ink)
            Text("Folders too. We don't judge.").label(.body, weight: .medium).foregroundStyle(Theme.inkSoft)
            Button("Choose files…", action: addFiles).buttonStyle(.chunky).padding(.top, 4)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(targeted ? Theme.pink.opacity(0.16) : Theme.card.opacity(0.55)))
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(targeted ? Theme.pink : Theme.ink.opacity(0.5),
                              style: StrokeStyle(lineWidth: targeted ? 4 : 2.5, dash: targeted ? [] : [10, 8]))
        )
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
    let goVault: () -> Void

    private var added: Int { model.pullItems.filter { $0.kind == .ingested }.count }

    var body: some View {
        if model.lockState != .unlocked {
            EmptyState(mood: .asleep, title: "Unlock the vault first",
                       text: "Pulling needs the passphrase to open the sealed files. Unlock it in the Vault section.",
                       button: "Go to the vault", action: goVault)
        } else {
            VStack(alignment: .leading, spacing: 12) {
                PaneHeader(mood: model.pullRunning ? .working : .smitten, title: "Pull",
                           subtitle: "Reel in whatever is waiting on the server.", sparkle: added) {
                    Button(model.pullRunning ? "Pulling…" : "Pull from server") { Task { await model.pull() } }
                        .buttonStyle(.chunkyPrimary).disabled(model.pullRunning)
                }
                if let m = model.pullMessage { Banner(kind: .error, text: m) }
                if let s = model.pullSummary { Banner(kind: .info, text: s) }
                if model.pullItems.isEmpty {
                    VStack(spacing: 8) {
                        Aster(mood: model.pullRunning ? .working : .asleep, size: 96)
                        Text("Nothing pulled yet").display(22).foregroundStyle(Theme.ink)
                        Text("Hit the button when you're expecting something.").label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(model.pullItems.enumerated()), id: \.element.id) { i, item in
                                FileRow(name: String(item.id.prefix(8)), showsIcon: false, mono: true) { pill(item.kind) }
                                if i < model.pullItems.count - 1 { Divider().overlay(Theme.ink.opacity(0.12)).padding(.horizontal, 12) }
                            }
                        }
                    }
                    .sticker(radius: 14)
                    .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                }
                Note(text: "Pulled files are listed by id, not name: names stay inside the vault. Rebuild the listing in Vault to see them.")
            }
            .padding(20)
        }
    }

    @ViewBuilder private func pill(_ kind: PullKind) -> some View {
        switch kind {
        case .ingested: Pill(text: "added", icon: "checkmark", tint: Theme.mint)
        case .alreadyIngested: Pill(text: "already in the vault", icon: "tray.full", tint: Theme.inkSoft)
        case .notAuthentic: Pill(text: "not authentic — left on the server", icon: "exclamationmark.triangle.fill", tint: Theme.tomato)
        case .conflict: Pill(text: "conflicts with an existing file — left on the server", icon: "xmark", tint: Theme.tomato)
        case .error: Pill(text: "failed — left on the server", icon: "xmark", tint: Theme.tomato)
        }
    }
}
