import AppCore
import AppKit
import SwiftUI

/// Two places: the vault (yours, needs the passphrase) and Send (to the inbox server, works while locked).
/// Pulling is not a place: it happens when the vault unlocks and from "Check inbox".
enum Pane: String, CaseIterable, Identifiable {
    case vault, send
    var id: String { rawValue }
    var title: String {
        switch self {
        case .vault: "Vault"
        case .send: "Send"
        }
    }
    var icon: String {
        switch self {
        case .vault: "lock.shield.fill"
        case .send: "paperplane.fill"
        }
    }
    var tint: Color {
        switch self {
        case .vault: Theme.grape
        case .send: Theme.pink
        }
    }
    var key: Character {
        switch self {
        case .vault: "1"
        case .send: "2"
        }
    }
}

/// Preference keys owned by the views (AppCore keeps its own).
enum Prefs {
    static let pullOnUnlock = "pullOnUnlock"
    static let skipOpenWarning = "skipOpenWarning"
    static let recentVaults = "recentVaults"
}

/// Vault folders used on this Mac, most recent first, for one-click switching on the lock screen.
enum RecentVaults {
    static let limit = 6

    static func list() -> [String] {
        (UserDefaults.standard.stringArray(forKey: Prefs.recentVaults) ?? [])
            .filter { FileManager.default.fileExists(atPath: $0) }
    }

    static func note(_ path: String) {
        guard !path.isEmpty else { return }
        let rest = (UserDefaults.standard.stringArray(forKey: Prefs.recentVaults) ?? []).filter { $0 != path }
        UserDefaults.standard.set(Array(([path] + rest).prefix(limit)), forKey: Prefs.recentVaults)
    }
}

extension AppModel {
    var serverConfigured: Bool { tokenIsSet && !tokenNeedsReentry && !serverURLText.isEmpty }

    /// Pull, then refresh the list so the arrivals show up by name.
    func pullAndRefresh() async {
        await pull()
        if listingStale { await rebuildListing() }
    }

    /// Ids added by the last pull; cleared on lock.
    var arrivedIDs: Set<String> { Set(pullItems.filter { $0.kind == .ingested }.map(\.id)) }
}

/// Open panels shared by the views and the menu bar.
@MainActor
enum FilePanels {
    static func addToVault(_ model: AppModel) {
        let p = NSOpenPanel()
        p.canChooseFiles = true; p.canChooseDirectories = true; p.allowsMultipleSelection = true
        p.prompt = "Add to vault"
        p.message = "Files are encrypted on this Mac. The originals stay where they are."
        if p.runModal() == .OK { model.addToVault(urls: p.urls) }
    }

    static func send(_ queue: SendQueue) {
        let p = NSOpenPanel()
        p.canChooseFiles = true; p.canChooseDirectories = true; p.allowsMultipleSelection = true
        p.prompt = "Send"
        if p.runModal() == .OK { queue.add(urls: p.urls) }
    }

    /// Points the app at an existing vault folder (locks the current one). True if a folder was chosen.
    @discardableResult
    static func openExistingVault(_ model: AppModel) -> Bool {
        let p = NSOpenPanel()
        p.canChooseDirectories = true; p.canChooseFiles = false; p.allowsMultipleSelection = false
        p.prompt = "Open vault"
        p.message = "Choose the folder that holds your vault (the one with vault.json)."
        guard p.runModal() == .OK, let u = p.url else { return false }
        model.setVaultPath(u.path)
        return true
    }
}

struct ContentView: View {
    @Bindable var model: AppModel
    @State private var pane: Pane = .vault
    @State private var showCreate = false
    @AppStorage(Prefs.pullOnUnlock) private var pullOnUnlock = true

    var body: some View {
        NavigationSplitView {
            Sidebar(model: model, pane: $pane)
                .navigationSplitViewColumnWidth(min: 190, ideal: 210, max: 260)
        } detail: {
            Group {
                switch pane {
                case .vault: VaultView(model: model, openCreate: { showCreate = true }, goSend: { pane = .send })
                case .send: SendView(model: model, queue: model.sendQueue)
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
                        .help("Lock the vault (⌘L)")
                }
                SettingsLink { Label("Settings", systemImage: "gearshape") }
                    .help("Settings (⌘,)")
            }
        }
        .sheet(isPresented: Binding(get: { model.recoveryKey != nil }, set: { _ in })) {
            RecoveryKeyView(model: model).interactiveDismissDisabled()
        }
        .sheet(isPresented: $showCreate) { CreateVaultView(model: model, close: { showCreate = false }) }
        .onAppear { RecentVaults.note(model.vaultPath) }
        .onChange(of: model.vaultPath) { _, new in RecentVaults.note(new) }
        .onChange(of: model.lockState) { _, new in
            guard new == .unlocked, pullOnUnlock, model.serverConfigured else { return }
            Task { await model.pullAndRefresh() }
        }
    }
}

// MARK: Sidebar

struct Sidebar: View {
    let model: AppModel
    @Binding var pane: Pane

    private var mood: Aster.Mood {
        switch model.lockState {
        case .locked: .asleep
        case .unlocking: .working
        case .unlocked, .noFolder: .happy
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Aster(mood: mood, size: 36, interactive: true)
                Wordmark(size: 18)
            }
            .padding(.leading, 4).padding(.bottom, 14)
            ForEach(Pane.allCases) { row($0) }
            Spacer()
            lockChip
        }
        .padding(.horizontal, 12).padding(.bottom, 14).padding(.top, 4)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(Theme.paperDeep.ignoresSafeArea())
    }

    /// A small live count next to a pane: files still to send, or files that just arrived.
    private func badge(_ p: Pane) -> (Int, Color)? {
        switch p {
        case .vault:
            let n = model.arrivedIDs.count
            return n > 0 ? (n, Theme.mint) : nil
        case .send:
            let n = model.sendQueue.items.filter { $0.state != .sent }.count
            return n > 0 ? (n, Theme.pink) : nil
        }
    }

    private func row(_ p: Pane) -> some View {
        let selected = pane == p
        return Button { pane = p } label: {
            HStack(spacing: 10) {
                Image(systemName: p.icon).font(.system(size: 13, weight: .bold))
                    .foregroundStyle(Theme.onAccent).frame(width: 28, height: 28)
                    .background(p.tint, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(Theme.ink, lineWidth: 1.5))
                Text(p.title).label(.body, weight: .bold).foregroundStyle(Theme.ink)
                Spacer(minLength: 0)
                if let (n, tint) = badge(p) {
                    Text(verbatim: "\(n)").label(.caption, weight: .heavy).foregroundStyle(Theme.onAccent)
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(tint, in: Capsule())
                        .overlay(Capsule().strokeBorder(Theme.ink, lineWidth: 1.5))
                        .transition(.scale.combined(with: .opacity))
                }
            }
            .padding(.horizontal, 7).padding(.vertical, 6)
            .contentShape(Rectangle())
            .sticker(radius: 12, shadow: selected ? 3 : 0, fill: selected ? Theme.card : .clear, outlined: selected)
        }
        .buttonStyle(.plain)
        .padding(.trailing, 3).padding(.bottom, 3)
        .keyboardShortcut(KeyEquivalent(p.key), modifiers: .command)
        .accessibilityLabel(p.title)
        .accessibilityValue(badge(p).map { "\($0.0)" } ?? "")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    @ViewBuilder private var lockChip: some View {
        switch model.lockState {
        case .unlocked:
            Button { model.lock() } label: {
                Label("Lock now", systemImage: "lock.open.fill").frame(maxWidth: .infinity)
            }
            .buttonStyle(.chunkySmall).help("Lock the vault (⌘L)")
        case .locked, .unlocking:
            chip("Locked", "lock.fill", Theme.grape)
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

// MARK: Menu bar

struct AppCommands: Commands {
    let model: AppModel

    var body: some Commands {
        CommandGroup(after: .newItem) {
            Button("Add to Vault…") { FilePanels.addToVault(model) }
                .keyboardShortcut("o")
                .disabled(model.lockState != .unlocked || model.adding)
            Button("Send to Inbox…") { FilePanels.send(model.sendQueue) }
                .keyboardShortcut("o", modifiers: [.command, .shift])
                .disabled(!model.serverConfigured)
            Divider()
            Button("Open Another Vault…") { FilePanels.openExistingVault(model) }
        }
        CommandMenu("Vault") {
            Button("Refresh") { Task { await model.rebuildListing() } }
                .keyboardShortcut("r")
                .disabled(model.lockState != .unlocked || model.busy)
            Button("Check Inbox") { Task { await model.pullAndRefresh() } }
                .keyboardShortcut("i", modifiers: [.command, .shift])
                .disabled(model.lockState != .unlocked || model.pullRunning || !model.serverConfigured)
            Divider()
            Button("Lock") { model.lock() }
                .keyboardShortcut("l")
                .disabled(model.lockState != .unlocked && model.lockState != .unlocking)
        }
    }
}
