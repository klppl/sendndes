import AppCore
import AppKit
import SwiftUI

/// The ⌘, window. Each control saves where it stands; only the server address and token have a Save
/// button, because they are checked together.
struct SettingsView: View {
    @Bindable var model: AppModel

    var body: some View {
        TabView {
            GeneralTab(model: model).tabItem { Label("General", systemImage: "gearshape") }
            ServerTab(model: model).tabItem { Label("Server", systemImage: "network") }
            SecurityTab(model: model).tabItem { Label("Security", systemImage: "lock.shield") }
        }
        .frame(width: 540)
        .tint(Theme.pink)
    }
}

private struct GeneralTab: View {
    @Bindable var model: AppModel
    @AppStorage(Prefs.pullOnUnlock) private var pullOnUnlock = true
    @AppStorage(Prefs.skipOpenWarning) private var skipOpenWarning = false

    private static let lockChoices = [1, 5, 10, 15, 30, 60, 120]

    var body: some View {
        Form {
            Section {
                LabeledContent("Vault folder") {
                    HStack {
                        Text(verbatim: model.vaultPath.isEmpty ? "None" : model.vaultPath)
                            .lineLimit(1).truncationMode(.middle).foregroundStyle(.secondary)
                        Button("Change…") { FilePanels.openExistingVault(model) }
                    }
                }
            } footer: {
                Text("Changing the folder locks the current vault.").font(.caption).foregroundStyle(.secondary)
            }
            Section {
                Picker("Lock after", selection: $model.autoLockMinutes) {
                    ForEach(Self.lockChoices + (Self.lockChoices.contains(model.autoLockMinutes) ? [] : [model.autoLockMinutes]), id: \.self) {
                        Text("\($0) min without activity").tag($0)
                    }
                }
            } footer: {
                Text("The vault also locks at once when the Mac sleeps, the screen locks or you switch user. Waiting for inactivity never interrupts a running transfer.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section {
                Toggle("Check the inbox when the vault unlocks", isOn: $pullOnUnlock)
                Toggle("Ask before opening a decrypted copy", isOn: Binding(get: { !skipOpenWarning }, set: { skipOpenWarning = !$0 }))
            }
        }
        .formStyle(.grouped)
    }
}

private struct ServerTab: View {
    let model: AppModel
    @State private var keysNote: String?

    var body: some View {
        Form {
            Section {
                ServerForm(model: model)
            } header: {
                Text("Inbox server")
            }
            Section {
                LabeledContent {
                    Button("Copy Server Keys") { copyServerKeys() }.disabled(model.lockState != .unlocked)
                } label: {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Server keys")
                        Text(model.lockState == .unlocked ? "Paste into the valvd admin page, step 1." : "Unlock the vault first.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                if let keysNote { Text(verbatim: keysNote).font(.callout) }
            } footer: {
                Text("These let your server seal files for this vault. They can't decrypt anything, but anyone holding them can add files that look authentic, and they can't be rotated: give them only to your own server. The clipboard is cleared after 60 seconds.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }

    private func copyServerKeys() {
        keysNote = nil
        Task {
            guard let keys = await model.serverKeys() else { keysNote = "Could not read the keys. Is the vault unlocked?"; return }
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(keys.clipboardText, forType: .string)
            pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            let count = pb.changeCount
            keysNote = "Copied. Check value \(keys.fingerprint); the admin page should show the same."
            DispatchQueue.main.asyncAfter(deadline: .now() + 60) {
                if NSPasteboard.general.changeCount == count { NSPasteboard.general.clearContents() }
            }
        }
    }
}

private struct SecurityTab: View {
    @Bindable var model: AppModel

    var body: some View {
        Form {
            if model.touchIDAvailable {
                Section {
                    Toggle("Unlock with Touch ID", isOn: Binding(
                        get: { model.touchIDEnabled },
                        set: { $0 ? model.enableTouchID() : model.disableTouchID() }))
                        .disabled(!model.touchIDEnabled && model.lockState != .unlocked)
                    if let m = model.touchIDMessage { Text(verbatim: m).font(.callout) }
                } footer: {
                    Text("Keeps the passphrase in your login keychain behind Touch ID (or your Mac password). Convenient, but weaker than typing it: anything running as you while the keychain is open could read it. Unlock the vault first to turn it on.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Section {
                RecoveryReveal(model: model)
            } header: {
                Text("Recovery key")
            } footer: {
                Text("Anyone who sees the recovery key can open the vault without the passphrase. Show it only when you are writing it down; it hides itself after 30 seconds.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
    }
}

/// Shows the recovery key again after the passphrase (or Touch ID) is given. Hides itself after 30 seconds,
/// when the window closes, and when the vault locks.
struct RecoveryReveal: View {
    @Bindable var model: AppModel
    @State private var pass = ""
    @State private var key: String?
    @State private var working = false
    @State private var hideTask: Task<Void, Never>?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let key {
                Text(verbatim: key).font(.system(.body, design: .monospaced).bold()).textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                    .background(Theme.sun.opacity(0.3), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Button("Hide") { hide() }
            } else if model.lockState != .unlocked {
                Text("Unlock the vault to show the recovery key.").foregroundStyle(.secondary)
            } else {
                HStack(spacing: 8) {
                    SecureField("Passphrase", text: $pass, prompt: Text("Type your passphrase to show it"))
                        .labelsHidden().onSubmit { reveal(typed: true) }
                    Button("Show") { reveal(typed: true) }.disabled(pass.isEmpty || working)
                    if model.touchIDEnabled {
                        Button { reveal(typed: false) } label: { Image(systemName: "touchid") }
                            .disabled(working).help("Show with Touch ID")
                    }
                }
            }
            if let m = model.recoveryMessage { Text(verbatim: m).font(.callout) }
        }
        .onChange(of: model.lockState) { _, new in if new != .unlocked { hide() } }
        .onDisappear { hide() }
    }

    private func hide() { hideTask?.cancel(); key = nil; pass = "" }

    private func reveal(typed: Bool) {
        let p = typed ? pass : nil
        pass = ""
        working = true
        Task {
            let k = await model.revealRecoveryKey(passphrase: p)
            working = false
            guard let k else { return }
            key = k
            hideTask = Task {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                if !Task.isCancelled { hide() }
            }
        }
    }
}
