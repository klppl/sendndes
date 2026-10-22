import AppCore
import AppKit
import SwiftUI

// MARK: Shared sheet pieces

/// Title row shared by the sheets.
struct SheetHeader: View {
    var mood: Aster.Mood = .happy
    let title: String
    var subtitle: String?
    var body: some View {
        HStack(spacing: 12) {
            Aster(mood: mood, size: 50, interactive: true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).display(26).foregroundStyle(Theme.ink)
                if let subtitle { Text(subtitle).label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft) }
            }
            Spacer()
        }
    }
}

struct FieldLabel<Content: View>: View {
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
struct FolderPicker: View {
    let path: String
    let action: () -> Void
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "folder.fill").foregroundStyle(Theme.sun).frame(width: 18)
            Text(verbatim: path.isEmpty ? "None chosen" : path)
                .label(.body, weight: .medium).foregroundStyle(path.isEmpty ? Theme.inkSoft : Theme.ink)
                .lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 6)
            Button(path.isEmpty ? "Choose…" : "Change…", action: action).buttonStyle(.chunkySmall)
        }
        .padding(.leading, 12).padding(.trailing, 4).padding(.vertical, 5)
        .background(Theme.paper, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
    }
}

/// One live requirement in a form: grey while unmet, a green tick once met.
struct CheckRow: View {
    let text: String
    let met: Bool
    var body: some View {
        Label {
            Text(text).label(.callout, weight: .medium).foregroundStyle(met ? Theme.ink : Theme.inkSoft)
        } icon: {
            Image(systemName: met ? "checkmark.circle.fill" : "circle")
                .foregroundStyle(met ? Theme.mintText : Theme.inkSoft)
        }
        .accessibilityValue(met ? "done" : "not yet")
    }
}

// MARK: Welcome (no vault yet)

struct WelcomeView: View {
    let model: AppModel
    let openCreate: () -> Void
    let goSend: () -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                Aster(mood: .happy, size: 120, interactive: true)
                VStack(spacing: 6) {
                    Text("Hi. Let's keep your files to yourself.").display(28).foregroundStyle(Theme.ink)
                        .multilineTextAlignment(.center)
                    Text("A vault is a folder of encrypted files. Put it anywhere: on this Mac, a NAS, Drive or Dropbox. Only your passphrase opens it.")
                        .label(.body, weight: .medium).foregroundStyle(Theme.inkSoft)
                        .multilineTextAlignment(.center).frame(maxWidth: 460)
                }
                HStack(spacing: 16) {
                    choice(icon: "sparkles", tint: Theme.pink, title: "Create a vault",
                           text: "Start fresh in an empty folder.", primary: true, action: openCreate)
                    choice(icon: "folder.fill", tint: Theme.sun, title: "Open a vault",
                           text: "Use one you already made.", primary: false) { FilePanels.openExistingVault(model) }
                }
                .frame(maxWidth: 560)
                .padding(.top, 4)
                Button("Only here to send files to a server? Set up sending", action: goSend)
                    .buttonStyle(.chunkyQuietSmall)
            }
            .padding(32)
            .frame(maxWidth: .infinity, minHeight: 480)
        }
    }

    private func choice(icon: String, tint: Color, title: String, text: String, primary: Bool,
                        action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 10) {
                Image(systemName: icon).font(.system(size: 20, weight: .bold)).foregroundStyle(Theme.onAccent)
                    .frame(width: 42, height: 42)
                    .background(tint, in: RoundedRectangle(cornerRadius: 11, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
                Text(title).display(19).foregroundStyle(Theme.ink)
                Text(text).label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .sticker(radius: 18, shadow: primary ? 5 : 3)
        }
        .buttonStyle(PressDown())
        .padding(.trailing, 5).padding(.bottom, 5)
        .keyboardShortcut(primary ? .defaultAction : nil)
    }
}

/// Cards that sink a little when pressed.
private struct PressDown: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .offset(x: configuration.isPressed ? 2 : 0, y: configuration.isPressed ? 2 : 0)
            .animation(.snappy(duration: 0.1), value: configuration.isPressed)
    }
}

// MARK: Lock screen

struct LockScreen: View {
    @Bindable var model: AppModel
    let openCreate: () -> Void
    @State private var passphrase = ""
    @State private var shakes: CGFloat = 0
    @FocusState private var fieldFocused: Bool

    private var unlocking: Bool { model.lockState == .unlocking }

    var body: some View {
        let warming = unlocking || !passphrase.isEmpty
        let mood: Aster.Mood = warming ? .flustered : (model.vaultMessage != nil ? .oops : .asleep)
        ScrollView {
            VStack(spacing: 14) {
                Aster(mood: mood, size: 112, interactive: true)
                VStack(spacing: 4) {
                    Text(unlocking ? "Waking up…" : "The vault is napping.").display(28).foregroundStyle(Theme.ink)
                    Text(model.touchIDEnabled ? "Touch ID or your passphrase wakes it up." : "Your passphrase wakes it up.")
                        .label(.body, weight: .medium).foregroundStyle(Theme.inkSoft)
                }
                folderChip
                passField.frame(width: 320)
                if model.touchIDEnabled {
                    Button { touchID() } label: { Label("Use Touch ID", systemImage: "touchid") }
                        .buttonStyle(.chunkyQuietSmall).disabled(unlocking)
                }
                if let m = model.vaultMessage { Banner(kind: .error, text: m).frame(maxWidth: 400) }
            }
            .modifier(Shake(shakes: shakes))
            .padding(28)
            .frame(maxWidth: .infinity, minHeight: 440)
        }
        .onAppear {
            fieldFocused = !model.touchIDEnabled
            // At launch only: a lock screen that appears because you just locked must not prompt at once.
            if !TouchIDPrompt.launched {
                TouchIDPrompt.launched = true
                if NSApp.isActive { autoTouchID() }
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            TouchIDPrompt.launched = true
            autoTouchID()
        }
        // The Touch ID dialog itself takes focus from the app; only a switch to another app re-arms the prompt,
        // so cancelling it leaves you on the lock screen instead of looping.
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
            if !TouchIDPrompt.inFlight { TouchIDPrompt.armed = true }
        }
        .onChange(of: model.vaultMessage) { _, new in
            if new != nil && model.lockState == .locked { withAnimation(.linear(duration: 0.45)) { shakes += 3 } }
        }
    }

    /// Passphrase field with its own ⏎ button, macOS login style.
    private var passField: some View {
        HStack(spacing: 8) {
            Image(systemName: "key.fill").foregroundStyle(Theme.inkSoft).frame(width: 18)
            SecureField("Passphrase", text: $passphrase).textFieldStyle(.plain)
                .focused($fieldFocused).onSubmit(unlock).disabled(unlocking)
            if unlocking {
                ProgressView().controlSize(.small).frame(width: 28, height: 28)
            } else {
                Button(action: unlock) {
                    Image(systemName: "arrow.right").font(.system(size: 13, weight: .heavy))
                        .foregroundStyle(Theme.onAccent).frame(width: 28, height: 28)
                        .background(passphrase.isEmpty ? Theme.inkSoft.opacity(0.35) : Theme.pink, in: Circle())
                        .overlay(Circle().strokeBorder(Theme.ink, lineWidth: 1.5))
                }
                .buttonStyle(.plain).disabled(passphrase.isEmpty)
                .keyboardShortcut(.defaultAction)
                .accessibilityLabel("Unlock")
            }
        }
        .label(.body, weight: .medium)
        .padding(.leading, 12).padding(.trailing, 5).padding(.vertical, 5)
        .background(Theme.card, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
    }

    /// Which vault, and the way to a different one.
    private var folderChip: some View {
        HStack(spacing: 6) {
            Menu {
                let others = RecentVaults.list().filter { $0 != model.vaultPath }
                if !others.isEmpty {
                    Section("Recent") {
                        ForEach(others, id: \.self) { path in
                            Button { switchTo(path) } label: { Text(verbatim: (path as NSString).lastPathComponent) }
                                .help(path)
                        }
                    }
                }
                Button("Open Another Vault…") { if FilePanels.openExistingVault(model) { vaultSwitched() } }
                Button("Create a New Vault…", action: openCreate)
                Divider()
                Button("Show in Finder") { NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: model.vaultPath) }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: "folder.fill").foregroundStyle(Theme.sun)
                    Text(verbatim: (model.vaultPath as NSString).lastPathComponent)
                        .label(.callout, weight: .semibold).foregroundStyle(Theme.ink).lineLimit(1)
                    Image(systemName: "chevron.down").font(.system(size: 9, weight: .bold)).foregroundStyle(Theme.inkSoft)
                }
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(Theme.card.opacity(0.7), in: Capsule())
                .overlay(Capsule().strokeBorder(Theme.ink.opacity(0.35), lineWidth: 1.5))
            }
            .menuStyle(.button).buttonStyle(.plain).fixedSize()
            .help(model.vaultPath)
            HelpTip(title: "Vaults in Drive or Dropbox",
                    text: "Unlocking reads every file in the vault. In Google Drive “stream” mode or Dropbox online-only folders that can make the sync app download them, so the first unlock may take a while.")
        }
    }

    private func unlock() {
        guard !passphrase.isEmpty, !unlocking else { return }
        let p = passphrase
        passphrase = ""
        Task { await model.unlock(passphrase: p) }
    }

    private func switchTo(_ path: String) {
        model.setVaultPath(path)
        vaultSwitched()
    }

    /// You picked this vault yourself, so asking for Touch ID straight away is what you expect.
    private func vaultSwitched() {
        passphrase = ""
        fieldFocused = !model.touchIDEnabled
        if model.touchIDEnabled { touchID() }
    }

    /// One prompt at a time: a second evaluatePolicy while the first is open fails without showing anything.
    private func touchID() {
        guard !TouchIDPrompt.inFlight else { return }
        TouchIDPrompt.inFlight = true
        Task {
            await model.unlockWithTouchID()
            TouchIDPrompt.inFlight = false
        }
    }

    /// Touch ID prompts on its own at launch and when you come back from another app while locked.
    private func autoTouchID() {
        guard model.touchIDEnabled, model.lockState == .locked, TouchIDPrompt.armed else { return }
        TouchIDPrompt.armed = false
        touchID()
    }
}

/// Shared across lock screens (one is created on every lock).
@MainActor private enum TouchIDPrompt {
    static var launched = false
    static var inFlight = false
    static var armed = true
}

// MARK: Create

struct CreateVaultView: View {
    @Bindable var model: AppModel
    let close: () -> Void
    @State private var folder = ""
    @State private var folderNotEmpty = false
    @State private var pass = ""
    @State private var again = ""

    private var longEnough: Bool {
        pass.precomposedStringWithCanonicalMapping.unicodeScalars.count >= AppModel.minPassphraseCharacters
    }
    private var matching: Bool { !pass.isEmpty && pass == again }
    private var ready: Bool { !folder.isEmpty && !folderNotEmpty && longEnough && matching }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(mood: model.creating ? .working : (ready ? .smitten : .happy), title: "Create a vault",
                        subtitle: "Two things: where it lives, and the passphrase that opens it.")
            FieldLabel(title: "Folder") { FolderPicker(path: folder, action: choose) }
            if folderNotEmpty {
                Banner(kind: .warn, text: "That folder already has files in it. Choose an empty folder, or make a new one in the dialog.")
            }
            FieldLabel(title: "Passphrase") {
                VStack(spacing: 8) {
                    SecureField("Passphrase", text: $pass)
                        .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
                    SecureField("Repeat passphrase", text: $again)
                        .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
                        .onSubmit { if ready { create() } }
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                CheckRow(text: "At least \(AppModel.minPassphraseCharacters) characters (a few random words work well)", met: longEnough)
                CheckRow(text: "Both entries match", met: matching)
            }
            Note(text: "Nobody can reset this passphrase, including us. Next you get a recovery key: the only way back in if you forget it.")
            if let m = model.createMessage { Banner(kind: .error, text: m) }
            HStack(spacing: 10) {
                Spacer()
                Button("Cancel") { model.createMessage = nil; close() }.buttonStyle(.chunky).keyboardShortcut(.cancelAction)
                Button(model.creating ? "Creating…" : "Create vault") { create() }
                    .buttonStyle(.chunkyPrimary).keyboardShortcut(.defaultAction).disabled(model.creating || !ready)
            }
        }
        .padding(24).frame(width: 540)
        .background(Theme.paper)
        .animation(.snappy(duration: 0.18), value: folderNotEmpty)
        .onAppear { model.createMessage = nil }
        .onChange(of: model.recoveryKey) { _, new in if new != nil { pass = ""; again = ""; close() } }
    }

    private func choose() {
        let p = NSOpenPanel()
        p.canChooseDirectories = true; p.canChooseFiles = false; p.allowsMultipleSelection = false
        p.canCreateDirectories = true
        p.prompt = "Use this folder"
        p.message = "Pick an empty folder, or make a new one. In Google Drive or Dropbox the encrypted files sync there."
        if p.runModal() == .OK, let u = p.url {
            folder = u.path
            let items = (try? FileManager.default.contentsOfDirectory(atPath: u.path)) ?? []
            folderNotEmpty = items.contains { $0 != ".DS_Store" }
        }
    }

    private func create() {
        let (a, b, f) = (pass, again, folder)
        Task { await model.createVault(at: f, passphrase: a, repeated: b) }
    }
}

// MARK: Recovery key

/// Shown once after creation. It cannot be dismissed until three randomly chosen groups have been typed back.
struct RecoveryKeyView: View {
    let model: AppModel
    @State private var picks: [Int] = []
    @State private var typed: [String] = ["", "", ""]

    private static func norm(_ s: String) -> String { s.uppercased().filter { !$0.isWhitespace && $0 != "-" } }

    var body: some View {
        let key = model.recoveryKey ?? ""
        let groups = key.split(separator: "-").map(String.init)
        let ok = picks.indices.map { i in
            picks[i] < groups.count && !typed[i].isEmpty && Self.norm(typed[i]) == Self.norm(groups[picks[i]])
        }
        let allOK = !ok.isEmpty && ok.allSatisfy { $0 }
        VStack(alignment: .leading, spacing: 16) {
            SheetHeader(mood: allOK ? .happy : .wow, title: "Your recovery key", subtitle: "The vault is ready. One last, important step.")
            Text("Write this down on paper or save it in a password manager. It is shown only once and this app does not keep it. Without it, a forgotten passphrase means the files are gone for good.")
                .label(.body, weight: .medium).foregroundStyle(Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
            ticket(groups)
            FieldLabel(title: "Check you've got it: type these groups") {
                HStack(spacing: 10) {
                    ForEach(picks.indices, id: \.self) { i in
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Group \(picks[i] + 1)").label(.caption, weight: .semibold).foregroundStyle(Theme.inkSoft)
                            TextField("", text: $typed[i], prompt: Text(verbatim: "····"))
                                .textFieldStyle(StickerFieldStyle(icon: ok[i] ? "checkmark.circle.fill" : nil))
                                .font(.system(.body, design: .monospaced)).autocorrectionDisabled()
                                .accessibilityLabel("Group \(picks[i] + 1)")
                        }
                    }
                }
            }
            HStack {
                if allOK {
                    Label("That's the one.", systemImage: "checkmark.circle.fill").label(.callout).foregroundStyle(Theme.mintText)
                }
                Spacer()
                Button("I've stored it safely") { model.acknowledgeRecoveryKey() }
                    .buttonStyle(.chunkyPrimary).keyboardShortcut(.defaultAction).disabled(!allOK)
            }
        }
        .padding(24).frame(width: 580)
        .background(Theme.paper)
        .animation(.snappy(duration: 0.2), value: allOK)
        .onAppear {
            guard picks.isEmpty, groups.count >= 3 else { return }
            picks = Array(Array(0..<groups.count).shuffled().prefix(3)).sorted()
        }
    }

    /// Numbered groups, four per line, so the paper copy can be checked group by group.
    private func ticket(_ groups: [String]) -> some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "key.horizontal.fill")
                Text("RECOVERY KEY · SHOWN ONCE").tracking(1.2)
                Spacer()
            }
            .label(.caption, weight: .bold).foregroundStyle(Theme.ink.opacity(0.75))
            .padding(.horizontal, 16).padding(.vertical, 10)
            Line().stroke(Theme.ink.opacity(0.6), style: StrokeStyle(lineWidth: 2, dash: [6, 6])).frame(height: 2)
            Grid(horizontalSpacing: 18, verticalSpacing: 10) {
                ForEach(Array(stride(from: 0, to: groups.count, by: 4)), id: \.self) { start in
                    GridRow {
                        ForEach(start..<min(start + 4, groups.count), id: \.self) { i in
                            VStack(spacing: 1) {
                                Text(verbatim: groups[i]).font(.system(size: 21, weight: .bold, design: .monospaced))
                                    .foregroundStyle(Theme.ink)
                                Text(verbatim: "\(i + 1)").font(.system(size: 9, weight: .bold, design: .rounded))
                                    .foregroundStyle(Theme.inkSoft)
                            }
                        }
                    }
                }
            }
            .textSelection(.enabled)
            .padding(.horizontal, 16).padding(.vertical, 16).frame(maxWidth: .infinity)
        }
        .fixedSize(horizontal: false, vertical: true)
        .background(Theme.sun.opacity(0.3), in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .sticker(radius: 16, shadow: 4)
        .padding(.trailing, 4).padding(.bottom, 4)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Recovery key")
        .accessibilityValue(groups.joined(separator: ", "))
    }
}

private struct Line: Shape {
    func path(in r: CGRect) -> Path {
        var p = Path()
        p.move(to: CGPoint(x: r.minX, y: r.midY)); p.addLine(to: CGPoint(x: r.maxX, y: r.midY))
        return p
    }
}
