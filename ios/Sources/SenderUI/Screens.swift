import SenderCore
import SwiftUI

/// The app's one root view.
public struct SenderRootView: View {
    @Bindable var model: SenderModel
    @Environment(\.scenePhase) private var phase

    public init(model: SenderModel) { self.model = model }

    public var body: some View {
        ZStack {
            Theme.paper.ignoresSafeArea()
            switch model.screen {
            case .welcome: WelcomeView(model: model)
            case .scanning: ScannerScreen(model: model)
            case .confirm(let p): ConfirmView(model: model, payload: p)
            case .waiting(let code, let host): WaitingView(model: model, code: code, host: host)
            case .home: HomeView(model: model)
            }
        }
        .tint(Theme.pink)
        .onChange(of: phase) { _, p in if p == .active { model.didBecomeActive() } }
        .onAppear { model.didBecomeActive() }
    }
}

struct WelcomeView: View {
    @Bindable var model: SenderModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Aster(mood: .happy, size: 132, interactive: true).padding(.top, 36)
                Wordmark(size: 28)
                Text("Send things from your phone to your own vault.").label(.title3, weight: .semibold)
                    .foregroundStyle(Theme.ink).multilineTextAlignment(.center)
                Text("Share a photo, a PDF, a note or a link to send n*des. It is locked on this phone before it leaves, so your server and anyone watching the network only see scrambled bytes.")
                    .label(.body, weight: .medium).foregroundStyle(Theme.inkSoft).multilineTextAlignment(.center)
                if let e = model.pairingError { Banner(kind: .error, text: e) }
                Button { model.beginScanning() } label: { Label("Scan the QR code from your Mac", systemImage: "qrcode.viewfinder") }
                    .buttonStyle(.chunkyPrimary)
                Note(text: "On your Mac: send n*des > Settings > Devices > Show QR code. This phone gets its own upload-only key: it can send files but can't read or delete anything.")
                    .padding(.top, 8)
            }
            .padding(24)
        }
    }
}

struct ConfirmView: View {
    @Bindable var model: SenderModel
    let payload: SenderPayload

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Aster(mood: .wow, size: 100).padding(.top, 28)
                Text("Pair with this server?").display(26).foregroundStyle(Theme.ink)
                if let old = model.pairedInfo {
                    Banner(kind: .warn, text: "This replaces the current pairing with \(old.url.replacingOccurrences(of: "https://", with: "")). Files still waiting for that server will not be sent to the new one.")
                }
                VStack(alignment: .leading, spacing: 12) {
                    row("Server", payload.server.canonical.replacingOccurrences(of: "https://", with: ""))
                    row("Device name", payload.label)
                    row("Check value", payload.fingerprint, mono: true)
                }
                .padding(16).frame(maxWidth: .infinity, alignment: .leading).sticker(radius: 16, shadow: 3)
                Note(text: "The check value must be the same as the one on your Mac's screen. If it is not, or you did not just scan your own code, cancel.")
                HStack(spacing: 12) {
                    Button("Cancel") { model.cancelPairing() }.buttonStyle(.chunky)
                    Button("Pair") { model.confirm(payload) }.buttonStyle(.chunkyPrimary)
                }
                .padding(.top, 4)
            }
            .padding(24)
        }
    }

    private func row(_ k: String, _ v: String, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(k).label(.caption, weight: .bold).foregroundStyle(Theme.inkSoft)
            Text(verbatim: v).font(mono ? .system(.title2, design: .monospaced).bold() : .system(.title3, design: .rounded, weight: .bold))
                .foregroundStyle(Theme.ink).textSelection(.disabled)
        }
    }
}

struct WaitingView: View {
    @Bindable var model: SenderModel
    let code: String
    let host: String

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Aster(mood: .working, size: 100).padding(.top, 28)
                Text(code.isEmpty ? "Asking the server…" : "Approve this code on your Mac").display(24).foregroundStyle(Theme.ink).multilineTextAlignment(.center)
                if !code.isEmpty {
                    Text(verbatim: code).font(.system(size: 48, weight: .heavy, design: .rounded)).monospacedDigit().foregroundStyle(Theme.ink)
                        .padding(.horizontal, 22).padding(.vertical, 10).sticker(radius: 18, shadow: 4)
                        .accessibilityLabel("Code " + code.filter(\.isNumber).map(String.init).joined(separator: " "))
                    Text("On your Mac the QR window shows the same code. Press Approve there. Or approve it on the server's web page (Devices).")
                        .label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft).multilineTextAlignment(.center)
                    Text(verbatim: "Server: " + host).label(.caption, weight: .medium).foregroundStyle(Theme.inkSoft)
                    Note(text: "If the codes differ, or you did not just scan your own code, cancel.")
                }
                Button("Cancel") { model.cancelServerPairing() }.buttonStyle(.chunky)
            }
            .padding(24)
        }
    }
}

struct HomeView: View {
    @Bindable var model: SenderModel
    @State private var showSettings = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if let e = model.pairingError { Banner(kind: .error, text: e) }
                connectionCard
                queueCard
                howToCard
                if !model.history.isEmpty { historyCard }
            }
            .padding(20)
        }
        .refreshable { model.didBecomeActive() }
        .sheet(isPresented: $showSettings) { SettingsView(model: model) }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Aster(mood: model.items.contains { $0.state == .uploading } ? .working : .smitten, size: 56, interactive: true)
            VStack(alignment: .leading, spacing: 2) {
                Text("send n*des").display(26).foregroundStyle(Theme.ink)
                Text(verbatim: model.pairedInfo.map { "Paired with \($0.url.replacingOccurrences(of: "https://", with: ""))" } ?? "Not paired").label(.callout, weight: .medium)
                    .foregroundStyle(Theme.inkSoft).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            Button { showSettings = true } label: { Image(systemName: "gearshape.fill").font(.title3) }
                .buttonStyle(.chunkySmall).accessibilityLabel("Settings")
        }
    }

    private var connectionCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("Connection").label(.headline, weight: .bold).foregroundStyle(Theme.ink)
                Spacer()
                if let p = model.pairedInfo { Pill(text: "check " + p.fp, icon: "checkmark.seal.fill", tint: Theme.mint) }
            }
            if model.keychainLocked { Banner(kind: .info, text: "Unlock your phone to use the keys. Files already waiting keep sending.") }
            if let r = model.pingResult { Banner(kind: r.ok ? .success : .error, text: r.text) }
            Button { model.testConnection() } label: {
                HStack(spacing: 6) {
                    if model.pinging { ProgressView() } else { Image(systemName: "bolt.horizontal.fill") }
                    Text(model.pinging ? "Testing…" : "Test connection")
                }
            }
            .buttonStyle(.chunky).disabled(model.pinging)
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading).sticker(radius: 16, shadow: 3)
    }

    private var queueCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Waiting to send").label(.headline, weight: .bold).foregroundStyle(Theme.ink)
            if model.items.isEmpty {
                Text("Nothing waiting. Files you share are sent in the background.").label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
            } else {
                ForEach(model.items) { item in ItemRow(item: item, model: model) }
            }
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading).sticker(radius: 16, shadow: 3)
    }

    private var howToCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("How to send").label(.headline, weight: .bold).foregroundStyle(Theme.ink)
            Text("Open a photo, a PDF, a note or a web page, tap the share button, and choose send n*des.").label(.callout, weight: .medium).foregroundStyle(Theme.ink)
            Note(text: SenderLimits.tooLargeMessage + " Up to \(SenderLimits.maxItemsPerShare) items per share.")
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading).sticker(radius: 16, shadow: 3)
    }

    private var historyCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("History").label(.headline, weight: .bold).foregroundStyle(Theme.ink)
                Spacer()
                Button("Clear history") { model.clearHistory() }.buttonStyle(.chunkyQuietSmall)
            }
            ForEach(model.history.prefix(50)) { h in
                HStack {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(verbatim: h.name).label(.callout, weight: .semibold).foregroundStyle(Theme.ink).lineLimit(1).truncationMode(.middle)
                        Text(verbatim: h.date.formatted(date: .abbreviated, time: .shortened) + " · " + ByteCountFormatter.string(fromByteCount: h.size, countStyle: .file))
                            .font(.caption).foregroundStyle(Theme.inkSoft)
                    }
                    Spacer()
                    Pill(text: h.statusText, icon: h.status == .stored ? "checkmark" : "xmark", tint: h.status == .stored ? Theme.mint : Theme.amber)
                }
            }
            Note(text: "\"Stored on server\" means the server has the locked file. It does not mean anyone has opened it yet.")
        }
        .padding(16).frame(maxWidth: .infinity, alignment: .leading).sticker(radius: 16, shadow: 3)
    }
}

struct ItemRow: View {
    let item: SealedItem
    let model: SenderModel

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: icon).foregroundStyle(tint).frame(width: 22)
                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: item.displayName).label(.callout, weight: .semibold).foregroundStyle(Theme.ink).lineLimit(1).truncationMode(.middle)
                    Text(verbatim: ByteCountFormatter.string(fromByteCount: item.size, countStyle: .file)).font(.caption).foregroundStyle(Theme.inkSoft)
                }
                Spacer()
                Pill(text: label, tint: tint, spinner: item.state == .uploading)
            }
            if item.state == .failed, let f = item.failure {
                Text(verbatim: f.message).font(.caption).foregroundStyle(Theme.tomatoText)
                HStack(spacing: 8) {
                    Button("Retry") { model.retry(item.id) }.buttonStyle(.chunkySmall)
                    Button("Discard") { model.discard(item.id) }.buttonStyle(.chunkyQuietSmall)
                }
            }
        }
    }

    private var label: String {
        switch item.state {
        case .sealed: return "Waiting"
        case .uploading: return "Sending"
        case .stored: return "Stored on server"
        case .failed: return "Failed"
        }
    }
    private var tint: Color { item.state == .failed ? Theme.tomato : item.state == .stored ? Theme.mint : Theme.grape }
    private var icon: String { item.state == .failed ? "exclamationmark.triangle.fill" : "lock.fill" }
}

struct SettingsView: View {
    @Bindable var model: SenderModel
    @Environment(\.dismiss) private var dismiss
    @State private var folder = ""
    @State private var confirmRemove = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Folder in your vault", text: $folder)
                        .plainTyping()
                    if !model.folderIsValid(folder) { Text("Not a valid folder name. Use names separated by /, with no . or .. parts.").font(.caption).foregroundStyle(Theme.tomatoText) }
                } header: { Text("Where files go") } footer: {
                    Text("Files arrive in this folder of your vault (default \"\(SenderLimits.defaultFolder)\").")
                }
                Section {
                    Toggle("Send over Wi-Fi only", isOn: $model.settings.wifiOnly)
                } footer: { Text("Off: files may also use mobile data.") }
                Section {
                    if let p = model.pairedInfo {
                        LabeledContent("Server", value: p.url.replacingOccurrences(of: "https://", with: ""))
                        LabeledContent("Device name", value: p.label)
                        LabeledContent("Check value", value: p.fp)
                    }
                    Button("Pair again…") { dismiss(); model.beginScanning() }
                    Button("Remove configuration", role: .destructive) { confirmRemove = true }
                } header: { Text("This phone") } footer: {
                    Text("Removing deletes the keys, the saved address, waiting files and the history from this phone. To stop this phone from sending at all, also delete its line on the server and reload it.")
                }
                Section {
                    Text("send n*des is made by AI for one person and has had no human security audit. This phone can't read or delete anything on your server. Nothing here talks to anyone but your own server: no analytics, no third-party code.")
                        .font(.footnote)
                }
            }
            .scrollContentBackground(.hidden).background(Theme.paper)
            .navigationTitle("Settings").navigationBarTitleDisplayModeInline()
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { commit(); dismiss() } } }
            .onAppear { folder = model.settings.folder }
            .onChange(of: folder) { _, f in if model.folderIsValid(f) { model.settings.folder = f; model.saveSettings() } }
            .onChange(of: model.settings.wifiOnly) { _, _ in model.saveSettings() }
            .confirmationDialog("Remove this phone's configuration?", isPresented: $confirmRemove, titleVisibility: .visible) {
                Button("Remove configuration", role: .destructive) { model.removeConfiguration(); dismiss() }
            } message: { Text("Keys, saved address, waiting files and history are deleted from this phone.") }
        }
    }

    private func commit() { if model.folderIsValid(folder) { model.settings.folder = folder }; model.saveSettings() }
}

extension View {
    /// `.navigationBarTitleDisplayMode(.inline)` exists on iOS only; the package also builds on macOS for its tests.
    @ViewBuilder func navigationBarTitleDisplayModeInline() -> some View {
        #if os(iOS)
        navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }
    /// No automatic capitals or corrections for a folder name (iOS only).
    @ViewBuilder func plainTyping() -> some View {
        #if os(iOS)
        textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        autocorrectionDisabled()
        #endif
    }
}
