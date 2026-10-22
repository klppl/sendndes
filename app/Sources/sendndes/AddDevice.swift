import AppCore
import AppKit
import SwiftUI

/// Settings tab: pair a phone. Makes an upload-only token and shows its QR code in a window that the screen
/// cannot capture (`sharingType = .none`), for one minute.
struct DevicesTab: View {
    @Bindable var model: AppModel
    @State private var label = "iphone"
    @State private var server = ""
    @State private var working = false

    var body: some View {
        Form {
            Section {
                TextField("Device name", text: $label, prompt: Text("iphone"))
                TextField("Server address", text: $server, prompt: Text("https://inbox.example.com"))
                    .autocorrectionDisabled()
                HStack {
                    Button { create() } label: { Text(working ? "Making the code…" : "Show QR code") }
                        .disabled(working || model.lockState != .unlocked || label.isEmpty || server.isEmpty)
                    if model.lockState != .unlocked { Text("Unlock the vault first.").font(.callout).foregroundStyle(.secondary) }
                }
                if let m = model.pairingMessage { Text(verbatim: m).font(.callout) }
            } header: {
                Text("Add a phone")
            } footer: {
                Text("The phone scans the code, then asks your server to connect and shows a code; you approve it here when the codes match. It gets its own upload-only access and can't read or delete anything. The QR code holds the server address and the vault's two public sealing keys, so show it only to the phone you are pairing. It disappears after a minute, when you close its window, when you lock the vault, or when this app loses focus. The app offers no way to save or copy it and asks macOS to keep the window out of screen sharing and screenshots, but macOS does not always honour that.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section {
                if model.deviceList.isEmpty {
                    Text("No devices yet.").foregroundStyle(.secondary)
                }
                ForEach(model.deviceList) { d in
                    LabeledContent {
                        Button("Remove", role: .destructive) { Task { await model.revokeDevice(d.label) } }
                    } label: {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(verbatim: d.label)
                            Text(d.role == "both" ? "A Mac with full access" : d.role == "upload" ? "Can only send files" : "Can read the inbox").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if let m = model.devicesMessage { Text(verbatim: m).font(.callout) }
            } header: {
                Text("Connected devices")
            } footer: {
                Text("Remove a device when you lose it: it stops working at once.").font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .task { while !Task.isCancelled { if model.lockState == .unlocked || model.tokenIsSet { await model.refreshDevices() }; try? await Task.sleep(nanoseconds: 5_000_000_000) } }
        .onAppear { if server.isEmpty, model.serverURLText.hasPrefix("https://") { server = model.serverURLText } }
        .onChange(of: model.pairing) { _, new in
            if new != nil { PairingWindow.shared.show(model: model) } else { PairingWindow.shared.close() }
        }
    }

    private func create() {
        working = true
        Task {
            _ = await model.createPairing(label: label, serverURL: server)
            working = false
        }
    }
}

/// One floating window for the QR code. It asks macOS to leave it out of screen sharing and screenshots (newer
/// macOS versions do not always honour that, so the UI does not promise it), never remembers its state, and
/// goes away with the pairing.
@MainActor
final class PairingWindow: NSObject, NSWindowDelegate {
    static let shared = PairingWindow()
    private var window: NSWindow?
    private var resignObserver: NSObjectProtocol?
    private weak var model: AppModel?

    /// The red close button ends the pairing too: the payload does not wait for the timer.
    func windowWillClose(_ notification: Notification) {
        model?.clearPairing()
    }

    func show(model: AppModel) {
        close()
        self.model = model
        // Losing focus ends the pairing: the code is only for as long as the owner is looking at it.
        resignObserver = NotificationCenter.default.addObserver(forName: NSApplication.didResignActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { model.clearPairing() }
        }
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 440, height: 760), styleMask: [.titled, .closable],
                         backing: .buffered, defer: false)
        w.title = "Add a phone"
        w.sharingType = .none
        w.isReleasedWhenClosed = false
        w.isRestorable = false
        w.delegate = self
        w.level = .floating
        w.contentView = NSHostingView(rootView: PairingView(model: model))
        w.center()
        window = w
        w.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func close() {
        window?.delegate = nil
        if let o = resignObserver { NotificationCenter.default.removeObserver(o); resignObserver = nil }
        window?.orderOut(nil)
        window?.contentView = nil
        window = nil
    }
}

private struct PairingView: View {
    @Bindable var model: AppModel

    var body: some View {
        Group {
            if let p = model.pairing { content(p) } else { Text("This code has been cleared.").label(.body).padding(40) }
        }
        .frame(width: 440)
        .background(Theme.paper)
        .tint(Theme.pink)
        .onChange(of: model.pairing) { _, new in if new == nil { PairingWindow.shared.close() } }
        .task { while !Task.isCancelled { await model.refreshDevices(); try? await Task.sleep(nanoseconds: 2_000_000_000) } }
    }

    @ViewBuilder private func content(_ p: DevicePairing) -> some View {
        VStack(spacing: 14) {
            Text("Scan with send n*des on your iPhone").display(18).foregroundStyle(Theme.ink)
            if let img = QRCode.image(for: p.payload, scale: 6) {
                Image(decorative: img, scale: 1)
                    .interpolation(.none)
                    .resizable().frame(width: 288, height: 288)
                    .padding(8).background(.white, in: RoundedRectangle(cornerRadius: 10))
                    .sticker(radius: 12, shadow: 3)
                    .accessibilityLabel("QR code for pairing the phone")
            }
            HStack(spacing: 6) {
                Text("Check value").label(.callout, weight: .bold).foregroundStyle(Theme.ink)
                Text(verbatim: p.fingerprint).font(.system(.title3, design: .monospaced).bold()).foregroundStyle(Theme.ink)
            }
            Text("The phone shows the same value before it saves anything.").label(.caption, weight: .medium).foregroundStyle(Theme.inkSoft)
            TimelineView(.periodic(from: .now, by: 1)) { ctx in
                let left = max(0, Int(p.expires.timeIntervalSince(ctx.date).rounded(.up)))
                Text("Hides in \(left) s").label(.callout, weight: .semibold).foregroundStyle(Theme.inkSoft)
            }
            Divider()
            VStack(alignment: .leading, spacing: 8) {
                Text("Then approve the phone here").label(.callout, weight: .bold).foregroundStyle(Theme.ink)
                Text("After you scan, the phone shows a code. When the same code appears below, press Approve.")
                    .label(.caption, weight: .medium).foregroundStyle(Theme.inkSoft)
                if let reqs = model.phonePairing?.requests, !reqs.isEmpty {
                    ForEach(reqs) { r in
                        HStack(spacing: 10) {
                            Text(verbatim: r.spacedCode).font(.system(size: 26, weight: .heavy, design: .rounded)).monospacedDigit().foregroundStyle(Theme.ink)
                            Text(verbatim: r.label).label(.callout, weight: .semibold).foregroundStyle(Theme.inkSoft).lineLimit(1)
                            Spacer()
                            Button("Approve") { Task { await model.decidePair(r.id, approve: true); model.clearPairing() } }.buttonStyle(.chunkySmall)
                            Button("Deny") { Task { await model.decidePair(r.id, approve: false) } }.buttonStyle(.chunkyQuietSmall)
                        }
                        .padding(8).sticker(radius: 12)
                    }
                } else if !model.tokenIsSet || model.tokenNeedsReentry {
                    Text("Connect this Mac to your server first (Settings > Server), or approve on the server's web page.").label(.caption, weight: .medium).foregroundStyle(Theme.tomatoText)
                } else {
                    Text("Waiting for the phone…").label(.caption, weight: .medium).foregroundStyle(Theme.inkSoft)
                }
                if let m = model.devicesMessage { Text(verbatim: m).label(.caption, weight: .medium).foregroundStyle(Theme.tomatoText) }
            }
            Button("Done") { model.clearPairing() }.buttonStyle(.chunkyPrimary)
        }
        .padding(22)
    }
}
