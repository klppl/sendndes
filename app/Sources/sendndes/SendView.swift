import AppCore
import AppKit
import SwiftUI

struct SendView: View {
    let model: AppModel
    @Bindable var queue: SendQueue
    @State private var targeted = false

    private var sentCount: Int { queue.items.filter { $0.state == .sent }.count }

    private var subtitle: String {
        if queue.items.isEmpty { return "Straight to your inbox server. No passphrase needed." }
        return "\(queue.items.count) in the queue · \(sentCount) sent."
    }

    var body: some View {
        if !model.serverConfigured {
            ScrollView {
                VStack(spacing: 16) {
                    Aster(mood: .oops, size: 100, interactive: true)
                    VStack(spacing: 4) {
                        Text("Where should files go?").display(26).foregroundStyle(Theme.ink)
                        Text("Connect your inbox server (ndesd). Files sent there wait until your vault pulls them in.")
                            .label(.body, weight: .medium).foregroundStyle(Theme.inkSoft)
                            .multilineTextAlignment(.center).frame(maxWidth: 420)
                    }
                    ServerForm(model: model, compact: false)
                        .padding(18).sticker(radius: 16, shadow: 4)
                        .padding(.trailing, 4).padding(.bottom, 4)
                        .frame(maxWidth: 460)
                }
                .padding(28)
                .frame(maxWidth: .infinity)
            }
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
                    Button { FilePanels.send(queue) } label: { Label("Send files…", systemImage: "plus") }.buttonStyle(.chunkyPrimary)
                }
                .lineLimit(1)
                .fixedSize()
            }
            if let r = queue.pausedReason { Banner(kind: .warn, text: r, actionTitle: "Resume") { queue.resume() } }
            ForEach(queue.notes, id: \.self) { Banner(kind: .info, text: $0) }
            if queue.items.isEmpty {
                dropZone
            } else {
                TransferList(items: queue.items, activeText: "sending…", doneText: "sent!") { queue.retry($0) }
            }
            HStack(spacing: 6) {
                if model.hasServerKeys {
                    Image(systemName: "lock.shield").foregroundStyle(Theme.mintText)
                    Text("Sealed on this Mac: the server only receives encrypted files and never sees contents or names.")
                        .font(.caption).foregroundStyle(Theme.inkSoft)
                    HelpTip(title: "How client-sealed sending works",
                            text: "Files are sealed on your Mac using the vault's inbox public key and upload authentication key. The server stores only the sealed .inb file and never sees contents, names or directories.")
                } else {
                    Image(systemName: "eye").foregroundStyle(Theme.amberText)
                    Text("Sealed by the server: files are sent unencrypted, and the server sees each file and its name while it seals it.")
                        .font(.caption).foregroundStyle(Theme.inkSoft)
                    HelpTip(title: "How sending works",
                            text: "Files go one at a time, straight from where they are (no copies). Don't send files that are still being written. The server seals each one for your vault and keeps it until your vault pulls it in, which happens when you unlock or press Check inbox. To seal on this Mac instead, choose that option in Settings → Server and paste the server keys.")
                }
            }
        }
        .padding(20)
        .overlay { if targeted && !queue.items.isEmpty { DropHint(title: "Drop to send").padding(10) } }
        .animation(.snappy(duration: 0.18), value: targeted)
    }

    private var dropZone: some View {
        VStack(spacing: 10) {
            Aster(mood: targeted ? .wow : .happy, size: 116, interactive: true)
            Text(targeted ? "Ooh. Let go!" : "Drop files here").display(28).foregroundStyle(Theme.ink)
            Text("Folders too. We don't judge.").label(.body, weight: .medium).foregroundStyle(Theme.inkSoft)
            Button("Choose files…") { FilePanels.send(queue) }.buttonStyle(.chunky).padding(.top, 4)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(RoundedRectangle(cornerRadius: 20, style: .continuous).fill(targeted ? Theme.pink.opacity(0.16) : Theme.card.opacity(0.55)))
        .overlay(
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(targeted ? Theme.pink : Theme.ink.opacity(0.5),
                              style: StrokeStyle(lineWidth: targeted ? 4 : 2.5, dash: targeted ? [] : [10, 8]))
        )
    }
}

/// Server address + access token, validated and saved together. Used on the Send screen and in Settings.
struct ServerForm: View {
    let model: AppModel
    var compact = true
    @State private var url = ""
    @State private var token = ""
    @State private var keysText = ""
    @State private var sealMode: SealMode = .onMac
    @State private var error: String?
    @State private var saved = false

    private var tokenSaved: Bool { model.tokenIsSet && !model.tokenNeedsReentry }
    private var changed: Bool {
        url.trimmingCharacters(in: .whitespaces) != model.serverURLText || !token.isEmpty || !keysText.isEmpty
            || (sealMode == .byServer && model.hasServerKeys)
    }
    private enum SealMode { case onMac, byServer }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            FieldLabel(title: "Server address") {
                TextField("Server address", text: $url, prompt: Text(verbatim: "https://inbox.example.ts.net or http://100.x.y.z:8485"))
                    .textFieldStyle(StickerFieldStyle(icon: "network")).labelsHidden()
                    .autocorrectionDisabled()
            }
            FieldLabel(title: "Access token") {
                SecureField("Access token", text: $token,
                            prompt: Text(tokenSaved ? "Saved in your Keychain · type to replace" : "Paste the token from the server's admin page"))
                    .textFieldStyle(StickerFieldStyle(icon: "key.fill")).labelsHidden()
                    .onSubmit(save)
            }
            FieldLabel(title: "How files are protected") {
                VStack(spacing: 8) {
                    SealChoice(selected: sealMode == .onMac, icon: "lock.shield", tint: Theme.mintText,
                               title: "Seal on this Mac (recommended)",
                               detail: "Files are encrypted here before they leave. The server only ever receives sealed files and can't see contents or names.") {
                        sealMode = .onMac; error = nil
                    }
                    SealChoice(selected: sealMode == .byServer, icon: "eye", tint: Theme.amberText,
                               title: "Let the server seal them",
                               detail: "Files are sent unencrypted and the server encrypts them on arrival. It sees each file and its name for a moment, so use Tailscale or https.") {
                        sealMode = .byServer; error = nil
                    }
                }
            }
            if sealMode == .onMac {
                FieldLabel(title: "Server keys") {
                    SecureField("Server keys", text: $keysText,
                                prompt: Text(model.hasServerKeys ? "Saved in your Keychain · paste to replace" : "Paste the two key lines from Settings → Server → Copy Server Keys"))
                        .textFieldStyle(StickerFieldStyle(icon: "lock.shield")).labelsHidden()
                        .onSubmit(save)
                }
            }
            if model.tokenNeedsReentry {
                Banner(kind: .warn, text: "The saved token belongs to a different server address, so it isn't sent to this one. Paste it again.")
            }
            if let error { Banner(kind: .error, text: error) }
            HStack(spacing: 8) {
                if saved && !changed {
                    Label("Saved", systemImage: "checkmark.circle.fill").label(.callout).foregroundStyle(Theme.mintText)
                }
                HelpTip(title: "Plain http and Tailscale",
                        text: "Plain http:// works only for this Mac or a Tailscale address (100.64–100.127), and only while the route really goes through Tailscale. Anything else needs https://. The token stays in your login keychain, is never synced to iCloud, and is bound to this address.")
                Spacer()
                Button(compact ? "Save" : "Connect", action: save)
                    .buttonStyle(.chunkyPrimary).disabled(!changed || url.isEmpty)
                    .keyboardShortcut(compact ? nil : .defaultAction)
            }
        }
        .onAppear {
            url = model.serverURLText
            sealMode = (model.hasServerKeys || model.serverURLText.isEmpty) ? .onMac : .byServer
        }
        .animation(.snappy(duration: 0.18), value: error)
    }

    private func save() {
        guard changed, !url.isEmpty else { return }
        var parsedKeys: ServerKeys? = nil
        if !keysText.isEmpty {
            guard let k = ServerKeys(text: keysText) else {
                error = "Invalid server keys. Paste the two lines from ndes server-config."
                return
            }
            parsedKeys = k
        }
        if sealMode == .onMac, parsedKeys == nil, !model.hasServerKeys {
            error = "Paste the server keys to seal files on this Mac, or choose “Let the server seal them”."
            return
        }
        do {
            try model.saveSettings(serverURL: url, token: token.isEmpty ? nil : token,
                                   serverKeys: sealMode == .onMac ? parsedKeys : nil,
                                   clearServerKeys: sealMode == .byServer, vaultPath: model.vaultPath)
            token = ""; keysText = ""; error = nil; saved = true
            url = model.serverURLText
        } catch let e as AppModel.SettingsError { error = e.message } catch { self.error = "Could not save." }
    }
}

/// One selectable row of the "How files are protected" choice.
private struct SealChoice: View {
    let selected: Bool
    let icon: String
    let tint: Color
    let title: String
    let detail: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? tint : Theme.inkSoft)
                VStack(alignment: .leading, spacing: 2) {
                    Label(title, systemImage: icon).label(.callout).foregroundStyle(Theme.ink)
                    Text(detail).font(.caption).foregroundStyle(Theme.inkSoft)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(10)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Theme.card.opacity(selected ? 1 : 0.55)))
            .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(selected ? tint : Theme.ink.opacity(0.25), lineWidth: selected ? 2 : 1))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}
