import AppCore
import SwiftUI

/// Connect this Mac to the server by approval: type the address, press Connect, compare the code with the one on the
/// server's page and approve it there. No token is typed or copied.
struct ConnectBox: View {
    @Bindable var model: AppModel
    @State private var address = ""

    private var connected: Bool { model.tokenIsSet && !model.tokenNeedsReentry && !model.serverURLText.isEmpty }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if connected, model.connectState == .idle || model.connectState == .connected {
                Banner(kind: .success, text: "Connected to \(model.serverURLText.replacingOccurrences(of: "https://", with: "")).")
            }
            FieldLabel(title: "Server address") {
                TextField("Server address", text: $address, prompt: Text(verbatim: "https://inbox.example.com"))
                    .textFieldStyle(StickerFieldStyle(icon: "network")).labelsHidden().autocorrectionDisabled()
                    .onSubmit(start)
            }
            switch model.connectState {
            case .idle, .connected:
                Button { start() } label: { Label(connected ? "Connect again" : "Connect", systemImage: "link") }
                    .buttonStyle(.chunkyPrimary).disabled(address.trimmingCharacters(in: .whitespaces).isEmpty)
            case .asking:
                HStack { ProgressView().controlSize(.small); Text("Asking the server…").label(.callout) }
            case .waiting(let code):
                VStack(alignment: .leading, spacing: 8) {
                    Text("Approve this code on your server").label(.headline, weight: .bold).foregroundStyle(Theme.ink)
                    Text(verbatim: code).font(.system(size: 40, weight: .heavy, design: .rounded)).monospacedDigit().foregroundStyle(Theme.ink)
                        .padding(.horizontal, 16).padding(.vertical, 6).sticker(radius: 14, shadow: 3)
                        .accessibilityLabel("Code " + code.filter(\.isNumber).map(String.init).joined(separator: " "))
                    Text("Open the server's web page, press Add a device if it is closed, and press Approve next to this same code. Waiting up to 5 minutes…")
                        .label(.callout, weight: .medium).foregroundStyle(Theme.inkSoft)
                    Button("Cancel") { model.cancelConnect() }.buttonStyle(.chunkyQuietSmall)
                }
            case .failed(let msg):
                Banner(kind: .error, text: msg)
                Button { start() } label: { Label("Try again", systemImage: "arrow.clockwise") }.buttonStyle(.chunky)
            }
        }
        .onAppear { if address.isEmpty { address = model.serverURLText } }
        .onChange(of: model.connectState) { _, s in if s == .connected { address = model.serverURLText } }
    }

    private func start() { model.connect(to: address) }
}
