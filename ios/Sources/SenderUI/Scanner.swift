import SenderCore
import SwiftUI
#if canImport(UIKit) && canImport(AVFoundation)
import AVFoundation
import UIKit

/// Scan-only pairing: the camera is the only way in (no paste, no photo library), except in debug builds (see `DebugPasteField`).
struct ScannerScreen: View {
    @Bindable var model: SenderModel
    @State private var denied = false
    @Environment(\.openURL) private var openURL   // not UIApplication.shared: this code is also linked into the extension

    var body: some View {
        VStack(spacing: 12) {
            HStack {
                Text("Scan the code").display(24).foregroundStyle(Theme.ink)
                Spacer()
                Button("Cancel") { model.cancelPairing() }.buttonStyle(.chunkySmall)
            }
            .padding(.horizontal, 20).padding(.top, 16)
            if denied {
                EmptyState(mood: .oops, title: "No camera access", text: "send n*des needs the camera only to read the pairing code. Allow it in Settings > send n*des.",
                           button: "Open Settings", action: { if let u = URL(string: UIApplication.openSettingsURLString) { openURL(u) } })
            } else {
                QRScannerView(onCode: { model.scanned($0) }, onDenied: { denied = true })
                    .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 20, style: .continuous).strokeBorder(Theme.ink, lineWidth: 3))
                    .padding(20)
                Note(text: "Point the camera at the QR code on your Mac.").padding(.horizontal, 20).padding(.bottom, 20)
            }
            #if DEBUG
            DebugPasteField(model: model)
            #endif
        }
    }
}

#if DEBUG
/// Debug builds only (the Simulator has no camera): paste the `payload:` line of `ndes sender-config --pair`.
/// It goes through the same `scanned` path as a camera read, so the owner still compares the check value.
private struct DebugPasteField: View {
    @Bindable var model: SenderModel
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Debug: paste the pairing code").font(.footnote).foregroundStyle(Theme.ink)
            TextField("ndes-sender2:…", text: $text)
                .textInputAutocapitalization(.never).autocorrectionDisabled()
                .submitLabel(.go).onSubmit { if !text.isEmpty { model.scanned(text.trimmingCharacters(in: .whitespacesAndNewlines)) } }
                .font(.footnote.monospaced())
                .padding(10)
                .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2))
            Button("Use pasted code") { model.scanned(text.trimmingCharacters(in: .whitespacesAndNewlines)) }
                .buttonStyle(.chunkySmall).disabled(text.isEmpty)
        }
        .padding(.horizontal, 20).padding(.bottom, 20)
    }
}
#endif

struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    let onDenied: () -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let c = ScannerController()
        c.onCode = onCode
        c.onDenied = onDenied
        return c
    }
    func updateUIViewController(_ vc: ScannerController, context: Context) {}
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    var onDenied: (() -> Void)?
    private let session = AVCaptureSession()
    private var preview: AVCaptureVideoPreviewLayer?
    private var done = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: configure()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { ok in DispatchQueue.main.async { ok ? self.configure() : self.onDenied?() } }
        default: onDenied?()
        }
    }

    private func configure() {
        guard let dev = AVCaptureDevice.default(for: .video), let input = try? AVCaptureDeviceInput(device: dev),
              session.canAddInput(input) else { onDenied?(); return }
        session.addInput(input)
        let out = AVCaptureMetadataOutput()
        guard session.canAddOutput(out) else { onDenied?(); return }
        session.addOutput(out)
        out.setMetadataObjectsDelegate(self, queue: .main)
        out.metadataObjectTypes = [.qr]
        let p = AVCaptureVideoPreviewLayer(session: session)
        p.videoGravity = .resizeAspectFill
        view.layer.addSublayer(p)
        preview = p
        DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
    }

    override func viewDidLayoutSubviews() { super.viewDidLayoutSubviews(); preview?.frame = view.bounds }
    override func viewWillDisappear(_ animated: Bool) { super.viewWillDisappear(animated); if session.isRunning { session.stopRunning() } }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard !done, let o = objects.first as? AVMetadataMachineReadableCodeObject, o.type == .qr, let s = o.stringValue else { return }
        done = true
        session.stopRunning()
        onCode?(s)
    }
}
#else
struct ScannerScreen: View {
    @Bindable var model: SenderModel
    var body: some View { Text("Scanning needs an iPhone camera.") }
}
#endif
