import CoreImage
import Foundation

/// What `ndes sender-config --json` produced for one phone: the secret payload for the QR code, the fingerprint
/// to compare on the phone, and the line the server's tokens file needs. Held in memory only, for a minute.
public struct DevicePairing: Equatable, Sendable {
    /// `ndes-sender1:` + base64url(JSON). Holds the upload token and k_auth: never shown as text, saved or copied.
    public let payload: String
    public let fingerprint: String
    /// Only for the older flow that makes the token here (`upload <label> <sha256-hex>`); empty when the phone asks the server to pair.
    public let tokenLine: String
    public let label: String
    public let server: String
    public let expires: Date
}

/// Reads the records of `ndes sender-config --json`: `payload`, `token-line`, then `end`, or one `error`.
final class PairingAccumulator: @unchecked Sendable {
    private let lock = NSLock()
    private var payload: String?
    private var fp: String?
    private var line: String?
    private var ended = false
    private(set) var errorCode: String?
    private var bad = false

    func feed(_ d: Data) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard let o = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any], let type = o["type"] as? String else {
            bad = true; return false
        }
        switch type {
        case "payload":
            guard let p = o["payload"] as? String, p.hasPrefix("ndes-sender1:") || p.hasPrefix("ndes-sender2:"), p.utf8.count < 4096,
                  let f = o["fp"] as? String, f.count == 8, f.allSatisfy({ $0.isHexDigit && !$0.isUppercase }), payload == nil else { bad = true; return false }
            payload = p; fp = f
        case "token-line":
            guard let l = o["line"] as? String, l.hasPrefix("upload "), line == nil else { bad = true; return false }
            line = l
        case "end": ended = true
        case "error": errorCode = o["code"] as? String ?? "other"
        default: bad = true; return false
        }
        return true
    }

    func result(label: String, server: String, expires: Date) -> DevicePairing? {
        lock.lock(); defer { lock.unlock() }
        guard !bad, ended, errorCode == nil, let p = payload, let f = fp else { return nil }
        // A v1 payload (token made here) needs its token line; a v2 payload (pairing by approval) has none.
        if p.hasPrefix("ndes-sender1:"), line == nil { return nil }
        if p.hasPrefix("ndes-sender2:"), line != nil { return nil }
        return DevicePairing(payload: p, fingerprint: f, tokenLine: line ?? "", label: label, server: server, expires: expires)
    }
}

/// QR codes with CoreImage (error correction M, no dependency).
public enum QRCode {
    /// A black-on-white image of the payload, `scale` pixels per module, with a quiet zone of 4 modules.
    public static func image(for text: String, scale: Int = 8) -> CGImage? {
        guard let f = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        f.setValue(Data(text.utf8), forKey: "inputMessage")
        f.setValue("M", forKey: "inputCorrectionLevel")
        guard let out = f.outputImage else { return nil }
        let quiet = 4
        let side = Int(out.extent.width) + 2 * quiet
        let ctx = CIContext(options: [.useSoftwareRenderer: true])
        let scaled = out
            .transformed(by: CGAffineTransform(translationX: CGFloat(quiet) - out.extent.minX, y: CGFloat(quiet) - out.extent.minY))
            .composited(over: CIImage(color: .white).cropped(to: CGRect(x: 0, y: 0, width: side, height: side)))
            .transformed(by: CGAffineTransform(scaleX: CGFloat(scale), y: CGFloat(scale)))
        // Nearest-neighbour: modules stay sharp.
        let sharp = scaled.samplingNearest()
        return ctx.createCGImage(sharp, from: CGRect(x: 0, y: 0, width: side * scale, height: side * scale))
    }

    /// Reads a QR code back (for tests).
    public static func decode(_ image: CGImage) -> String? {
        let det = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        let feats = det?.features(in: CIImage(cgImage: image)) ?? []
        return (feats.first as? CIQRCodeFeature)?.messageString
    }
}
