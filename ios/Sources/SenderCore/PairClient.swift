import CryptoKit
import Foundation
import Security

/// What can go wrong while the phone asks the server to connect (and the words the person sees).
public enum PairFailure: Error, Equatable, Sendable {
    case closed, busy, rejected, unreachable, unexpected, denied, expired, notOffered

    public var message: String {
        switch self {
        case .closed: return "The server isn't accepting new devices right now. On your Mac, open Settings > Devices and show the QR code again, then scan it."
        case .busy: return "Too many connection requests are waiting on the server. Try again in a few minutes."
        case .rejected: return "The server did not accept the request."
        case .unreachable: return "Can't reach the server. Check your connection and the address."
        case .unexpected: return "The server's answer was not what send n*des expects."
        case .denied: return "The request was denied."
        case .expired: return "The request ran out of time (5 minutes). Scan the QR code again."
        case .notOffered: return "This server does not offer device pairing. Update the server."
        }
    }
}

public struct PairRequest: Equatable, Sendable {
    public let id: String
    public let code: String
    let secret: String
    /// "123 456"
    public var spacedCode: String { code.count == 6 ? String(code.prefix(3)) + " " + String(code.suffix(3)) : code }
}

public enum PairPoll: Equatable, Sendable {
    case pending
    case approved(token: String)
}

/// The two calls a new device makes before it has a token. https only (the server address was checked when the
/// QR code was read), no redirects, a small answer.
public enum PairClient {
    private static func call(_ server: ServerURL, _ method: String, _ path: String, secret: String? = nil, json: [String: String]? = nil) async -> Result<(Int, Data), PairFailure> {
        guard let url = URL(string: server.canonical + path) else { return .failure(.unexpected) }
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        r.httpMethod = method
        r.httpShouldHandleCookies = false
        if let secret { r.setValue(secret, forHTTPHeaderField: "X-Pair-Secret") }
        if let json, let d = try? JSONSerialization.data(withJSONObject: json) {
            r.httpBody = d
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let cfg = URLSessionConfiguration.ephemeral
        cfg.httpCookieStorage = nil
        cfg.urlCache = nil
        let session = URLSession(configuration: cfg, delegate: NoRedirects(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        do {
            let (data, resp) = try await session.data(for: r)
            guard let h = resp as? HTTPURLResponse, data.count <= 4096 else { return .failure(.unexpected) }
            return .success((h.statusCode, data))
        } catch {
            return .failure(.unreachable)
        }
    }

    /// Asks to be connected as an upload-only device.
    public static func request(server: ServerURL, label: String) async -> Result<PairRequest, PairFailure> {
        var b = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, b.count, &b)
        let secret = Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        let hash = SHA256.hash(data: Data(secret.utf8)).map { String(format: "%02x", $0) }.joined()
        switch await call(server, "POST", "/v1/pair/request", json: ["label": label, "role": "upload", "secret_hash": hash]) {
        case .failure(let f): return .failure(f)
        case .success(let (status, data)):
            switch status {
            case 201:
                guard let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let id = o["id"] as? String, id.count == 32,
                      let code = o["code"] as? String, code.count == 6, code.allSatisfy(\.isNumber) else { return .failure(.unexpected) }
                return .success(PairRequest(id: id, code: code, secret: secret))
            case 403: return .failure(.closed)
            case 429: return .failure(.busy)
            case 400: return .failure(.rejected)
            case 401, 404, 405: return .failure(.notOffered)
            default: return .failure(.unexpected)
            }
        }
    }

    public static func status(server: ServerURL, request: PairRequest) async -> Result<PairPoll, PairFailure> {
        switch await call(server, "GET", "/v1/pair/status/" + request.id, secret: request.secret) {
        case .failure(let f): return .failure(f)
        case .success(let (status, data)):
            guard status == 200, let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let state = o["state"] as? String else {
                return .failure(status == 404 ? .expired : status == 429 ? .busy : .unexpected)
            }
            switch state {
            case "pending": return .success(.pending)
            case "denied": return .failure(.denied)
            case "expired", "done": return .failure(.expired)
            case "approved":
                guard let t = o["token"] as? String, (32...512).contains(t.utf8.count), t.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
                      o["role"] as? String == "upload" else { return .failure(.unexpected) }
                return .success(.approved(token: t))
            default: return .failure(.unexpected)
            }
        }
    }
}

final class NoRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
}
