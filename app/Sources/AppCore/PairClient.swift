import CryptoKit
import Foundation
import Security

/// Talks to the server's device pairing endpoints (`ndesd`, see SPEC 8): a device asks, the owner approves on the
/// server's page or in this app, the device collects its token once.
public enum PairFailure: Error, Equatable {
    case closed        // the pairing window is not open
    case busy          // too many requests are waiting
    case rejected      // the server refused the request as invalid
    case unreachable
    case unexpected
    case denied, expired
    case notOffered    // an older server without pairing
    case tokenRejected

    public var message: String {
        switch self {
        case .closed: return "The server isn't accepting new devices right now. Open the server's web page and press Add a device, then try again."
        case .busy: return "Too many connection requests are waiting on the server. Try again in a few minutes."
        case .rejected: return "The server did not accept the request."
        case .unreachable: return "Can't reach the server. Check the address and that it is running."
        case .unexpected: return "The server's answer was not understood."
        case .denied: return "The request was denied on the server."
        case .expired: return "The request ran out of time (5 minutes). Press Connect to try again."
        case .notOffered: return "This server does not offer device pairing. Update it to the latest send n*des server."
        case .tokenRejected: return "The server rejected this device's token. Connect again."
        }
    }
}

public struct PairRequestInfo: Equatable, Sendable {
    public let id: String
    /// Six digits, shown here and on the server's page: the owner compares them.
    public let code: String
    let secret: String

    /// "123 456"
    public var spacedCode: String { code.count == 6 ? String(code.prefix(3)) + " " + String(code.suffix(3)) : code }
}

public enum PairPoll: Equatable, Sendable {
    case pending
    case approved(token: String, role: String, label: String)
    case done
}

public struct PendingPair: Equatable, Identifiable, Sendable {
    public let id: String
    public let label: String
    public let role: String
    public let code: String
    public var spacedCode: String { code.count == 6 ? String(code.prefix(3)) + " " + String(code.suffix(3)) : code }
    public var isPhone: Bool { role == "upload" }
}

public struct DeviceEntry: Equatable, Identifiable, Sendable {
    public var id: String { label }
    public let label: String
    public let role: String
}

public struct PairingState: Equatable, Sendable {
    public var open: Bool
    public var secondsLeft: Int
    public var requests: [PendingPair]
}

enum PairClient {
    private static func secretAndHash() -> (String, String) {
        var b = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, b.count, &b)
        let secret = Data(b).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return (secret, SHA256.hash(data: Data(secret.utf8)).map { String(format: "%02x", $0) }.joined())
    }

    private static func call(_ server: ServerURL, _ method: String, _ path: String, token: String? = nil, secret: String? = nil, json: [String: Any]? = nil) async -> Result<(Int, Data), PairFailure> {
        guard let url = URL(string: server.canonical + path) else { return .failure(.unexpected) }
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        r.httpMethod = method
        if let token { r.setValue("Bearer " + token, forHTTPHeaderField: "Authorization") }
        if let secret { r.setValue(secret, forHTTPHeaderField: "X-Pair-Secret") }
        if let json, let d = try? JSONSerialization.data(withJSONObject: json) {
            r.httpBody = d
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        switch await Transfer.run(request: r, body: nil) {
        case .failure(let f): return .failure(f == .unexpectedResponse ? .unexpected : .unreachable)
        case .success(let (s, d)): return .success((s, d))
        }
    }

    static func request(server: ServerURL, label: String, role: String) async -> Result<PairRequestInfo, PairFailure> {
        let (secret, hash) = secretAndHash()
        switch await call(server, "POST", "/v1/pair/request", json: ["label": label, "role": role, "secret_hash": hash]) {
        case .failure(let f): return .failure(f)
        case .success(let (status, data)):
            switch status {
            case 201:
                guard let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let id = o["id"] as? String, id.count == 32,
                      let code = o["code"] as? String, code.count == 6, code.allSatisfy(\.isNumber) else { return .failure(.unexpected) }
                return .success(PairRequestInfo(id: id, code: code, secret: secret))
            case 403: return .failure(.closed)
            case 429: return .failure(.busy)
            case 400: return .failure(.rejected)
            case 401, 404, 405: return .failure(.notOffered)
            default: return .failure(.unexpected)
            }
        }
    }

    static func status(server: ServerURL, request: PairRequestInfo) async -> Result<PairPoll, PairFailure> {
        switch await call(server, "GET", "/v1/pair/status/" + request.id, secret: request.secret) {
        case .failure(let f): return .failure(f)
        case .success(let (status, data)):
            guard status == 200, let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let state = o["state"] as? String else {
                return .failure(status == 404 ? .expired : status == 429 ? .busy : .unexpected)
            }
            switch state {
            case "pending": return .success(.pending)
            case "done": return .success(.done)
            case "denied": return .failure(.denied)
            case "expired": return .failure(.expired)
            case "approved":
                guard let t = o["token"] as? String, (32...512).contains(t.utf8.count), let role = o["role"] as? String, let label = o["label"] as? String else { return .failure(.unexpected) }
                return .success(.approved(token: t, role: role, label: label))
            default: return .failure(.unexpected)
            }
        }
    }

    // MARK: Owner calls (a token with full access)

    static func pairingState(server: ServerURL, token: String) async -> Result<PairingState, PairFailure> {
        switch await call(server, "GET", "/v1/pair/pending", token: token) {
        case .failure(let f): return .failure(f)
        case .success(let (status, data)):
            if status == 401 || status == 403 { return .failure(.tokenRejected) }
            guard status == 200, let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return .failure(status == 404 ? .notOffered : .unexpected) }
            let reqs: [PendingPair] = ((o["requests"] as? [[String: Any]]) ?? []).compactMap {
                guard let id = $0["id"] as? String, let l = $0["label"] as? String, let r = $0["role"] as? String, let c = $0["code"] as? String else { return nil }
                return PendingPair(id: id, label: l, role: r, code: c)
            }
            return .success(PairingState(open: o["open"] as? Bool ?? false, secondsLeft: o["seconds_left"] as? Int ?? 0, requests: reqs))
        }
    }

    static func ownerAction(server: ServerURL, token: String, method: String, path: String, json: [String: Any]? = nil) async -> Result<Void, PairFailure> {
        switch await call(server, method, path, token: token, json: json) {
        case .failure(let f): return .failure(f)
        case .success(let (status, _)):
            if status == 200 { return .success(()) }
            return .failure(status == 401 || status == 403 ? .tokenRejected : status == 404 ? .expired : .unexpected)
        }
    }

    static func devices(server: ServerURL, token: String) async -> Result<[DeviceEntry], PairFailure> {
        switch await call(server, "GET", "/v1/devices", token: token) {
        case .failure(let f): return .failure(f)
        case .success(let (status, data)):
            guard status == 200, let o = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any], let list = o["devices"] as? [[String: Any]] else {
                return .failure(status == 401 || status == 403 ? .tokenRejected : .unexpected)
            }
            return .success(list.compactMap { d in (d["label"] as? String).flatMap { l in (d["role"] as? String).map { DeviceEntry(label: l, role: $0) } } })
        }
    }
}
