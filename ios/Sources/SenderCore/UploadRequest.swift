import Foundation

public enum UploadRequest {
    /// `PUT {server}/inbox/{id}` with the token in an Authorization header. No file name anywhere: the id is
    /// random and the name is inside the sealed body.
    public static func make(server: ServerURL, id: String, token: String, length: Int64, allowsCellular: Bool = true) -> URLRequest? {
        guard Outbox.validID(id), length > 0, !token.isEmpty, token.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }),
              let url = URL(string: server.canonical + "/inbox/" + id) else { return nil }
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 120)
        r.httpMethod = "PUT"
        r.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        r.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        r.setValue(String(length), forHTTPHeaderField: "Content-Length")
        r.httpShouldHandleCookies = false
        r.allowsCellularAccess = allowsCellular
        return r
    }

    /// `GET {server}/v1/ping`, for "Test connection".
    public static func ping(server: ServerURL, token: String) -> URLRequest? {
        guard !token.isEmpty, token.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }), let url = URL(string: server.canonical + "/v1/ping") else { return nil }
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 20)
        r.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        r.httpShouldHandleCookies = false
        return r
    }

    /// Maps the ping answer to words for the person holding the phone.
    public static func pingMessage(status: Int?) -> (ok: Bool, text: String) {
        switch status {
        case 204: return (true, "Connected. The server accepts this phone's token.")
        case 401, 403: return (false, "The server rejected the token. Scan the QR code again.")
        case nil: return (false, "Could not reach the server.")
        default: return (false, "The server answered \(status!), which is not what send n*des expects.")
        }
    }
}
