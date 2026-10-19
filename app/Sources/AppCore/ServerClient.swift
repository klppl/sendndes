import Foundation
import UniformTypeIdentifiers

public enum UploadFailure: Error, Equatable {
    case tokenRejected, tooLarge, rateLimited, inboxFull, badName, serverError
    case unreachable, timedOut, fileChanged(deleted: Bool), cantRead, unexpectedResponse

    /// Failures after which the next file would fail the same way: the queue pauses.
    public var pausesQueue: Bool {
        switch self {
        case .tokenRejected, .rateLimited, .inboxFull, .unreachable, .timedOut: return true
        default: return false
        }
    }

    public var message: String {
        switch self {
        case .tokenRejected: return "The server rejected the token."
        case .tooLarge: return "Larger than the server allows (--max-upload-bytes)."
        case .rateLimited: return "The server is refusing requests for a while (too many failed logins or uploads)."
        case .inboxFull: return "Server inbox full; pull first."
        case .badName: return "The server rejected the file's name or folder."
        case .serverError: return "Server error."
        case .unreachable: return "Can't reach the server. Is Tailscale on?"
        case .timedOut: return "The server stopped responding."
        case .fileChanged(let deleted):
            return deleted ? "The file changed while sending; the partial copy on the server was removed."
                           : "The file changed while sending; the server may keep a partial copy."
        case .cantRead: return "Can't read this file."
        case .unexpectedResponse: return "The server's answer was not understood."
        }
    }
}

/// One upload = one fresh ephemeral session: no connection reuse, no redirects,
/// no cookies/cache/credentials, response body capped at 4 KiB.
public struct ServerClient {
    public init() {}

    public func upload(file: URL, name: String, dir: String, server: ServerURL, token: String) async -> Result<String, UploadFailure> {
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return .failure(.cantRead) }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG else { return .failure(.cantRead) }

        var req = URLRequest(url: URL(string: server.canonical + "/inbox")!)
        req.httpMethod = "PUT"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue(Data(name.utf8).base64EncodedString(), forHTTPHeaderField: "X-Valv-Name-B64")
        if !dir.isEmpty { req.setValue(Data(dir.utf8).base64EncodedString(), forHTTPHeaderField: "X-Valv-Dir-B64") }
        let ns = Int64(before.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(before.st_mtimespec.tv_nsec)
        req.setValue(String(ns), forHTTPHeaderField: "X-Valv-Mtime")
        if let mime = UTType(filenameExtension: file.pathExtension)?.preferredMIMEType,
           mime.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) {
            req.setValue(mime, forHTTPHeaderField: "X-Valv-Mime")
        }

        let outcome = await Transfer.run(request: req, body: file)
        var after = stat()
        let changed = fstat(fd, &after) != 0 || after.st_size != before.st_size || after.st_ino != before.st_ino
            || after.st_dev != before.st_dev
            || after.st_mtimespec.tv_sec != before.st_mtimespec.tv_sec || after.st_mtimespec.tv_nsec != before.st_mtimespec.tv_nsec

        switch outcome {
        case .failure(let f):
            return .failure(f)
        case .success(let (status, body)):
            switch status {
            case 201:
                guard let id = Self.parseID(body) else { return .failure(.unexpectedResponse) }
                if changed {
                    let deleted = await deleteOwn(id: id, server: server, token: token)
                    return .failure(.fileChanged(deleted: deleted))
                }
                return .success(id)
            case 401, 403: return .failure(.tokenRejected)
            case 413: return .failure(.tooLarge)
            case 429: return .failure(.rateLimited)
            case 507: return .failure(.inboxFull)
            case 400: return .failure(.badName)
            case 408, 500...599: return .failure(.serverError)
            default: return .failure(.unexpectedResponse)
            }
        }
    }

    static func parseID(_ body: Data) -> String? {
        struct R: Decodable { let id: String }
        guard let r = try? JSONDecoder().decode(R.self, from: body), isValidID(r.id) else { return nil }
        return r.id
    }

    func deleteOwn(id: String, server: ServerURL, token: String) async -> Bool {
        var req = URLRequest(url: URL(string: server.canonical + "/inbox/" + id)!)
        req.httpMethod = "DELETE"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        if case .success(let (status, _)) = await Transfer.run(request: req, body: nil) { return status == 204 || status == 404 }
        return false
    }
}

/// A single request on its own session, with the redirect/challenge/size rules.
private final class Transfer: NSObject, URLSessionDataDelegate {
    static let bodyCap = 4096
    private var cont: CheckedContinuation<Result<(Int, Data), UploadFailure>, Never>?
    private var data = Data()
    private var status = 0
    private var overflow = false
    private var cancelledByUs = false
    private var session: URLSession?

    static func run(request: URLRequest, body: URL?) async -> Result<(Int, Data), UploadFailure> {
        let t = Transfer()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (c: CheckedContinuation<Result<(Int, Data), UploadFailure>, Never>) in
                t.cont = c
                let cfg = URLSessionConfiguration.ephemeral
                cfg.httpMaximumConnectionsPerHost = 1
                cfg.waitsForConnectivity = false
                cfg.httpCookieStorage = nil
                cfg.httpShouldSetCookies = false
                cfg.urlCache = nil
                cfg.urlCredentialStorage = nil
                cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
                cfg.timeoutIntervalForRequest = 60
                cfg.timeoutIntervalForResource = 24 * 3600
                cfg.connectionProxyDictionary = [:] // no system proxy: the token goes straight to the server
                let s = URLSession(configuration: cfg, delegate: t, delegateQueue: nil)
                t.session = s
                let task = body.map { s.uploadTask(with: request, fromFile: $0) } ?? s.dataTask(with: request)
                task.resume()
            }
        } onCancel: {
            t.session?.invalidateAndCancel()
        }
    }

    private func finish(_ r: Result<(Int, Data), UploadFailure>) {
        guard let c = cont else { return }
        cont = nil
        session?.finishTasksAndInvalidate()
        c.resume(returning: r)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil) // never follow: the token must not leave the configured host
    }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            completionHandler(.performDefaultHandling, nil)
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        urlSession(session, didReceive: challenge, completionHandler: completionHandler)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        status = (response as? HTTPURLResponse)?.statusCode ?? 0
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive d: Data) {
        data.append(d)
        if data.count > Transfer.bodyCap {
            overflow = true
            dataTask.cancel()
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if overflow { finish(.failure(.unexpectedResponse)); return }
        if let e = error as? URLError {
            // The server answered (redirect responses end up here without an error, handled below).
            finish(.failure(e.code == .timedOut ? .timedOut : .unreachable))
            return
        }
        if error != nil { finish(.failure(.unreachable)); return }
        if (100..<200).contains(status) || (300..<400).contains(status) || status == 0 {
            finish(.failure(.unexpectedResponse))
            return
        }
        finish(.success((status, data)))
    }
}
