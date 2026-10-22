import Foundation
import UniformTypeIdentifiers
import NdesCore

public enum UploadFailure: Error, Equatable {
    case tokenRejected, tooLarge, rateLimited, inboxFull, badName, serverError
    case unreachable, timedOut, fileChanged(deleted: Bool), cantRead, unexpectedResponse, notTailscaleRoute, dateOutOfRange, serverOutOfSpace, uploadRejected

    /// Failures after which the next file would fail the same way: the queue pauses.
    public var pausesQueue: Bool {
        switch self {
        case .tokenRejected, .rateLimited, .inboxFull, .serverOutOfSpace, .unreachable, .timedOut, .notTailscaleRoute: return true
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
        case .notTailscaleRoute: return RouteGuard.routeMessage
        case .serverOutOfSpace: return "The server is out of space."
        case .uploadRejected: return "The server could not store this file."
        case .dateOutOfRange: return "This file's modification date is out of range (before 1677 or after 2262)."
        }
    }
}

/// One upload = one fresh ephemeral session: no connection reuse, no redirects,
/// no cookies/cache/credentials, response body capped at 4 KiB.
public struct ServerClient {
    private let route: RouteGuard
    public init(route: RouteGuard = RouteGuard()) { self.route = route }
    /// Test seam: runs after the file was opened and checked, before the body is sent.
    var beforeBody: (() -> Void)?

    private static func changedSince(_ before: stat, fd: Int32) -> Bool {
        var after = stat()
        return fstat(fd, &after) != 0 || after.st_size != before.st_size || after.st_ino != before.st_ino
            || after.st_dev != before.st_dev
            || after.st_mtimespec.tv_sec != before.st_mtimespec.tv_sec || after.st_mtimespec.tv_nsec != before.st_mtimespec.tv_nsec
    }

    public func upload(file: URL, name: String, dir: String, server: ServerURL, token: String, keys: ServerKeys? = nil) async -> Result<String, UploadFailure> {
        // H1: checked again for every file (the route can change after sleep); never falls back.
        guard route.allows(server) else { return .failure(.notTailscaleRoute) }
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return .failure(.cantRead) }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, (before.st_mode & S_IFMT) == S_IFREG else { return .failure(.cantRead) }
        guard let ns = Self.mtimeNanos(sec: Int64(before.st_mtimespec.tv_sec), nsec: Int64(before.st_mtimespec.tv_nsec)) else {
            return .failure(.dateOutOfRange)
        }
        let mime = UTType(filenameExtension: file.pathExtension)?.preferredMIMEType

        if let keys {
            let pdir: PrivateDir
            do {
                pdir = try PrivateDir.create()
            } catch {
                return .failure(.cantRead)
            }
            defer { pdir.remove() }

            let meta: Metadata
            do {
                meta = try Metadata(name: name, dir: dir, mtime: ns, mime: mime ?? "", rev: 1, size: Int64(before.st_size))
            } catch {
                return .failure(.badName)
            }

            let sealer: InboxSealer
            do {
                sealer = try keys.makeSealer()
            } catch {
                return .failure(.uploadRejected)
            }

            let sealedPath = pdir.path + "/sealed.inb"
            let outFD = open(sealedPath, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
            guard outFD >= 0 else { return .failure(.cantRead) }
            defer { close(outFD) }

            let fileID: FileID
            do {
                let inHandle = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
                let outHandle = FileHandle(fileDescriptor: outFD, closeOnDealloc: false)
                fileID = try sealer.seal(plaintext: FileInput(inHandle), metadata: meta, to: FileOutput(outHandle))
            } catch {
                // The size goes into the metadata first, so a file that grew or shrank while
                // it was read fails the sealer; report that as a change, not a server problem.
                return .failure(Self.changedSince(before, fd: fd) ? .fileChanged(deleted: false) : .uploadRejected)
            }

            if Self.changedSince(before, fd: fd) {
                return .failure(.fileChanged(deleted: false))
            }

            var sealedStat = stat()
            guard fstat(outFD, &sealedStat) == 0 else { return .failure(.cantRead) }
            let sealedSize = Int64(sealedStat.st_size)

            var req = URLRequest(url: URL(string: server.canonical + "/inbox/" + fileID.hex)!)
            req.httpMethod = "PUT"
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            req.setValue(String(sealedSize), forHTTPHeaderField: "Content-Length")
            req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")

            beforeBody?()
            let outcome = await Transfer.run(request: req, body: FDBody(fd: outFD, length: sealedSize))

            switch outcome {
            case .failure(let f):
                return .failure(f)
            case .success(let (status, body)):
                switch status {
                case 200, 201:
                    guard let id = Self.parseID(body), id == fileID.hex else { return .failure(.unexpectedResponse) }
                    return .success(id)
                case 401, 403: return .failure(.tokenRejected)
                case 409: return .failure(.uploadRejected)
                case 413: return .failure(.tooLarge)
                case 429: return .failure(.rateLimited)
                case 507:
                    return .failure(String(decoding: body, as: UTF8.self).contains("out of space") ? .serverOutOfSpace : .inboxFull)
                case 400:
                    let text = String(decoding: body, as: UTF8.self)
                    return .failure(text.contains("upload failed") || text.contains("incomplete upload") || text.contains("malformed") ? .uploadRejected : .badName)
                case 408, 500...599: return .failure(.serverError)
                default: return .failure(.unexpectedResponse)
                }
            }
        }

        var req = URLRequest(url: URL(string: server.canonical + "/inbox")!)
        req.httpMethod = "PUT"
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.setValue(Data(name.utf8).base64EncodedString(), forHTTPHeaderField: "X-Ndes-Name-B64")
        if !dir.isEmpty { req.setValue(Data(dir.utf8).base64EncodedString(), forHTTPHeaderField: "X-Ndes-Dir-B64") }
        req.setValue(String(ns), forHTTPHeaderField: "X-Ndes-Mtime")
        if let mime, mime.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) {
            req.setValue(mime, forHTTPHeaderField: "X-Ndes-Mime")
        }

        // L5: the body is streamed from this open descriptor (pread on a dup), never re-opened by path, so a
        // path swapped after the check above cannot change what is sent. Exactly st_size bytes are sent.
        req.setValue(String(before.st_size), forHTTPHeaderField: "Content-Length")
        beforeBody?()
        let outcome = await Transfer.run(request: req, body: FDBody(fd: fd, length: Int64(before.st_size)))
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
            case 507:
                // ndesd: "server out of space" is the disk; the other 507 bodies are inbox limits (files or bytes).
                return .failure(String(decoding: body, as: UTF8.self).contains("out of space") ? .serverOutOfSpace : .inboxFull)
            case 400:
                // Only "upload failed" and "incomplete upload stream" are not about the name or metadata.
                let text = String(decoding: body, as: UTF8.self)
                return .failure(text.contains("upload failed") || text.contains("incomplete upload") ? .uploadRejected : .badName)
            case 408, 500...599: return .failure(.serverError)
            default: return .failure(.unexpectedResponse)
            }
        }
    }

    /// L6: seconds+nanoseconds as Unix nanoseconds, nil when the date does not fit in an Int64
    /// (before 1677 or after 2262, possible on file systems other than APFS). Never traps.
    static func mtimeNanos(sec: Int64, nsec: Int64) -> Int64? {
        guard (0..<1_000_000_000).contains(nsec) else { return nil }
        let (whole, o1) = sec.multipliedReportingOverflow(by: 1_000_000_000)
        guard !o1 else { return nil }
        let (total, o2) = whole.addingReportingOverflow(nsec)
        return o2 ? nil : total
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
    private var body: FDBody?

    static func run(request: URLRequest, body: FDBody?) async -> Result<(Int, Data), UploadFailure> {
        let t = Transfer()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (c: CheckedContinuation<Result<(Int, Data), UploadFailure>, Never>) in
                t.cont = c
                if Task.isCancelled { c.resume(returning: .failure(.unreachable)); t.cont = nil; return }
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
                t.body = body
                let task = body != nil ? s.uploadTask(withStreamedRequest: request) : s.dataTask(with: request)
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

    func urlSession(_ session: URLSession, task: URLSessionTask, needNewBodyStream completionHandler: @escaping (InputStream?) -> Void) {
        completionHandler(body?.makeStream())
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

/// The request body: `length` bytes of an already opened file, read with pread from a private dup of the
/// descriptor on a helper thread and handed to URLSession through a bound stream pair. A fresh stream
/// (needed if URLSession must resend) starts again at offset 0 of the same open file.
final class FDBody: @unchecked Sendable {
    let fd: Int32
    let length: Int64
    init(fd: Int32, length: Int64) { self.fd = fd; self.length = length }

    func makeStream() -> InputStream? {
        var input: InputStream?
        var output: OutputStream?
        Stream.getBoundStreams(withBufferSize: 64 * 1024, inputStream: &input, outputStream: &output)
        guard let input, let output else { return nil }
        let mine = dup(fd)
        guard mine >= 0 else { return nil }
        let length = self.length
        let thread = Thread {
            defer { close(mine) }
            output.open()
            defer { output.close() }
            var buf = [UInt8](repeating: 0, count: 64 * 1024)
            var off: Int64 = 0
            while off < length {
                let want = Int(min(Int64(buf.count), length - off))
                let n = buf.withUnsafeMutableBytes { pread(mine, $0.baseAddress, want, off_t(off)) }
                if n <= 0 { return } // the file got shorter: the body ends early and the request fails
                var sent = 0
                while sent < n {
                    let w = buf.withUnsafeBufferPointer { output.write($0.baseAddress! + sent, maxLength: n - sent) }
                    if w <= 0 { return } // URLSession closed its end (cancelled or finished)
                    sent += w
                }
                off += Int64(n)
            }
        }
        thread.stackSize = 256 * 1024
        thread.start()
        return input
    }
}
