import Foundation

/// A background URLSession that uploads sealed files from disk. Https only (the server address cannot be
/// anything else), the Authorization header set when the task is created, redirects never followed, and
/// the server's answer capped at 4 KiB. The system keeps uploading after the app or the share extension exits.
public final class BackgroundUploader: NSObject, UploadTransport, URLSessionDataDelegate, URLSessionTaskDelegate, @unchecked Sendable {
    public static let responseLimit = 4096

    private var session: URLSession!
    private let lock = NSLock()
    private var bodies: [Int: Data] = [:]
    private var onResult: (@Sendable (String, TransportResult) -> Void)?
    private var onFinishedEvents: (@Sendable () -> Void)?

    /// `identifier` names the session (the app uses one, the share extension another); `groupIdentifier` is the
    /// App Group so the system can read the sealed files from the shared container.
    public init(identifier: String, groupIdentifier: String?, onFinishedEvents: (@Sendable () -> Void)? = nil,
                onResult: @escaping @Sendable (String, TransportResult) -> Void) {
        super.init()
        self.onResult = onResult
        self.onFinishedEvents = onFinishedEvents
        let c = URLSessionConfiguration.background(withIdentifier: identifier)
        c.sharedContainerIdentifier = groupIdentifier
        c.isDiscretionary = false
        c.waitsForConnectivity = true
        c.httpCookieStorage = nil
        c.httpShouldSetCookies = false
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.tlsMinimumSupportedProtocolVersion = .TLSv12
        session = URLSession(configuration: c, delegate: self, delegateQueue: nil)
    }

    /// Called when the system has delivered every event for this session after a background launch.
    public func setFinishedEventsHandler(_ f: @escaping @Sendable () -> Void) {
        lock.lock(); onFinishedEvents = f; lock.unlock()
    }

    public func start(_ t: UploadTask) {
        let task = session.uploadTask(with: t.request, fromFile: t.fileURL)
        task.taskDescription = t.id
        task.resume()
    }

    public func activeTaskIDs() async -> Set<String> {
        let tasks = await session.allTasks
        return Set(tasks.compactMap { $0.state == .running || $0.state == .suspended ? $0.taskDescription : nil })
    }

    public func cancel(id: String) async {
        for t in await session.allTasks where t.taskDescription == id { t.cancel() }
    }

    /// Stops every upload of this session and releases the session (Remove configuration, end of events).
    public func cancelAllAndInvalidate() {
        session.invalidateAndCancel()
    }

    /// Releases the session once the system has delivered everything (so another process may own the identifier).
    public func finish() { session.finishTasksAndInvalidate() }

    // MARK: URLSessionTaskDelegate

    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)   // never follow: the 3xx is the answer
    }

    public func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock(); defer { lock.unlock() }
        var b = bodies[dataTask.taskIdentifier] ?? Data()
        if b.count < Self.responseLimit { b.append(data.prefix(Self.responseLimit - b.count)) }
        bodies[dataTask.taskIdentifier] = b
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let id = task.taskDescription else { return }
        lock.lock()
        let body = bodies.removeValue(forKey: task.taskIdentifier) ?? Data()
        let cb = onResult
        lock.unlock()
        if let e = error as? URLError, e.code == .cancelled { cb?(id, .cancelled); return }
        if error != nil { cb?(id, .networkError); return }
        // Background sessions follow redirects without asking: a request that ended somewhere else did not reach ndesd.
        if task.currentRequest?.url != task.originalRequest?.url { cb?(id, .redirected); return }
        guard let status = (task.response as? HTTPURLResponse)?.statusCode else { cb?(id, .networkError); return }
        cb?(id, .response(status: status, body: body))
    }

    public func urlSessionDidFinishEvents(forBackgroundURLSession session: URLSession) {
        lock.lock(); let f = onFinishedEvents; onFinishedEvents = nil; lock.unlock()
        f?()
    }
}
