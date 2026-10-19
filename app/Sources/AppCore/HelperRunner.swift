import CryptoKit
import Foundation

public enum HelperError: Error, Equatable {
    case refused(String)   // the helper failed the path/owner/hash check
    case locked            // no passphrase when the job started
    case cancelled
    case spawnFailed
}

public struct HelperOutcome {
    public var exitStatus: Int32 = -1
    public var killedByUs = false
    public var outputViolation = false   // line too long, too much output, NUL byte, or the caller said stop
    public var stdinFailed = false
    public var stderrTail = Data()       // last 64 KiB; never shown or logged
}

/// Collects the child process while it runs, so lock/quit can stop it.
private final class Running: @unchecked Sendable {
    let lock = NSLock()
    var process: Process?
    var killed = false
    func terminate() {
        lock.lock(); defer { lock.unlock() }
        guard let p = process, p.isRunning else { return }
        killed = true
        let pid = p.processIdentifier
        p.terminate()
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) { if p.isRunning { kill(pid, SIGKILL) } }
    }
}

/// Runs the bundled `valv`, one invocation at a time.
public actor HelperRunner {
    public static let maxLine = 1 << 20
    public static let maxTotal = 256 << 20
    public static let stderrKeep = 64 << 10

    private let helperPath: String
    private let expectedSHA256: String?
    private var busy = false
    private var waiters: [(id: Int, cont: CheckedContinuation<Void, Error>)] = []
    private var nextWaiter = 0
    private let running = Running()

    /// Test hook: called with the child's pid after spawn and before stdin is written.
    public nonisolated(unsafe) var afterSpawn: (@Sendable (pid_t) -> Void)?

    public init(helperPath: String, expectedSHA256: String?) {
        self.helperPath = helperPath
        self.expectedSHA256 = expectedSHA256
        signal(SIGPIPE, SIG_IGN)
    }

    // MARK: queue

    private func acquire() async throws {
        if !busy { busy = true; return }
        let id = nextWaiter; nextWaiter += 1
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            waiters.append((id, c))
        }
    }

    private func release() {
        if waiters.isEmpty { busy = false } else { waiters.removeFirst().cont.resume() } // busy stays true
    }

    /// Synchronous stop of the running helper (quit and signal handlers cannot await).
    public nonisolated func terminateNow() { running.terminate() }

    /// Lock, sleep, quit: drop queued jobs and stop the running one (SIGTERM, then SIGKILL after 5 s).
    public func terminateAll() {
        let w = waiters; waiters = []
        w.forEach { $0.cont.resume(throwing: HelperError.cancelled) }
        running.terminate()
    }

    // MARK: run

    /// `passphrase` is evaluated when the job is dequeued; nil fails the job without running it.
    /// `onLine` gets each stdout line (without the newline) on a background thread and returns false to stop.
    public func run(args: [String],
                    passphrase: @escaping @Sendable () -> String?,
                    onLine: @escaping @Sendable (Data) -> Bool) async throws -> HelperOutcome {
        try await acquire()
        defer { release() }
        guard let pass = passphrase() else { throw HelperError.locked }
        try verifyHelper()
        let path = helperPath
        let hook = afterSpawn
        let running = self.running
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<HelperOutcome, Error>) in
            DispatchQueue.global().async {
                do { c.resume(returning: try HelperRunner.spawnAndCollect(path: path, args: args, passphrase: pass, running: running, afterSpawn: hook, onLine: onLine)) }
                catch { c.resume(throwing: error) }
            }
        }
    }

    // MARK: helper check (APPD-07)

    func verifyHelper() throws {
        guard let expected = expectedSHA256 else { throw HelperError.refused("no build hash") }
        var comps = helperPath.split(separator: "/").map(String.init)
        guard helperPath.hasPrefix("/"), !comps.isEmpty else { throw HelperError.refused("path") }
        comps.removeLast()
        let uid = geteuid()
        var paths = ["/"]
        var acc = ""
        for c in comps { acc += "/" + c; paths.append(acc) }
        for cur in paths {
            var st = stat()
            guard lstat(cur, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR else { throw HelperError.refused("ancestor \(cur)") }
            guard st.st_uid == 0 || st.st_uid == uid else { throw HelperError.refused("ancestor owner") }
            if st.st_mode & 0o022 != 0 {
                let rootSticky = st.st_uid == 0 && (st.st_mode & S_ISVTX) != 0
                if !(rootSticky || cur == "/Applications") { throw HelperError.refused("ancestor writable") }
            }
        }
        let fd = open(helperPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HelperError.refused("open") }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == uid, st.st_mode & 0o022 == 0
        else { throw HelperError.refused("file") }
        var h = SHA256()
        var buf = [UInt8](repeating: 0, count: 1 << 16)
        while true {
            let n = read(fd, &buf, buf.count)
            if n < 0 { if errno == EINTR { continue }; throw HelperError.refused("read") }
            if n == 0 { break }
            h.update(data: buf[0..<n])
        }
        let got = h.finalize().map { String(format: "%02x", $0) }.joined()
        guard got == expected.lowercased() else { throw HelperError.refused("hash") }
    }

    // MARK: spawn (blocking; runs on a global queue)

    private static func spawnAndCollect(path: String, args: [String], passphrase: String, running: Running,
                                        afterSpawn: (@Sendable (pid_t) -> Void)?,
                                        onLine: @escaping @Sendable (Data) -> Bool) throws -> HelperOutcome {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        p.environment = ["PATH": "/usr/bin:/bin"]
        p.currentDirectoryURL = URL(fileURLWithPath: "/")
        let inP = Pipe(), outP = Pipe(), errP = Pipe()
        p.standardInput = inP; p.standardOutput = outP; p.standardError = errP
        running.lock.lock()
        running.killed = false
        do { try p.run() } catch { running.lock.unlock(); throw HelperError.spawnFailed }
        running.process = p
        running.lock.unlock()
        defer { running.lock.lock(); running.process = nil; running.lock.unlock() }

        // Parent's copies of the child's ends are closed so EOF/EPIPE work.
        try? outP.fileHandleForWriting.close()
        try? errP.fileHandleForWriting.close()
        try? inP.fileHandleForReading.close()
        afterSpawn?(p.processIdentifier)

        var outcome = HelperOutcome()
        let group = DispatchGroup()
        let stateLock = NSLock()
        var violation = false, stdinFailed = false
        var errTail = Data()

        // stdin: passphrase + "\n", then close.
        let wfd = inP.fileHandleForWriting.fileDescriptor
        _ = fcntl(wfd, F_SETNOSIGPIPE, 1)
        group.enter()
        DispatchQueue.global().async {
            var bytes = Array((passphrase + "\n").utf8)
            var off = 0
            while off < bytes.count {
                let n = bytes.withUnsafeBytes { write(wfd, $0.baseAddress! + off, bytes.count - off) }
                if n < 0 { if errno == EINTR { continue }; stateLock.lock(); stdinFailed = true; stateLock.unlock(); break }
                off += n
            }
            for i in bytes.indices { bytes[i] = 0 }
            try? inP.fileHandleForWriting.close()
            group.leave()
        }

        group.enter()
        DispatchQueue.global().async {
            let rfd = errP.fileHandleForReading.fileDescriptor
            var buf = [UInt8](repeating: 0, count: 1 << 14)
            while true {
                let n = read(rfd, &buf, buf.count)
                if n < 0 { if errno == EINTR { continue }; break }
                if n == 0 { break }
                errTail.append(contentsOf: buf[0..<n])
                if errTail.count > stderrKeep { errTail = errTail.suffix(stderrKeep) }
            }
            group.leave()
        }

        group.enter()
        DispatchQueue.global().async {
            let rfd = outP.fileHandleForReading.fileDescriptor
            var pending = Data()
            var total = 0
            var buf = [UInt8](repeating: 0, count: 1 << 16)
            var stopped = false
            func stop() {
                if !stopped { stopped = true; stateLock.lock(); violation = true; stateLock.unlock(); running.terminate() }
            }
            while true {
                let n = read(rfd, &buf, buf.count)
                if n < 0 { if errno == EINTR { continue }; break }
                if n == 0 { break }
                if stopped { continue } // drain
                total += n
                if total > maxTotal { stop(); continue }
                pending.append(contentsOf: buf[0..<n])
                while let nl = pending.firstIndex(of: 0x0A) {
                    let line = pending[pending.startIndex..<nl]
                    pending = Data(pending[(nl + 1)...])
                    if line.count > maxLine || line.contains(0) { stop(); break }
                    if !onLine(Data(line)) { stop(); break }
                }
                if !stopped && pending.count > maxLine { stop() }
            }
            group.leave()
        }

        p.waitUntilExit()
        group.wait()
        stateLock.lock()
        outcome.outputViolation = violation
        outcome.stdinFailed = stdinFailed
        stateLock.unlock()
        outcome.stderrTail = errTail
        outcome.exitStatus = p.terminationStatus
        running.lock.lock(); outcome.killedByUs = running.killed; running.lock.unlock()
        return outcome
    }
}
