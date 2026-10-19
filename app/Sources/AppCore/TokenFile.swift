import Foundation

/// The token handed to `valv pull --token-file`: a 0600 file in a private 0700
/// directory `<T>/sendndes-<pid>-<128-bit hex>/` that is deleted as soon as the
/// helper says it has read it.
public final class TokenFile {
    public let dirPath: String
    public let filePath: String
    private var removed = false
    private let lock = NSLock()

    private static let activeLock = NSLock()
    private static var active: [TokenFile] = []

    /// confstr(_CS_DARWIN_USER_TEMP_DIR): the per-user temp dir; $TMPDIR is ignored.
    public static var userTempDir: String {
        var buf = [CChar](repeating: 0, count: Int(PATH_MAX))
        if confstr(_CS_DARWIN_USER_TEMP_DIR, &buf, buf.count) > 0 {
            var s = String(cString: buf)
            while s.count > 1 && s.hasSuffix("/") { s.removeLast() }
            return s
        }
        return NSTemporaryDirectory()
    }

    public static func create(token: String, base: String? = nil) throws -> TokenFile {
        let root = base ?? userTempDir
        var rnd = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, rnd.count, &rnd) == errSecSuccess else { throw posix(EIO) }
        let hex = rnd.map { String(format: "%02x", $0) }.joined()
        let dir = "\(root)/sendndes-\(getpid())-\(hex)"
        if mkdir(dir, 0o700) != 0 { throw posix(errno) }
        let file = "\(dir)/tok"
        let tf = TokenFile(dirPath: dir, filePath: file)
        do {
            let mark = open("\(dir)/.metadata_never_index", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if mark >= 0 { close(mark) }
            let fd = open(file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if fd < 0 { throw posix(errno) }
            defer { close(fd) }
            fchmod(fd, 0o600)
            var bytes = Array((token + "\n").utf8)
            defer { for i in bytes.indices { bytes[i] = 0 } }
            var off = 0
            while off < bytes.count {
                let n = bytes.withUnsafeBytes { write(fd, $0.baseAddress! + off, bytes.count - off) }
                if n < 0 { if errno == EINTR { continue }; throw posix(errno) }
                off += n
            }
        } catch {
            tf.remove()
            throw error
        }
        activeLock.lock(); active.append(tf); activeLock.unlock()
        return tf
    }

    private init(dirPath: String, filePath: String) {
        self.dirPath = dirPath
        self.filePath = filePath
    }

    /// Idempotent.
    public func remove() {
        lock.lock(); defer { lock.unlock() }
        if removed { return }
        removed = true
        unlink(filePath)
        unlink("\(dirPath)/.metadata_never_index")
        rmdir(dirPath)
        TokenFile.activeLock.lock()
        TokenFile.active.removeAll { $0 === self }
        TokenFile.activeLock.unlock()
    }

    public static func removeAll() {
        activeLock.lock(); let all = active; activeLock.unlock()
        all.forEach { $0.remove() }
    }

    /// At launch: remove `sendndes-<pid>-*` directories whose pid is gone.
    /// lstat only, no following; a live instance's directory is never touched.
    public static func sweep(base: String? = nil) {
        let root = base ?? userTempDir
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: root) else { return }
        for n in names where n.hasPrefix("sendndes-") {
            let parts = n.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count == 3, let pid = Int32(parts[1]), pid > 0 else { continue }
            if kill(pid, 0) == 0 || errno != ESRCH { continue }
            let dir = "\(root)/\(n)"
            var st = stat()
            guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == geteuid() else { continue }
            for e in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] {
                var es = stat()
                if lstat("\(dir)/\(e)", &es) == 0, (es.st_mode & S_IFMT) != S_IFDIR { unlink("\(dir)/\(e)") }
            }
            rmdir(dir)
        }
    }

    private static func posix(_ code: Int32) -> Error { NSError(domain: NSPOSIXErrorDomain, code: Int(code)) }
}
