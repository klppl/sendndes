import Foundation
import UniformTypeIdentifiers

/// A private 0700 directory `<T>/sendndes-<pid>-<128-bit hex>/` holding one decrypted copy that is
/// opened in another app. Removed on lock, quit, signals and (for dead processes) at next launch by
/// `TokenFile.sweep`, which matches the same directory pattern.
public final class PrivateDir {
    public let path: String
    private var removed = false
    private let lock = NSLock()
    private static let activeLock = NSLock()
    private static var active: [PrivateDir] = []

    public static func create(base: String? = nil) throws -> PrivateDir {
        let root = base ?? TokenFile.userTempDir
        var rnd = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, rnd.count, &rnd) == errSecSuccess else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(EIO)) }
        let dir = "\(root)/sendndes-\(getpid())-" + rnd.map { String(format: "%02x", $0) }.joined()
        if mkdir(dir, 0o700) != 0 { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        let mark = open("\(dir)/.metadata_never_index", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if mark >= 0 { close(mark) }
        let d = PrivateDir(path: dir)
        activeLock.lock(); active.append(d); activeLock.unlock()
        return d
    }

    private init(path: String) { self.path = path }

    /// Idempotent. The directory only ever holds regular files made by the helper; anything else is left alone.
    public func remove() {
        lock.lock(); defer { lock.unlock() }
        if removed { return }
        removed = true
        for e in (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? [] {
            var st = stat()
            if lstat("\(path)/\(e)", &st) == 0, (st.st_mode & S_IFMT) != S_IFDIR { unlink("\(path)/\(e)") }
        }
        rmdir(path)
        PrivateDir.activeLock.lock()
        PrivateDir.active.removeAll { $0 === self }
        PrivateDir.activeLock.unlock()
    }

    public static func removeAll() {
        activeLock.lock(); let all = active; activeLock.unlock()
        all.forEach { $0.remove() }
    }
}

/// Which decrypted files the app hands to the default app. Anything that can run code or script a
/// browser (apps, scripts, installers, HTML, SVG, unknown types) is refused: use Export for those.
public enum OpenPolicy {
    static let allowedExact: [UTType] = [.plainText, .utf8PlainText, .rtf, .commaSeparatedText, .pdf]

    public static func canOpen(fileName: String) -> Bool {
        let ext = (fileName as NSString).pathExtension.lowercased()
        guard !ext.isEmpty, let t = UTType(filenameExtension: ext) else { return false }
        let refused: [UTType] = [.application, .executable, .script, .sourceCode, .html, .xml, .svg, .archive, .diskImage, .package, .bundle, .internetLocation, .urlBookmarkData]
        if refused.contains(where: { t.conforms(to: $0) }) { return false }
        if allowedExact.contains(where: { t == $0 }) { return true }
        if t.conforms(to: .image) || t.conforms(to: .audiovisualContent) { return true }
        return false
    }
}
