import Foundation
import NdesCore
import UniformTypeIdentifiers

public enum SealError: Error, Equatable, Sendable {
    case tooLarge(Int64)
    case notARegularFile
    case cannotRead
    case fileChanged
    case badFolder
    case sealingFailed
}

/// Reads a file for sealing and refuses to read more than it was told to expect: a file that grows while it is
/// read (or a provider that reports the wrong size) cannot make the app read past `limit` bytes.
final class GuardedInput: NdesInput, @unchecked Sendable {
    private let inner: NdesInput
    private let allowed: Int64
    private var total: Int64 = 0

    /// `declared` is the size seen on the open file descriptor. NdesCore reads exactly that many bytes and then
    /// one more to check for growth, so one extra byte is allowed here and a second one is an error.
    init(_ inner: NdesInput, declared: Int64, limit: Int64) {
        self.inner = inner
        self.allowed = min(declared, limit) + 1
    }

    func read(upTo count: Int) throws -> Data {
        let room = allowed - total
        guard room > 0 else { throw SealError.fileChanged }
        let d = try inner.read(upTo: Int(min(Int64(count), room)))
        total += Int64(d.count)
        return d
    }

    func totalLength() throws -> Int64 { try inner.totalLength() }
}

/// Seals one file for the paired vault, straight from the file the item provider gave us (no extra plaintext
/// copy), into the outbox. Memory stays at a few 64 KiB chunks whatever the file size.
public struct ShareSealer: Sendable {
    public let pairing: Pairing
    public let outbox: Outbox
    public let files: FileProtecting
    public let folder: String
    private let now: @Sendable () -> Date

    public init(pairing: Pairing, outbox: Outbox, files: FileProtecting = NoProtection(), folder: String,
                now: @escaping @Sendable () -> Date = { Date() }) {
        self.pairing = pairing
        self.outbox = outbox
        self.files = files
        self.folder = folder
        self.now = now
    }

    /// What the app shows for a candidate before sealing, and what decides whether it is sealed at all.
    public struct Candidate: Equatable, Sendable {
        public let size: Int64
        public let mtimeNanos: Int64?
        public let device: UInt64
        public let inode: UInt64
    }

    /// Opens `url` without following a final symlink, checks it is a regular file and within the size limit.
    public static func inspect(_ url: URL) throws -> (fd: Int32, candidate: Candidate) {
        // O_NONBLOCK: opening a FIFO must not hang; it is refused below and the flag is cleared for real files.
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw errno == ELOOP ? SealError.notARegularFile : SealError.cannotRead }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { close(fd); throw SealError.notARegularFile }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK)
        let size = Int64(st.st_size)
        guard size <= SenderLimits.maxFileBytes else { close(fd); throw SealError.tooLarge(size) }
        let ns = Self.nanos(st.st_mtimespec)
        return (fd, Candidate(size: size, mtimeNanos: ns, device: UInt64(st.st_dev), inode: UInt64(st.st_ino)))
    }

    static func nanos(_ ts: timespec) -> Int64? {
        let (a, o1) = Int64(ts.tv_sec).multipliedReportingOverflow(by: 1_000_000_000)
        let (b, o2) = a.addingReportingOverflow(Int64(ts.tv_nsec))
        return (o1 || o2) ? nil : b
    }

    public func seal(fileAt url: URL, suggestedName: String?, mime: String? = nil) throws -> SealedItem {
        guard FileNames.validateFolder(folder) != nil else { throw SealError.badFolder }
        let (fd, cand) = try Self.inspect(url)
        return try sealOpened(fd: fd, candidate: cand, url: url, suggestedName: suggestedName, mime: mime)
    }

    /// The second half of `seal`, after the file is open and checked. Split out so tests can change the file in between.
    package func sealOpened(fd: Int32, candidate cand: Candidate, url: URL, suggestedName: String?, mime: String?) throws -> SealedItem {
        guard let dir = FileNames.validateFolder(folder) else { close(fd); throw SealError.badFolder }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)

        let ext = url.pathExtension.isEmpty ? (suggestedName.map { ($0 as NSString).pathExtension } ?? "") : url.pathExtension
        let name = FileNames.sanitize(suggestedName, fallback: FileNames.fallbackName(now: now(), ext: ext))
        let type = mime ?? (ext.isEmpty ? nil : UTType(filenameExtension: ext)?.preferredMIMEType) ?? ""
        let mtime = cand.mtimeNanos ?? Int64(now().timeIntervalSince1970 * 1_000_000_000)

        let meta: Metadata
        do { meta = try Metadata(name: name, dir: dir, mtime: mtime, mime: type, rev: 1, size: cand.size) }
        catch { throw SealError.sealingFailed }

        let tmp = outbox.newTempURL()
        guard FileManager.default.createFile(atPath: tmp.path, contents: nil, attributes: [.posixPermissions: 0o600]),
              let out = try? FileHandle(forWritingTo: tmp) else { throw SealError.sealingFailed }
        var cleanup = true
        defer { if cleanup { try? out.close(); try? FileManager.default.removeItem(at: tmp) } }

        let sealer = InboxSealer(inboxPub: pairing.inboxPub, kAuthBytes: pairing.kAuth)
        let fileID: FileID
        do {
            let input = GuardedInput(FileInput(handle), declared: cand.size, limit: SenderLimits.maxFileBytes)
            fileID = try sealer.seal(plaintext: input, metadata: meta, to: FileOutput(out))
            try out.synchronize()
            try out.close()
        } catch let e as SealError {
            throw e
        } catch NdesError.io {
            throw SealError.fileChanged      // shorter or longer than it was when we looked
        } catch {
            throw SealError.sealingFailed
        }
        // The file must not have changed while it was read (the same check as the Mac app).
        var after = stat()
        guard fstat(handle.fileDescriptor, &after) == 0,
              Int64(after.st_size) == cand.size, UInt64(after.st_ino) == cand.inode, Self.nanos(after.st_mtimespec) == cand.mtimeNanos else {
            throw SealError.fileChanged
        }

        let final = outbox.sealedURL(fileID.hex)
        do {
            try FileManager.default.moveItem(at: tmp, to: final)
            cleanup = false
            try files.protect(final)
            let sealedSize = (try? FileManager.default.attributesOfItem(atPath: final.path)[.size] as? Int64) ?? 0
            return try outbox.add(id: fileID.hex, displayName: name, size: cand.size, sealedSize: sealedSize, pairingFP: pairing.fingerprint)
        } catch {
            try? FileManager.default.removeItem(at: final)
            outbox.discardQuietly(fileID.hex)
            throw SealError.sealingFailed
        }
    }
}
