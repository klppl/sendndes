import Foundation

/// A byte source. NdesCore never reads a whole file: it asks for at most one
/// stored chunk (65552 bytes) or one metadata blob at a time.
public protocol NdesInput: AnyObject {
    /// Reads up to `count` bytes. Returns an empty Data only at end of input.
    func read(upTo count: Int) throws -> Data
    /// Total length in bytes. Needed only for object and inbox files (the
    /// structural check, SPEC 5.3); plaintext sources may throw.
    func totalLength() throws -> Int64
}

/// A byte sink.
public protocol NdesOutput: AnyObject {
    func write(_ data: Data) throws
}

extension NdesInput {
    /// Reads until `count` bytes or end of input, whichever comes first, so a
    /// short read from a pipe never shortens a chunk. Returns a zero-based array.
    func readFull(_ count: Int) throws -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(count)
        while out.count < count {
            let d = try read(upTo: count - out.count)
            if d.isEmpty { break }
            out.append(contentsOf: d)
        }
        return out
    }

    /// Reads exactly `count` bytes; a short read means the file changed under us.
    func readExactly(_ count: Int, what: String) throws -> [UInt8] {
        let b = try readFull(count)
        guard b.count == count else { throw NdesError.malformed("\(what): file ended early") }
        return b
    }
}

/// Reads from an open file. The length is taken with fstat when first needed.
public final class FileInput: NdesInput {
    private let handle: FileHandle

    public init(_ handle: FileHandle) {
        self.handle = handle
    }

    public convenience init(url: URL) throws {
        do {
            self.init(try FileHandle(forReadingFrom: url))
        } catch {
            throw NdesError.io("cannot open \(url.lastPathComponent)")
        }
    }

    public func read(upTo count: Int) throws -> Data {
        // FileHandle returns autoreleased buffers. Without a pool per read,
        // every chunk stays alive until the caller's pool drains, which for a
        // CLI or one long GCD work item is the end of the whole file: memory
        // then grows with file size. The pool keeps it at one chunk.
        try autoreleasepool {
            do {
                return try handle.read(upToCount: count) ?? Data()
            } catch {
                throw NdesError.io("read failed")
            }
        }
    }

    public func totalLength() throws -> Int64 {
        var st = stat()
        guard fstat(handle.fileDescriptor, &st) == 0 else { throw NdesError.io("fstat failed") }
        guard (st.st_mode & S_IFMT) == S_IFREG else { throw NdesError.io("not a regular file") }
        return Int64(st.st_size)
    }
}

/// Writes to an open file.
public final class FileOutput: NdesOutput {
    private let handle: FileHandle

    public init(_ handle: FileHandle) {
        self.handle = handle
    }

    public func write(_ data: Data) throws {
        // See FileInput.read: drain per call so writes cannot accumulate either.
        try autoreleasepool {
            do {
                try handle.write(contentsOf: data)
            } catch {
                throw NdesError.io("write failed")
            }
        }
    }
}

/// In-memory input, for tests and small buffers.
public final class DataInput: NdesInput {
    private let data: [UInt8]
    private var offset = 0

    public init<D: DataProtocol>(_ data: D) {
        self.data = [UInt8](data)
    }

    public func read(upTo count: Int) throws -> Data {
        let n = min(count, data.count - offset)
        defer { offset += n }
        return Data(data[offset..<(offset + n)])
    }

    public func totalLength() throws -> Int64 {
        Int64(data.count)
    }
}

/// In-memory output, for tests.
public final class DataOutput: NdesOutput {
    public private(set) var data = Data()

    public init() {}

    public func write(_ d: Data) throws {
        data.append(d)
    }
}

/// Discards everything; used to authenticate without keeping plaintext.
public final class DiscardOutput: NdesOutput {
    public init() {}
    public func write(_ data: Data) throws {}
}
