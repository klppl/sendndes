import CryptoKit
import Foundation

enum Format {
    static let magic: [UInt8] = Array("VALV".utf8)
    static let version: UInt8 = 0x01
    static let chunkPlain = 65536
    static let chunkStored = 65552  // ct + tag
    static let tag = 16
    static let metaLenMin = 540     // 512 + 28
    static let metaLenMax = 65564   // 65536 + 28
}

enum FileKind: UInt8 {
    case object = 0x01
    case inbox = 0x02

    /// Bytes before meta_blob: 86 for objects, 58 for inbox files.
    var fixedHeaderLength: Int { self == .object ? 86 : 58 }
}

// MARK: - Structural check (SPEC 5.3)

struct ChunkLayout {
    let ctTotal: Int64
    let chunkCount: Int64
    let plaintextLength: Int64

    /// Runs before any decryption, including unwrapping FK.
    init(ctTotal ct: Int64) throws {
        let stored = Int64(Format.chunkStored)
        guard ct >= 16 else { throw ValvError.malformed("structural check: ct_total < 16") }
        let r = ct % stored
        if r >= 1 && r <= 15 { throw ValvError.malformed("structural check: ct_total mod 65552 in [1, 15]") }
        if r == 16 && ct != 16 { throw ValvError.malformed("structural check: empty final chunk after a full chunk") }
        ctTotal = ct
        chunkCount = try checkedAdd(ct, stored - 1) / stored  // ceil
        plaintextLength = try checkedSub(ct, checkedMul(16, chunkCount))
    }

    func storedLength(ofChunk i: Int64) -> Int {
        precondition(i >= 0 && i < chunkCount)
        if i < chunkCount - 1 { return Format.chunkStored }
        return Int(ctTotal - (chunkCount - 1) * Int64(Format.chunkStored))
    }
}

/// `u64 chunk_index (BE) | 00 00 00 | final_flag`.
func chunkNonce(_ index: Int64, final: Bool) -> [UInt8] {
    var n = [UInt8]()
    n.reserveCapacity(12)
    n.appendU64BE(UInt64(index))
    n += [0, 0, 0, final ? 1 : 0]
    return n
}

// MARK: - Header (SPEC 5.1, 6.1)

struct FileHeader {
    let kind: FileKind
    let fileID: FileID
    /// Bytes [0, fixedHeaderLength) as stored.
    let fixed: [UInt8]
    let metaLen: Int
    /// nonce 12 | ct | tag 16
    let metaBlob: [UInt8]
    let layout: ChunkLayout

    /// magic | version | kind | file_id (22 bytes).
    var wrapAAD: [UInt8] { fixed.copy(from: 0, count: 22) }
    var wrapNonce: [UInt8] { precondition(kind == .object); return fixed.copy(from: 22, count: 12) }
    var wrappedFK: [UInt8] { precondition(kind == .object); return fixed.copy(from: 34, count: 48) }
    var ephPub: [UInt8] { precondition(kind == .inbox); return fixed.copy(from: 22, count: 32) }
    var metaAAD: [UInt8] { ValvCore.metaAAD(fileID) }

    /// Reads and checks the header and meta_blob, and runs the structural
    /// check, leaving `input` at the first chunk. Nothing is decrypted.
    static func read(_ input: ValvInput, kind: FileKind, expected: FileID) throws -> FileHeader {
        let total = try input.totalLength()
        let fixedLen = kind.fixedHeaderLength
        let fixed = try input.readFull(fixedLen)
        guard fixed.count >= 4, fixed.copy(from: 0, count: 4) == Format.magic else {
            throw ValvError.malformed("bad magic")
        }
        guard fixed.count >= 5 else { throw ValvError.malformed("truncated header") }
        guard fixed[4] == Format.version else { throw ValvError.unsupported("format version \(fixed[4])") }
        guard fixed.count >= 6 else { throw ValvError.malformed("truncated header") }
        guard fixed[5] == kind.rawValue else { throw ValvError.malformed("wrong kind \(fixed[5])") }
        guard fixed.count == fixedLen else { throw ValvError.malformed("truncated header") }

        let metaLen = Int(fixed.readU32BE(at: fixedLen - 4))
        guard metaLen >= Format.metaLenMin, metaLen <= Format.metaLenMax, (metaLen - 28) % 512 == 0 else {
            throw ValvError.malformed("meta_len out of bounds")
        }

        let id = FileID(bytes: fixed.copy(from: 6, count: 16))
        guard constantTimeEqual(id.bytes, expected.bytes) else {
            throw ValvError.path("header file_id does not match the file name")
        }

        let headerLen = try checkedAdd(Int64(fixedLen), Int64(metaLen))
        let layout = try ChunkLayout(ctTotal: checkedSub(total, headerLen))
        let metaBlob = try input.readExactly(metaLen, what: "meta_blob")
        return FileHeader(kind: kind, fileID: id, fixed: fixed, metaLen: metaLen, metaBlob: metaBlob, layout: layout)
    }

    /// Decrypts and strictly parses meta_blob.
    func openMetadata(_ kMeta: SymmetricKey) throws -> Metadata {
        try Metadata.parse(padded: openMetadataBytes(kMeta))
    }

    func openMetadataBytes(_ kMeta: SymmetricKey) throws -> Data {
        try AEAD.open(metaBlob.copy(from: 12, count: metaLen - 12), key: kMeta,
                      nonce: metaBlob.copy(from: 0, count: 12), aad: metaAAD, what: "meta_blob")
    }
}

/// magic | version | file_id (21 bytes; kind deliberately excluded).
func metaAAD(_ id: FileID) -> [UInt8] {
    Format.magic + [Format.version] + id.bytes
}

/// meta_blob = nonce | ChaCha20-Poly1305(K_meta, nonce, meta_aad, padded metadata).
func sealMetadata(_ m: Metadata, key: SymmetricKey, fileID: FileID) throws -> [UInt8] {
    let padded = try m.paddedPlaintext()
    let nonce = Random.bytes(12, for: .metaNonce)
    return nonce + AEAD.seal(padded, key: key, nonce: nonce, aad: metaAAD(fileID))
}

// MARK: - Chunk streams

/// Reads the chunks laid out by a checked header, one at a time.
final class ChunkStream {
    private let input: ValvInput
    private let layout: ChunkLayout
    private let key: SymmetricKey?
    private let aad: [UInt8]
    private(set) var index: Int64 = 0

    init(input: ValvInput, layout: ChunkLayout, key: SymmetricKey?, fileID: FileID) {
        self.input = input
        self.layout = layout
        self.key = key
        self.aad = fileID.bytes
    }

    /// The next stored chunk (ct | tag), or nil after the last. After the
    /// last chunk the input must be at its end.
    func nextStored() throws -> [UInt8]? {
        guard index < layout.chunkCount else { return nil }
        let stored = try input.readExactly(layout.storedLength(ofChunk: index), what: "chunk")
        index += 1
        if index == layout.chunkCount {
            guard try input.read(upTo: 1).isEmpty else {
                throw ValvError.malformed("file grew while it was read")
            }
        }
        return stored
    }

    /// Authenticates and decrypts one stored chunk read by `nextStored`.
    func open(_ stored: [UInt8], at i: Int64) throws -> Data {
        guard let key else { preconditionFailure("stream has no key") }
        return try AEAD.open(stored, key: key, nonce: chunkNonce(i, final: i == layout.chunkCount - 1),
                             aad: aad, what: "chunk \(i)")
    }

    /// The next chunk's authenticated plaintext, or nil after the last.
    func next() throws -> (stored: [UInt8], plaintext: Data)? {
        let i = index
        guard let stored = try nextStored() else { return nil }
        return (stored, try open(stored, at: i))
    }
}

/// Stream-encrypts plaintext with a one-chunk lookahead: a chunk is sealed
/// only once it is known whether more data follows. Holds at most two
/// plaintext chunks. Returns the plaintext length.
@discardableResult
func encryptChunks(from plaintext: ValvInput, key: SymmetricKey, fileID: FileID, to out: ValvOutput) throws -> Int64 {
    var current = try plaintext.readFull(Format.chunkPlain)
    var index: Int64 = 0
    var total: Int64 = 0
    while true {
        // A short chunk can only come from end of input (readFull).
        let next = current.count == Format.chunkPlain ? try plaintext.readFull(Format.chunkPlain) : []
        let final = next.isEmpty
        try out.write(Data(AEAD.seal(current, key: key, nonce: chunkNonce(index, final: final), aad: fileID.bytes)))
        total = try checkedAdd(total, Int64(current.count))
        if final { return total }
        current = next
        index = try checkedAdd(index, 1)
    }
}

// MARK: - Objects

/// An opened object: header checked, FK unwrapped, metadata authenticated
/// and parsed. Chunks are decrypted on demand.
public final class ObjectReader {
    public let fileID: FileID
    public let metadata: Metadata
    /// Derived from the file length (SPEC 5.3).
    public let plaintextLength: Int64
    let header: FileHeader
    private let stream: ChunkStream

    init(vault: Vault, input: ValvInput, expected: FileID) throws {
        header = try FileHeader.read(input, kind: .object, expected: expected)
        let keys = FileKeys(fk: try vault.unwrapFK(header))
        metadata = try header.openMetadata(keys.meta)
        fileID = header.fileID
        plaintextLength = header.layout.plaintextLength
        stream = ChunkStream(input: input, layout: header.layout, key: keys.content, fileID: header.fileID)
    }

    /// The next chunk's plaintext, authenticated, or nil after the last.
    /// Plaintext handed out before the last chunk is valid only if every
    /// chunk authenticates: write it to a temp file and discard it on any
    /// error (SPEC 5.3, 5.4).
    public func nextChunk() throws -> Data? {
        try stream.next()?.plaintext
    }

    public func decryptAll(to output: ValvOutput) throws {
        while let chunk = try nextChunk() {
            try output.write(chunk)
        }
    }
}

extension Vault {
    func unwrapFK(_ h: FileHeader) throws -> SymmetricKey {
        var fk = try AEAD.open(h.wrappedFK, key: kWrap, nonce: h.wrapNonce, aad: h.wrapAAD, what: "wrapped_fk")
        defer { wipe(&fk) }
        return SymmetricKey(data: fk)
    }

    /// Opens an object for reading. `expected` comes from the object's path
    /// (`FileID(objectPath:)`), so the path check cannot be skipped.
    public func openObject(_ input: ValvInput, expected: FileID) throws -> ObjectReader {
        try ObjectReader(vault: self, input: input, expected: expected)
    }

    /// Decrypts a whole object to `output`. On error, discard the output.
    @discardableResult
    public func decryptObject(_ input: ValvInput, expected: FileID, to output: ValvOutput) throws -> Metadata {
        let r = try openObject(input, expected: expected)
        try r.decryptAll(to: output)
        return r.metadata
    }

    /// Authenticates the metadata and every chunk, keeping nothing.
    @discardableResult
    public func verifyObject(_ input: ValvInput, expected: FileID) throws -> Metadata {
        try decryptObject(input, expected: expected, to: DiscardOutput())
    }

    /// Encrypts `plaintext` into a new object with a random file_id and a
    /// fresh FK. Write `output` to a temp file and move it to the returned
    /// id's `objectPath` only after this returns (SPEC 8).
    public func writeObject(plaintext: ValvInput, metadata: Metadata, to output: ValvOutput) throws -> FileID {
        let fileID = FileID(bytes: Random.bytes(16, for: .fileID))
        var fkRaw = Random.bytes(32, for: .fk)
        let keys = FileKeys(fk: takeKey(&fkRaw))
        let metaBlob = try sealMetadata(metadata, key: keys.meta, fileID: fileID)
        try output.write(Data(objectHeader(fileID: fileID, fk: keys.fk, metaLen: metaBlob.count)))
        try output.write(Data(metaBlob))
        try encryptChunks(from: plaintext, key: keys.content, fileID: fileID, to: output)
        return fileID
    }

    /// The 86 fixed header bytes, with FK wrapped under K_wrap with a fresh nonce.
    func objectHeader(fileID: FileID, fk: SymmetricKey, metaLen: Int) -> [UInt8] {
        var h = Format.magic + [Format.version, FileKind.object.rawValue] + fileID.bytes
        let wrapNonce = Random.bytes(12, for: .fkWrapNonce)
        let wrapped = fk.withUnsafeBytes { AEAD.seal($0, key: kWrap, nonce: wrapNonce, aad: h) }
        h += wrapNonce
        h += wrapped
        h.appendU32BE(UInt32(metaLen))
        precondition(h.count == FileKind.object.fixedHeaderLength)
        return h
    }
}
