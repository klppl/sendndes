import CryptoKit
import Foundation

/// FK = HKDF-SHA256(ikm = DH | K_auth, salt = eph_pub | inbox_pub,
/// info = "ndes/v1/inbox-fk", L = 32)   (SPEC 6.2)
func inboxFK(dh: [UInt8], kAuth: SymmetricKey, ephPub: [UInt8], inboxPub: [UInt8]) -> SymmetricKey {
    var ikm = dh + keyBytes(kAuth)
    defer { wipe(&ikm) }
    return hkdf32(SymmetricKey(data: ikm), salt: ephPub + inboxPub, info: Label.inboxFK)
}

/// Seals files to a vault's inbox (SPEC 6.2). Holds only `inbox_pub` and
/// K_auth: it cannot read anything, including what it sealed.
public struct InboxSealer: Sendable {
    let inboxPub: [UInt8]
    let kAuth: SymmetricKey

    public init(inboxPub: [UInt8], kAuth: SymmetricKey) {
        precondition(inboxPub.count == 32)
        self.inboxPub = inboxPub
        self.kAuth = kAuth
    }

    public init(inboxPub: [UInt8], kAuthBytes: [UInt8]) {
        precondition(inboxPub.count == 32)
        precondition(kAuthBytes.count == 32)
        self.inboxPub = inboxPub
        self.kAuth = SymmetricKey(data: kAuthBytes)
    }

    public init(inboxPubBase64: String, kAuthBase64: String) throws {
        guard let pub = Data(base64Encoded: inboxPubBase64), pub.count == 32,
              let auth = Data(base64Encoded: kAuthBase64), auth.count == 32 else {
            throw NdesError.malformed("invalid inbox_pub or k_auth")
        }
        self.init(inboxPub: [UInt8](pub), kAuth: SymmetricKey(data: auth))
    }

    /// Seals `plaintext` into a new inbox file with a random file_id and a
    /// fresh ephemeral key. `metadata.rev` must be 1. Returns the file_id;
    /// the file belongs at its `inboxPath`.
    public func seal(plaintext: NdesInput, metadata: Metadata, to output: NdesOutput) throws -> FileID {
        guard metadata.rev == 1 else { throw NdesError.metadata("inbox files are written with rev 1") }
        let fileID = FileID(bytes: Random.bytes(16, for: .fileID))
        var ephRaw = Random.bytes(32, for: .ephemeralKey)
        let eph = try X25519.privateKey(&ephRaw)
        let ephPub = [UInt8](eph.publicKey.rawRepresentation)
        var dh = try X25519.sharedSecret(eph, inboxPub)
        let keys = FileKeys(fk: inboxFK(dh: dh, kAuth: kAuth, ephPub: ephPub, inboxPub: inboxPub))
        wipe(&dh)

        let metaBlob = try sealMetadata(metadata, key: keys.meta, fileID: fileID)
        var h = Format.magic + [Format.version, FileKind.inbox.rawValue] + fileID.bytes + ephPub
        h.appendU32BE(UInt32(metaBlob.count))
        try output.write(Data(h))
        try output.write(Data(metaBlob))
        try encryptChunks(from: plaintext, key: keys.content, fileID: fileID, to: output)
        // eph and keys go out of scope here; CryptoKit zeroes their storage.
        return fileID
    }
}

/// An opened inbox file: header checked, FK derived, metadata authenticated
/// and parsed.
public final class InboxReader {
    public let fileID: FileID
    public let metadata: Metadata
    public let plaintextLength: Int64
    let header: FileHeader
    let keys: FileKeys
    private let stream: ChunkStream

    init(vault: Vault, input: NdesInput, expected: FileID) throws {
        let (h, k) = try vault.openInboxHeader(input, expected: expected)
        header = h
        keys = k
        do {
            metadata = try h.openMetadata(k.meta)
        } catch NdesError.auth {
            throw NdesError.auth("inbox file is not authentic")
        }
        fileID = h.fileID
        plaintextLength = h.layout.plaintextLength
        stream = ChunkStream(input: input, layout: h.layout, key: k.content, fileID: h.fileID)
    }

    /// Like `ObjectReader.nextChunk`.
    public func nextChunk() throws -> Data? {
        try stream.next()?.plaintext
    }

    fileprivate func nextChunkWithStored() throws -> (stored: [UInt8], plaintext: Data)? {
        try stream.next()
    }

    public func decryptAll(to output: NdesOutput) throws {
        while let chunk = try nextChunk() {
            try output.write(chunk)
        }
    }
}

/// Result of comparing an inbox file with an existing object of the same
/// file_id (SPEC 6.3 idempotency).
public enum IngestComparison: Equatable, Sendable {
    /// Same FK, valid metadata, identical authenticated chunks: delete the inbox file.
    case alreadyIngested
    /// Report a conflict and delete nothing.
    case conflict
}

extension Vault {
    /// The sealer for this vault's inbox, as the inbox server would hold it.
    public func makeInboxSealer() -> InboxSealer {
        InboxSealer(inboxPub: inboxPublicKey, kAuth: kAuth)
    }

    /// Header and structural check, then DH (all-zero rejected) and FK.
    func openInboxHeader(_ input: NdesInput, expected: FileID) throws -> (FileHeader, FileKeys) {
        let h = try FileHeader.read(input, kind: .inbox, expected: expected)
        var dh = try X25519.sharedSecret(inboxPrivateKey, h.ephPub)
        defer { wipe(&dh) }
        let fk = inboxFK(dh: dh, kAuth: kAuth, ephPub: h.ephPub, inboxPub: inboxPublicKey)
        return (h, FileKeys(fk: fk))
    }

    /// Opens an inbox file for reading. `expected` comes from `FileID(inboxPath:)`.
    public func openInbox(_ input: NdesInput, expected: FileID) throws -> InboxReader {
        try InboxReader(vault: self, input: input, expected: expected)
    }

    /// Ingest transform (SPEC 6.3 steps 1 to 3): writes an object with the
    /// same file_id, FK re-wrapped under K_wrap with a fresh nonce, meta_blob
    /// copied verbatim and chunks copied byte for byte, each authenticated
    /// before it is copied. `output` must be a temp file; on any error discard
    /// it and keep the inbox file. Moving the object into place, reading it
    /// back (`verifyObject`) and only then deleting the inbox file are the
    /// caller's steps 4 and 5.
    @discardableResult
    public func ingest(inbox input: NdesInput, expected: FileID, to output: NdesOutput) throws -> Metadata {
        let reader = try openInbox(input, expected: expected)
        let h = reader.header
        try output.write(Data(objectHeader(fileID: h.fileID, fk: reader.keys.fk, metaLen: h.metaLen)))
        try output.write(Data(h.metaBlob))
        while let chunk = try reader.nextChunkWithStored() {
            try output.write(Data(chunk.stored))
        }
        return reader.metadata
    }

    /// SPEC 6.3 idempotency: is the inbox file already ingested as
    /// `existingObject`? First authenticates the inbox file itself (header,
    /// `meta_blob` and every chunk); any error in the inbox file is thrown so
    /// the caller keeps the inbox file. Then requires (1) the object's
    /// unwrapped FK to equal the inbox FK (constant time), (2) the object's
    /// `meta_blob` to decrypt under it and pass SPEC 5.2, and (3)
    /// byte-identical chunks, authenticated during the comparison. The two
    /// `meta_blob`s may differ (renames). Anything wrong with the object is a
    /// conflict.
    public func compareIngested(inbox: NdesInput, existingObject: NdesInput, expected: FileID) throws -> IngestComparison {
        let reader = try openInbox(inbox, expected: expected)
        let ih = reader.header
        let ikeys = reader.keys
        var ostream: ChunkStream?
        do {
            let oh = try FileHeader.read(existingObject, kind: .object, expected: expected)
            let ofk = try unwrapFK(oh)
            if constantTimeEqual(keyBytes(ofk), keyBytes(ikeys.fk)) {
                let okeys = FileKeys(fk: ofk)
                _ = try oh.openMetadata(okeys.meta)
                if ih.layout.ctTotal == oh.layout.ctTotal {
                    ostream = ChunkStream(input: existingObject, layout: oh.layout, key: okeys.content, fileID: oh.fileID)
                }
            }
        } catch let e as NdesError {
            if case .io = e { throw e }
        }
        var matches = ostream != nil
        while let ichunk = try reader.nextChunkWithStored() {
            if matches, let os = ostream {
                do {
                    if let ostored = try os.next()?.stored, constantTimeEqual(ichunk.stored, ostored) {
                        continue
                    }
                } catch let e as NdesError {
                    if case .io = e { throw e }
                }
                matches = false
            }
        }
        return matches ? .alreadyIngested : .conflict
    }

    /// SPEC 4.5: an inbox file authenticates if its meta_blob and first chunk do.
    func inboxAuthenticates(_ c: RecoveryCandidate) -> Bool {
        guard let expected = try? FileID(inboxPath: c.path),
              let input = try? c.open(),
              let (h, keys) = try? openInboxHeader(input, expected: expected),
              (try? h.openMetadataBytes(keys.meta)) != nil else {
            return false
        }
        let stream = ChunkStream(input: input, layout: h.layout, key: keys.content, fileID: h.fileID)
        guard let first = try? stream.nextStored(), (try? stream.open(first, at: 0)) != nil else {
            return false
        }
        return true
    }
}
