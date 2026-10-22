import CryptoKit
import Foundation
import Testing
@testable import NdesCore

@Suite struct InboxTests {
    nonisolated(unsafe) static let ib = (vectors["inbox"] as! [JSONObject])[0]
    var ib: JSONObject { InboxTests.ib }
    var ingest: JSONObject { ib["ingest"] as! JSONObject }
    var inboxFile: Data { vfile(ib["file"] as! String) }
    var ingestedFile: Data { vfile(ingest["file"] as! String) }
    var expected: FileID { try! FileID(inboxPath: ib["path"] as! String) }

    @Test func opensInboxVector() throws {
        #expect(sha256hex(inboxFile) == ib["file_sha256"] as! String)
        let r = try testVault.openInbox(DataInput(inboxFile), expected: expected)
        #expect(r.metadata == storedMetadata(ib["meta"] as! JSONObject))
        #expect(r.plaintextLength == Int64(ib["plaintext_len"] as! Int))
        let out = DataOutput()
        try r.decryptAll(to: out)
        #expect(out.data == vfile(ib["plaintext_file"] as! String))

        #expect(keyBytes(r.keys.fk) == hex(ib["fk"]))
        #expect(keyBytes(r.keys.content) == hex(ib["k_content"]))
        #expect(keyBytes(r.keys.meta) == hex(ib["k_meta"]))
        #expect(r.header.ephPub == hex(ib["eph_pub"]))
        #expect(r.header.metaBlob == hex(ib["meta_blob"]))
    }

    @Test func intermediateValues() throws {
        var eph = hex(ib["eph_priv"])
        let priv = try X25519.privateKey(&eph)
        #expect([UInt8](priv.publicKey.rawRepresentation) == hex(ib["eph_pub"]))
        let dh = try X25519.sharedSecret(priv, hex(ib["inbox_pub"]))
        #expect(dh == hex(ib["dh"]))
        // Both sides agree.
        #expect(try X25519.sharedSecret(testVault.inboxPrivateKey, hex(ib["eph_pub"])) == dh)
        #expect(dh + keyBytes(testVault.kAuth) == hex(ib["hkdf_ikm"]))
        #expect(hex(ib["eph_pub"]) + testVault.inboxPublicKey == hex(ib["hkdf_salt"]))
        let fk = inboxFK(dh: dh, kAuth: testVault.kAuth, ephPub: hex(ib["eph_pub"]), inboxPub: testVault.inboxPublicKey)
        #expect(keyBytes(fk) == hex(ib["fk"]))
    }

    @Test func allZeroSharedSecretRejected() throws {
        // Low-order points give an all-zero X25519 result.
        let lowOrder: [[UInt8]] = [
            [UInt8](repeating: 0, count: 32),
            [1] + [UInt8](repeating: 0, count: 31),
        ]
        for p in lowOrder {
            #expect(errorClass { _ = try X25519.sharedSecret(testVault.inboxPrivateKey, p) } == "malformed")
        }
    }

    @Test func ingestedObjectVector() throws {
        #expect(sha256hex(ingestedFile) == ingest["file_sha256"] as! String)
        let id = try FileID(objectPath: expected.objectPath)
        let out = DataOutput()
        let m = try testVault.decryptObject(DataInput(ingestedFile), expected: id, to: out)
        #expect(m == storedMetadata(ib["meta"] as! JSONObject))
        #expect(out.data == vfile(ib["plaintext_file"] as! String))
        #expect([UInt8](ingestedFile.prefix(86)) == hex(ingest["header"]).prefix(86).map { $0 })
    }

    #if NDES_TESTVECTORS
    @Test func sealReproducesInboxFile() throws {
        let out = DataOutput()
        let (id, source) = try TestHooks.withFixedRandom([
            .fileID: [hex(ib["file_id"])],
            .ephemeralKey: [hex(ib["eph_priv"])],
            .metaNonce: [hex(ib["meta_nonce"])],
        ]) {
            try testVault.makeInboxSealer().seal(plaintext: DataInput(vfile(ib["plaintext_file"] as! String)),
                                                 metadata: storedMetadata(ib["meta"] as! JSONObject), to: out)
        }
        #expect(source.isExhausted)
        #expect(id.inboxPath == ib["path"] as! String)
        #expect(out.data == inboxFile)
    }

    @Test func ingestReproducesObject() throws {
        let out = DataOutput()
        let (_, source) = try TestHooks.withFixedRandom([.fkWrapNonce: [hex(ingest["wrap_nonce"])]]) {
            try testVault.ingest(inbox: DataInput(inboxFile), expected: expected, to: out)
        }
        #expect(source.isExhausted)
        #expect(out.data == ingestedFile)
    }
    #endif

    @Test func ingestCopiesMetaAndChunksVerbatim() throws {
        let out = DataOutput()
        try testVault.ingest(inbox: DataInput(inboxFile), expected: expected, to: out)
        // Only wrap_nonce and wrapped_fk (bytes 22..<82) may differ.
        #expect(out.data.count == ingestedFile.count)
        #expect(out.data.prefix(22) == ingestedFile.prefix(22))
        #expect(out.data.dropFirst(82) == ingestedFile.dropFirst(82))
        #expect(inboxFile.dropFirst(58) == ingestedFile.dropFirst(86))
    }

    @Test func alreadyIngestedComparison() throws {
        #expect(try testVault.compareIngested(inbox: DataInput(inboxFile), existingObject: DataInput(ingestedFile),
                                              expected: expected) == .alreadyIngested)
        // A rename (new meta_blob, same FK and chunks) still counts as ingested.
        let r = try testVault.openObject(DataInput(ingestedFile), expected: expected)
        let fk = try testVault.unwrapFK(r.header)
        let renamed = try Metadata(name: "renamed.pdf", dir: "", mtime: 1, mime: "", rev: 2, size: r.metadata.size)
        let blob = try sealMetadata(renamed, key: FileKeys(fk: fk).meta, fileID: expected)
        var obj = [UInt8](ingestedFile)
        obj.replaceSubrange(86..<(86 + blob.count), with: blob)
        #expect(try testVault.compareIngested(inbox: DataInput(inboxFile), existingObject: DataInput(obj),
                                              expected: expected) == .alreadyIngested)

        // A flipped chunk bit in the object is a conflict.
        var flipped = [UInt8](ingestedFile)
        flipped[flipped.count - 1] ^= 1
        #expect(try testVault.compareIngested(inbox: DataInput(inboxFile), existingObject: DataInput(flipped),
                                              expected: expected) == .conflict)
        // An object with another FK but the same file_id is a conflict.
        let reader = try testVault.openInbox(DataInput(inboxFile), expected: expected)
        let content = DataOutput()
        try reader.decryptAll(to: content)
        // writeObject always picks a fresh file_id, so build one by hand.
        let fresh = DataOutput()
        let freshFK = SymmetricKey(size: .bits256)
        let keys = FileKeys(fk: freshFK)
        let mb = try sealMetadata(reader.metadata, key: keys.meta, fileID: expected)
        try fresh.write(Data(testVault.objectHeader(fileID: expected, fk: freshFK, metaLen: mb.count)))
        try fresh.write(Data(mb))
        try encryptChunks(from: DataInput(content.data), size: reader.metadata.size, key: keys.content, fileID: expected, to: fresh)
        #expect(try testVault.verifyObject(DataInput(fresh.data), expected: expected) == reader.metadata)
        #expect(try testVault.compareIngested(inbox: DataInput(inboxFile), existingObject: DataInput(fresh.data),
                                              expected: expected) == .conflict)
    }

    @Test func alreadyIngestedRequiresAuthenticInbox() throws {
        // Tampered meta_blob in the inbox file must fail with auth (keeping .inb),
        // even when a valid matching object already exists.
        var badMeta = [UInt8](inboxFile)
        badMeta[58] ^= 1
        #expect(errorClass {
            _ = try testVault.compareIngested(inbox: DataInput(badMeta), existingObject: DataInput(ingestedFile),
                                              expected: expected)
        } == "auth")

        // Tampered chunk in the inbox file must fail with auth (keeping .inb),
        // even when a valid matching object already exists.
        var badChunk = [UInt8](inboxFile)
        badChunk[badChunk.count - 1] ^= 1
        #expect(errorClass {
            _ = try testVault.compareIngested(inbox: DataInput(badChunk), existingObject: DataInput(ingestedFile),
                                              expected: expected)
        } == "auth")
    }

    @Test func standaloneInboxSealer() throws {
        let pubB64 = Data(testVault.inboxPublicKey).base64EncodedString()
        let authB64 = Data(keyBytes(testVault.kAuth)).base64EncodedString()
        let sealer = try InboxSealer(inboxPubBase64: pubB64, kAuthBase64: authB64)
        let plain = Data("standalone inbox sealer test".utf8)
        let meta = try Metadata(name: "test.txt", dir: "sub", mtime: 1234567, mime: "text/plain", rev: 1, size: Int64(plain.count))
        let out = DataOutput()
        let fileID = try sealer.seal(plaintext: DataInput(plain), metadata: meta, to: out)

        let reader = try testVault.openInbox(DataInput(out.data), expected: fileID)
        #expect(reader.fileID == fileID)
        #expect(reader.metadata == meta)
        let dec = DataOutput()
        try reader.decryptAll(to: dec)
        #expect(dec.data == plain)
    }
}
