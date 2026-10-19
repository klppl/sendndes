import Foundation
import Testing
@testable import ValvCore

@Suite struct ObjectTests {
    nonisolated(unsafe) static let objects = vectors["objects"] as! [JSONObject]

    @Test(arguments: objects.indices)
    func decryptsVector(_ i: Int) throws {
        let o = ObjectTests.objects[i]
        let file = vfile(o["file"] as! String)
        #expect(sha256hex(file) == o["file_sha256"] as! String)
        let expected = try FileID(objectPath: o["path"] as! String)
        #expect(expected.hex == o["file_id"] as! String)

        let reader = try testVault.openObject(DataInput(file), expected: expected)
        #expect(reader.metadata == storedMetadata(o["meta"] as! JSONObject))
        #expect(reader.plaintextLength == Int64(o["plaintext_len"] as! Int))
        #expect(reader.metadata.isNFC == !(o["warn_non_nfc"] as? Bool ?? false))
        let out = DataOutput()
        try reader.decryptAll(to: out)
        #expect(out.data == vfile(o["plaintext_file"] as! String))
        #expect(sha256hex(out.data) == o["plaintext_sha256"] as! String)

        // Intermediate values.
        let h = reader.header
        #expect(h.layout.ctTotal == Int64(o["ct_total"] as! Int))
        #expect(h.wrapAAD == hex(o["wrap_aad"]))
        #expect(h.metaAAD == hex(o["meta_aad"]))
        #expect(h.metaBlob == hex(o["meta_blob"]))
        let fk = try testVault.unwrapFK(h)
        let keys = FileKeys(fk: fk)
        #expect(keyBytes(fk) == hex(o["fk"]))
        #expect(keyBytes(keys.content) == hex(o["k_content"]))
        #expect(keyBytes(keys.meta) == hex(o["k_meta"]))
        #expect([UInt8](try h.openMetadataBytes(keys.meta)) == hex(o["meta_plaintext"]))
        let chunks = o["chunks"] as! [JSONObject]
        #expect(Int64(chunks.count) == h.layout.chunkCount)
        for c in chunks {
            let idx = Int64(c["index"] as! Int)
            #expect(chunkNonce(idx, final: c["final"] as! Bool) == hex(c["nonce"]))
            #expect((idx == h.layout.chunkCount - 1) == (c["final"] as! Bool))
            #expect(h.layout.storedLength(ofChunk: idx) == c["stored_len"] as! Int)
            let off = c["offset"] as! Int, len = c["stored_len"] as! Int
            #expect(file[(off + len - 16)..<(off + len)].elementsEqual(hex(c["tag"])))
        }
    }

    #if VALV_TESTVECTORS
    @Test(arguments: objects.indices)
    func reencryptsToIdenticalBytes(_ i: Int) throws {
        let o = ObjectTests.objects[i]
        let meta = storedMetadata(o["meta"] as! JSONObject)
        let out = DataOutput()
        let (id, source) = try TestHooks.withFixedRandom([
            .fileID: [hex(o["file_id"])],
            .fk: [hex(o["fk"])],
            .fkWrapNonce: [hex(o["wrap_nonce"])],
            .metaNonce: [hex(o["meta_nonce"])],
        ]) {
            try testVault.writeObject(plaintext: DataInput(vfile(o["plaintext_file"] as! String)),
                                      metadata: meta, to: out)
        }
        #expect(source.isExhausted)
        #expect(id.objectPath == o["path"] as! String)
        #expect(out.data == vfile(o["file"] as! String), "\(o["description"]!)")
    }
    #endif

    @Test func writerNormalizesNFDToNFC() throws {
        let nfdVector = ObjectTests.objects.first { $0["warn_non_nfc"] as? Bool == true }!
        let stored = storedMetadata(nfdVector["meta"] as! JSONObject)
        let written = try Metadata(nameUTF8: stored.nameUTF8, dirUTF8: stored.dirUTF8, mtime: stored.mtime,
                                   mimeUTF8: stored.mimeUTF8, rev: stored.rev)
        #expect(written.isNFC)
        #expect(written.nameUTF8 != stored.nameUTF8)
    }

    @Test func readsAreBoundedByOneChunk() throws {
        let o = ObjectTests.objects.first { ($0["plaintext_len"] as! Int) > 100_000 }!
        let input = CountingInput(vfile(o["file"] as! String))
        try testVault.verifyObject(input, expected: FileID(objectPath: o["path"] as! String))
        #expect(input.maxRead <= 65552)
    }

    @Test func shortReadsDoNotChangeOutput() throws {
        let o = ObjectTests.objects.first { ($0["plaintext_len"] as! Int) > 100_000 }!
        let out = DataOutput()
        try testVault.decryptObject(TrickleInput(vfile(o["file"] as! String)),
                                    expected: FileID(objectPath: o["path"] as! String), to: out)
        #expect(out.data == vfile(o["plaintext_file"] as! String))
    }

    @Test func objectGrowingAfterOpenIsRejected() throws {
        let o = ObjectTests.objects[0]
        final class Growing: ValvInput {
            let inner: DataInput, len: Int64
            init(_ d: Data) { inner = DataInput(d + Data([0])); len = Int64(d.count) }
            func read(upTo n: Int) throws -> Data { try inner.read(upTo: n) }
            func totalLength() throws -> Int64 { len }
        }
        #expect(errorClass {
            try testVault.verifyObject(Growing(vfile(o["file"] as! String)), expected: FileID(objectPath: o["path"] as! String))
        } == "malformed")
    }

    @Test func pathRules() {
        let id = "7c600a1cfb7fd7f124bf7bfc7df095f6"
        #expect((try? FileID(objectPath: "objects/7c/\(id).obj"))?.hex == id)
        #expect((try? FileID(objectPath: "/abs/vault/objects/7c/\(id).obj"))?.hex == id)
        for bad in ["objects/7d/\(id).obj", "objects/7c/\(id).inb", "objects/7c/\(id)x.obj",
                    "objects/7c/7C600a1cfb7fd7f124bf7bfc7df095f6.obj", "\(id).obj", "objects/7c/\(id.dropLast()).obj",
                    "objects/7c/\(id).obj.part", "7c/\(id).obj", "wrong/7c/\(id).obj", "/abs/vault/wrong/7c/\(id).obj",
                    "OBJECTS/7c/\(id).obj"] {
            #expect(errorClass { _ = try FileID(objectPath: bad) } == "path", "\(bad)")
        }
        #expect((try? FileID(inboxPath: "inbox/\(id).inb"))?.hex == id)
        #expect((try? FileID(inboxPath: "/abs/vault/inbox/\(id).inb"))?.hex == id)
        for badInb in ["inbox/\(id.uppercased()).inb", "inbox/\(id).obj", "\(id).inb",
                       "wrong/\(id).inb", "/abs/vault/wrong/\(id).inb", "INBOX/\(id).inb"] {
            #expect(errorClass { _ = try FileID(inboxPath: badInb) } == "path", "\(badInb)")
        }
    }

    @Test func structuralCheck() throws {
        for ok: Int64 in [16, 17, 65552, 65552 + 100, 65552 * 2, 65552 + 17] {
            #expect(throws: Never.self, "\(ok)") { _ = try ChunkLayout(ctTotal: ok) }
        }
        for bad: Int64 in [-1, 0, 15, 65552 + 1, 65552 + 15, 65552 + 16, 65552 * 3 + 16, Int64.max] {
            #expect(errorClass { _ = try ChunkLayout(ctTotal: bad) } == "malformed", "\(bad)")
        }
        let l = try ChunkLayout(ctTotal: 65552 * 3 + 17)
        #expect(l.chunkCount == 4 && l.plaintextLength == 65536 * 3 + 1)
    }
}
