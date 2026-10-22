import Foundation
import Testing
@testable import NdesCore

@Suite struct RoundTripTests {
    static let sizes = [0, 1, 65535, 65536, 65537, 3 * 65536 + 1]

    func meta(_ n: Int) throws -> Metadata {
        try Metadata(name: "file-\(n).bin", dir: "Round/Trip", mtime: Int64.max - 1, mime: "application/octet-stream", rev: 1, size: Int64(n))
    }

    func expectedLength(_ n: Int) -> Int {
        let padded = Int(paddedSize(Int64(n)))
        return 86 + 540 + padded + 16 * ((padded + 65535) / 65536)
    }

    @Test(arguments: sizes)
    func plainRoundTrip(_ n: Int) throws {
        let plain = pattern(n, seed: UInt8(n % 251))
        let obj = DataOutput()
        let id = try testVault.writeObject(plaintext: DataInput(plain), metadata: meta(n), to: obj)
        #expect(obj.data.count == expectedLength(n))
        let expected = try FileID(objectPath: id.objectPath)
        let out = DataOutput()
        let reader = try testVault.openObject(DataInput(obj.data), expected: expected)
        #expect(reader.plaintextLength == Int64(n))
        #expect(reader.metadata == (try meta(n)))
        try reader.decryptAll(to: out)
        #expect(out.data == plain)
    }

    @Test(arguments: sizes)
    func sealIngestRoundTrip(_ n: Int) throws {
        let plain = pattern(n, seed: 99)
        let inb = DataOutput()
        let id = try testVault.makeInboxSealer().seal(plaintext: TrickleInput(plain), metadata: meta(n), to: inb)
        let inboxID = try FileID(inboxPath: id.inboxPath)

        let direct = DataOutput()
        try testVault.openInbox(DataInput(inb.data), expected: inboxID).decryptAll(to: direct)
        #expect(direct.data == plain)

        let obj = DataOutput()
        try testVault.ingest(inbox: DataInput(inb.data), expected: inboxID, to: obj)
        let objID = try FileID(objectPath: id.objectPath)
        let out = DataOutput()
        #expect(try testVault.decryptObject(DataInput(obj.data), expected: objID, to: out) == (try meta(n)))
        #expect(out.data == plain)
        #expect(try testVault.compareIngested(inbox: DataInput(inb.data), existingObject: DataInput(obj.data),
                                              expected: inboxID) == .alreadyIngested)
    }

    @Test func freshRandomnessEveryWrite() throws {
        #expect(Random.bytes(0, for: .vk).isEmpty)
        let a = DataOutput(), b = DataOutput()
        let m = try meta(1)
        let ia = try testVault.writeObject(plaintext: DataInput(Data([1])), metadata: m, to: a)
        let ib = try testVault.writeObject(plaintext: DataInput(Data([1])), metadata: m, to: b)
        #expect(ia != ib)
        #expect(a.data.dropFirst(22).prefix(12) != b.data.dropFirst(22).prefix(12))
    }

    @Test func inboxSealRequiresRev1() throws {
        let m = try Metadata(name: "x", dir: "", mtime: 0, mime: "", rev: 2, size: 0)
        #expect(errorClass { _ = try testVault.makeInboxSealer().seal(plaintext: DataInput(Data()), metadata: m, to: DiscardOutput()) } == "metadata")
    }

    @Test func wrongExpectedIDIsPathError() throws {
        let obj = DataOutput()
        _ = try testVault.writeObject(plaintext: DataInput(Data([1, 2, 3])), metadata: meta(3), to: obj)
        let other = try FileID(objectPath: "objects/00/00000000000000000000000000000000.obj")
        #expect(errorClass { try testVault.verifyObject(DataInput(obj.data), expected: other) } == "path")
    }

    @Test func vaultFromAnotherVKCannotRead() throws {
        let obj = DataOutput()
        let id = try testVault.writeObject(plaintext: DataInput(Data([1])), metadata: meta(1), to: obj)
        let other = try Vault(vk: [UInt8](repeating: 9, count: 32))
        #expect(errorClass { try other.verifyObject(DataInput(obj.data), expected: id) } == "auth")
    }

    @Test func contentSizeMustMatchMetadata() throws {
        for (declared, actual) in [(10, 9), (10, 11), (0, 1), (65541, 65540), (5, 5 + 65536)] {
            let out = DataOutput()
            #expect(errorClass {
                _ = try testVault.writeObject(plaintext: DataInput(pattern(actual)), metadata: meta(declared), to: out)
            } == "io", "declared \(declared), actual \(actual)")
        }
    }

    /// A file whose stored length is not a padded size, whose metadata size is in another
    /// bucket, or whose padding is not zero is malformed (SPEC 5.3).
    @Test func paddingRules() throws {
        let valid = DataOutput()
        let id = try testVault.writeObject(plaintext: DataInput(pattern(100)), metadata: meta(100), to: valid)
        let expected = try FileID(objectPath: id.objectPath)
        #expect(valid.data.count == 86 + 540 + 4096 + 16)
        func decrypt(_ d: Data) -> String? {
            errorClass { _ = try testVault.decryptObject(DataInput(d), expected: expected, to: DiscardOutput()) }
        }
        #expect(decrypt(valid.data) == nil)
        // Truncating makes the stored length (4090) not a padded size.
        #expect(decrypt(valid.data.dropLast(6)) == "malformed")
        // A longer metadata size in the same file: 5000 pads to 5120, the file stores 4096.
        let header = try FileHeader.read(DataInput(valid.data), kind: .object, expected: expected)
        var fk = try testVault.unwrapFK(header)
        let keys = FileKeys(fk: fk)
        fk = keys.fk
        let blob = try sealMetadata(meta(5000), key: keys.meta, fileID: expected)
        var bad = [UInt8](valid.data)
        bad.replaceSubrange(86..<(86 + blob.count), with: blob)
        #expect(decrypt(Data(bad)) == "malformed")
        // A non-zero byte in the padding: seal the chunk by hand.
        var stored = [UInt8](repeating: 0, count: 4096)
        stored[4000] = 1
        var forged = [UInt8](valid.data.prefix(86 + 540))
        forged += AEAD.seal(stored, key: keys.content, nonce: chunkNonce(0, final: true), aad: expected.bytes)
        #expect(decrypt(Data(forged)) == "malformed")
    }
}
