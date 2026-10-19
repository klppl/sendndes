import Foundation
import Testing
@testable import ValvCore

@Suite struct RoundTripTests {
    static let sizes = [0, 1, 65535, 65536, 65537, 3 * 65536 + 1]

    func meta(_ n: Int) throws -> Metadata {
        try Metadata(name: "file-\(n).bin", dir: "Round/Trip", mtime: Int64.max - 1, mime: "application/octet-stream", rev: 1)
    }

    func expectedLength(_ n: Int) -> Int {
        let chunks = max(1, (n + 65535) / 65536)
        return 86 + 540 + n + 16 * chunks
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
        let m = try Metadata(name: "x", dir: "", mtime: 0, mime: "", rev: 2)
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
}
