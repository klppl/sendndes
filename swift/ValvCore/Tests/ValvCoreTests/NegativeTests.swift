import Foundation
import Testing
@testable import ValvCore

@Suite struct NegativeTests {
    nonisolated(unsafe) static let cases = vectors["negative"] as! [JSONObject]

    @Test(arguments: cases.indices)
    func rejectedWithExpectedClass(_ i: Int) {
        let n = NegativeTests.cases[i]
        let name = n["name"] as! String
        let data = vfile(n["file"] as! String)
        let got: String?
        switch n["kind"] as! String {
        case "vault":
            got = errorClass { _ = try Vault.unlock(vaultJSON: data, passphrase: n["passphrase"] as! String) }
        case "object":
            got = errorClass {
                let id = try FileID(objectPath: n["path"] as! String)
                try testVault.verifyObject(DataInput(data), expected: id)
            }
        case "inbox":
            got = errorClass {
                let id = try FileID(inboxPath: n["path"] as! String)
                let r = try testVault.openInbox(DataInput(data), expected: id)
                try r.decryptAll(to: DiscardOutput())
            }
        default:
            got = "unknown kind"
        }
        #expect(got == n["expect"] as? String, "\(name): \(n["description"]!)")
    }

    /// Metadata negatives: check the plaintext the vector lists, too.
    @Test(arguments: cases.indices.filter { cases[$0]["meta_plaintext"] != nil })
    func metadataPlaintextRejected(_ i: Int) throws {
        let n = NegativeTests.cases[i]
        let pt = hex(n["meta_plaintext"])
        #expect(errorClass { _ = try Metadata.parse(padded: pt) } == "metadata", "\(n["name"]!)")
        // And the object's meta_blob really decrypts to it.
        let id = try FileID(objectPath: n["path"] as! String)
        let h = try FileHeader.read(DataInput(vfile(n["file"] as! String)), kind: .object, expected: id)
        let fk = try testVault.unwrapFK(h)
        #expect([UInt8](try h.openMetadataBytes(FileKeys(fk: fk).meta)) == pt)
    }

    /// The ingest path rejects the inbox negatives with the same class.
    @Test(arguments: cases.indices.filter { cases[$0]["kind"] as! String == "inbox" })
    func ingestRejects(_ i: Int) {
        let n = NegativeTests.cases[i]
        let got = errorClass {
            let id = try FileID(inboxPath: n["path"] as! String)
            try testVault.ingest(inbox: DataInput(vfile(n["file"] as! String)), expected: id, to: DiscardOutput())
        }
        #expect(got == n["expect"] as? String, "\(n["name"]!)")
    }
}
