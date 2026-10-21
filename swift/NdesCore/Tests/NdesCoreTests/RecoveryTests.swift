import Foundation
import Testing
@testable import NdesCore

@Suite struct RecoveryTests {
    @Test func encodeMatchesVector() {
        #expect(testVault.recoveryKey == vaultVector["recovery_key"] as! String)
        #expect(RecoveryKey.checksum(testVault.vk) == hex(vaultVector["recovery_checksum"]))
        #expect(testVault.recoveryKey.count == 56 + 13)
    }

    @Test(arguments: (vectors["recovery_keys"] as! [JSONObject]).indices)
    func decodeVectors(_ i: Int) {
        let rk = (vectors["recovery_keys"] as! [JSONObject])[i]
        let input = rk["input"] as! String
        if let vk = rk["vk"] {
            #expect(throws: Never.self) {
                let v = try Vault(recoveryKey: input)
                #expect(v.exportVK() == hex(vk), "\(rk["description"]!)")
            }
        } else {
            let got = errorClass { _ = try Vault(recoveryKey: input) }
            #expect(got == rk["error"] as? String, "\(rk["description"]!)")
        }
    }

    // MARK: SPEC 4.3 recovery-key unlock

    func candidate(_ path: String, _ data: Data) -> RecoveryCandidate {
        RecoveryCandidate(path: path) { DataInput(data) }
    }

    var tiny: RecoveryCandidate {
        let o = (vectors["objects"] as! [JSONObject])[0]
        return candidate(o["path"] as! String, vfile(o["file"] as! String))
    }

    var inbox: RecoveryCandidate {
        let ib = (vectors["inbox"] as! [JSONObject])[0]
        return candidate(ib["path"] as! String, vfile(ib["file"] as! String))
    }

    @Test func recoveryUnlockSucceeds() throws {
        let v = try Vault.unlock(vaultJSON: vaultJSONBytes, recoveryKey: testVault.recoveryKey, sampleObject: tiny)
        #expect(v.exportVK() == testVault.exportVK())
    }

    @Test func recoveryUnlockReportsAlteredVaultJSON() throws {
        let altered = vfile("negative/vault_inbox_pub_mismatch.json")
        #expect(errorClass {
            _ = try Vault.unlock(vaultJSON: altered, recoveryKey: testVault.recoveryKey, sampleObject: tiny)
        } == "vault_json_altered")
        #expect(errorClass {
            _ = try Vault.unlock(vaultJSON: altered, recoveryKey: testVault.recoveryKey, sampleObject: nil)
        } == "wrong_recovery_key")
    }

    @Test func recoveryUnlockWithOtherKey() throws {
        let other = try Vault(vk: [UInt8](repeating: 7, count: 32))
        #expect(errorClass {
            _ = try Vault.unlock(vaultJSON: vaultJSONBytes, recoveryKey: other.recoveryKey, sampleObject: tiny)
        } == "wrong_recovery_key")
    }

    // MARK: SPEC 4.5 cases

    @Test func case1VerifiedWithCount() {
        let bad = candidate("objects/eb/eb43342ccc273a589b0a992cb6593a82.obj", vfile("negative/obj_flipped_wrapped_fk.obj"))
        let unreadable = candidate("objects/7c/7c600a1cfb7fd7f124bf7bfc7df095f6.obj", vfile("negative/obj_ct_zero.obj"))
        let r = testVault.verifyRecoveredKey(objects: [tiny, bad, unreadable], inboxFiles: [RecoveryCandidate]())
        #expect(r == .verified(unwrapping: 1, readable: 2))
    }

    @Test func case2VerifiedByInbox() {
        let bad = candidate("objects/eb/eb43342ccc273a589b0a992cb6593a82.obj", vfile("negative/obj_flipped_wrapped_fk.obj"))
        let r = testVault.verifyRecoveredKey(objects: [bad], inboxFiles: [inbox])
        #expect(r == .verifiedByInbox)
    }

    @Test func case3CannotBeVerified() throws {
        let other = try Vault(vk: [UInt8](repeating: 7, count: 32))
        #expect(other.verifyRecoveredKey(objects: [tiny], inboxFiles: [inbox]) == .cannotBeVerified(readable: 1))
        // Planted inbox files without K_auth do not verify a key either.
        let planted = candidate("inbox/958a27e63a79fba9e0206d76bc4b7cae.inb", vfile("negative/inb_no_k_auth.inb"))
        #expect(testVault.verifyRecoveredKey(objects: [RecoveryCandidate](), inboxFiles: [planted]) == .cannotBeVerified(readable: 0))
    }

    @Test func case4NothingToCheck() {
        #expect(testVault.verifyRecoveredKey(objects: [RecoveryCandidate](), inboxFiles: [RecoveryCandidate]()) == .nothingToCheck)
    }
}
