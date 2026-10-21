import CryptoKit
import Foundation
@testable import NdesCore

/// testvectors/ at the repository root, found relative to this file.
let vectorsDir: URL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // NdesCoreTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // NdesCore
    .deletingLastPathComponent()  // swift
    .deletingLastPathComponent()  // repo root
    .appendingPathComponent("testvectors")

typealias JSONObject = [String: Any]

nonisolated(unsafe) let vectors: JSONObject = {
    let data = try! Data(contentsOf: vectorsDir.appendingPathComponent("vectors.json"))
    return try! JSONSerialization.jsonObject(with: data) as! JSONObject
}()

func vfile(_ rel: String) -> Data {
    try! Data(contentsOf: vectorsDir.appendingPathComponent(rel))
}

func hex(_ s: Any?) -> [UInt8] {
    let str = s as! String
    return hexDecodeLowercase(Array(str.utf8))!
}

func i64(_ s: Any?) -> Int64 {
    Int64(s as! String)!
}

var vaultVector: JSONObject { vectors["vault"] as! JSONObject }
var vaultJSONBytes: Data { vfile("vault/vault.json") }
var passphrase: String { vaultVector["passphrase"] as! String }

/// The test vault, from VK (no Argon2), checked against vault.json.
let testVault: Vault = try! Vault(vk: hex(vaultVector["vk"]), vaultJSON: vfile("vault/vault.json"))

/// Metadata exactly as stored by the vector (bypasses the writer's NFC step,
/// for the NFD vector written "by another writer").
func storedMetadata(_ m: JSONObject) -> Metadata {
    Metadata(unchecked: hex(m["name_hex"]), hex(m["dir_hex"]), i64(m["mtime"]), hex(m["mime_hex"]), i64(m["rev"]))
}

func errorClass(_ body: () throws -> Void) -> String? {
    do {
        try body()
        return nil
    } catch let e as NdesError {
        return e.vectorClass
    } catch {
        return "unexpected: \(error)"
    }
}

func sha256hex(_ d: Data) -> String {
    hexEncode(SHA256.hash(data: d))
}

/// Deterministic pseudo-random plaintext of a given size.
func pattern(_ n: Int, seed: UInt8 = 1) -> Data {
    var d = Data(count: n)
    var x = UInt32(seed) &* 2654435761
    for i in 0..<n {
        x = x &* 1103515245 &+ 12345
        d[i] = UInt8(truncatingIfNeeded: x >> 16)
    }
    return d
}

/// An input that records the largest single read, to check streaming.
final class CountingInput: NdesInput {
    private let inner: DataInput
    private(set) var maxRead = 0
    init(_ d: Data) { inner = DataInput(d) }
    func read(upTo count: Int) throws -> Data {
        maxRead = max(maxRead, count)
        return try inner.read(upTo: count)
    }
    func totalLength() throws -> Int64 { try inner.totalLength() }
}

/// An input that returns at most 7 bytes per read, like a slow pipe.
final class TrickleInput: NdesInput {
    private let inner: DataInput
    init(_ d: Data) { inner = DataInput(d) }
    func read(upTo count: Int) throws -> Data { try inner.read(upTo: min(count, 7)) }
    func totalLength() throws -> Int64 { try inner.totalLength() }
}
