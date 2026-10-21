import Foundation

/// A parsed and fully checked vault.json (SPEC 4.2). Public values only.
public struct VaultConfig: Equatable, Sendable {
    public static let maxFileSize = 4096

    let salt: [UInt8]       // 16
    let wrappedVK: [UInt8]  // nonce 12 | ct 32 | tag 16
    public let inboxPublicKey: [UInt8]  // 32

    init(salt: [UInt8], wrappedVK: [UInt8], inboxPublicKey: [UInt8]) {
        precondition(salt.count == 16 && wrappedVK.count == 60 && inboxPublicKey.count == 32)
        self.salt = salt
        self.wrappedVK = wrappedVK
        self.inboxPublicKey = inboxPublicKey
    }

    /// The exact writer format: LF line endings, two-space indent, `kdf` on
    /// one line, one trailing LF.
    public func serialized() -> Data {
        var s = "{\n"
        s += "  \"v\": 1,\n"
        s += "  \"kdf\": { \"alg\": \"\(KDFParams.alg)\", \"salt\": \"\(Base64.encode(salt))\", "
        s += "\"t\": \(KDFParams.t), \"m_kib\": \(KDFParams.mKiB), \"p\": \(KDFParams.p) },\n"
        s += "  \"wrapped_vk\": \"\(Base64.encode(wrappedVK))\",\n"
        s += "  \"inbox_pub\": \"\(Base64.encode(inboxPublicKey))\"\n"
        s += "}\n"
        return Data(s.utf8)
    }

    /// The 83-byte AAD of `wrapped_vk`.
    var configAAD: [UInt8] {
        var a = Label.configAAD
        let alg = Array(KDFParams.alg.utf8)
        a.append(UInt8(alg.count))
        a.append(contentsOf: alg)
        a.append(contentsOf: salt)
        a.appendU32BE(KDFParams.t)
        a.appendU32BE(KDFParams.mKiB)
        a.appendU32BE(KDFParams.p)
        a.append(contentsOf: inboxPublicKey)
        return a
    }

    /// Strict parse: size cap, exact keys, `v` and KDF parameters, canonical
    /// Base64 with exact lengths, then re-serialize and compare bytes.
    public static func parse<D: DataProtocol>(_ data: D) throws -> VaultConfig {
        guard data.count <= maxFileSize else {
            throw NdesError.malformed("vault.json is larger than \(maxFileSize) bytes")
        }
        let raw = [UInt8](data)
        var p = MiniJSON(raw)
        let root = try p.parseDocument()

        guard case .object(let top) = root else { throw NdesError.malformed("vault.json: not an object") }
        try requireKeys(top, ["v", "kdf", "wrapped_vk", "inbox_pub"], what: "vault.json")

        guard case .int(let v) = top[0].1 else { throw NdesError.malformed("vault.json: v is not an integer") }
        guard v == 1 else { throw NdesError.unsupported("vault.json version \(v)") }

        guard case .object(let kdf) = top[1].1 else { throw NdesError.malformed("vault.json: kdf is not an object") }
        try requireKeys(kdf, ["alg", "salt", "t", "m_kib", "p"], what: "kdf")
        guard case .string(let alg) = kdf[0].1 else { throw NdesError.malformed("kdf.alg is not a string") }
        guard case .string(let saltB64) = kdf[1].1 else { throw NdesError.malformed("kdf.salt is not a string") }
        guard case .int(let t) = kdf[2].1, case .int(let m) = kdf[3].1, case .int(let par) = kdf[4].1 else {
            throw NdesError.malformed("kdf parameters are not integers")
        }
        guard alg == Array(KDFParams.alg.utf8) else { throw NdesError.unsupported("KDF algorithm") }
        guard t == Int64(KDFParams.t), m == Int64(KDFParams.mKiB), par == Int64(KDFParams.p) else {
            throw NdesError.unsupported("KDF parameters")
        }

        guard case .string(let wvkB64) = top[2].1 else { throw NdesError.malformed("wrapped_vk is not a string") }
        guard case .string(let pubB64) = top[3].1 else { throw NdesError.malformed("inbox_pub is not a string") }

        func b64(_ s: [UInt8], _ len: Int, _ what: String) throws -> [UInt8] {
            guard let d = Base64.decodeCanonical(s), d.count == len else {
                throw NdesError.malformed("\(what): not canonical base64 of \(len) bytes")
            }
            return d
        }
        let salt = try b64(saltB64, 16, "kdf.salt")
        let wvk = try b64(wvkB64, 60, "wrapped_vk")
        let pub = try b64(pubB64, 32, "inbox_pub")

        let cfg = VaultConfig(salt: salt, wrappedVK: wvk, inboxPublicKey: pub)
        guard constantTimeEqual([UInt8](cfg.serialized()), raw) else {
            throw NdesError.malformed("vault.json is not in the canonical writer format")
        }
        return cfg
    }

    private static func requireKeys(_ obj: [([UInt8], MiniJSON.Value)], _ keys: [String], what: String) throws {
        guard obj.count == keys.count,
              zip(obj, keys).allSatisfy({ $0.0 == Array($1.utf8) }) else {
            throw NdesError.malformed("\(what): wrong, missing, duplicate or unknown keys")
        }
    }
}

/// A tiny JSON reader for vault.json only: objects, strings without escapes
/// and integers. Anything else is malformed. Canonical form is enforced
/// afterwards by re-serializing, so this reader may accept extra whitespace.
struct MiniJSON {
    indirect enum Value {
        case object([([UInt8], Value)])
        case string([UInt8])
        case int(Int64)
    }

    private let s: [UInt8]
    private var i = 0
    private var depth = 0

    init(_ s: [UInt8]) { self.s = s }

    mutating func parseDocument() throws -> Value {
        let v = try value()
        skipWS()
        guard i == s.count else { throw NdesError.malformed("vault.json: trailing data") }
        return v
    }

    private mutating func skipWS() {
        while i < s.count, [0x20, 0x0A, 0x0D, 0x09].contains(s[i]) { i += 1 }
    }

    private mutating func expect(_ c: UInt8) throws {
        skipWS()
        guard i < s.count, s[i] == c else { throw NdesError.malformed("vault.json: syntax") }
        i += 1
    }

    private mutating func value() throws -> Value {
        skipWS()
        guard i < s.count else { throw NdesError.malformed("vault.json: unexpected end") }
        switch s[i] {
        case UInt8(ascii: "{"): return try object()
        case UInt8(ascii: "\""): return .string(try string())
        case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): return .int(try integer())
        default: throw NdesError.malformed("vault.json: unsupported value")
        }
    }

    private mutating func object() throws -> Value {
        depth += 1
        guard depth <= 4 else { throw NdesError.malformed("vault.json: nesting") }
        try expect(UInt8(ascii: "{"))
        var members: [([UInt8], Value)] = []
        skipWS()
        if i < s.count, s[i] == UInt8(ascii: "}") {
            i += 1
            depth -= 1
            return .object(members)
        }
        while true {
            skipWS()
            let k = try string()
            try expect(UInt8(ascii: ":"))
            let v = try value()
            members.append((k, v))
            skipWS()
            guard i < s.count else { throw NdesError.malformed("vault.json: unexpected end") }
            if s[i] == UInt8(ascii: ",") { i += 1; continue }
            if s[i] == UInt8(ascii: "}") { i += 1; break }
            throw NdesError.malformed("vault.json: syntax")
        }
        depth -= 1
        return .object(members)
    }

    private mutating func string() throws -> [UInt8] {
        guard i < s.count, s[i] == UInt8(ascii: "\"") else { throw NdesError.malformed("vault.json: expected string") }
        i += 1
        let start = i
        while i < s.count, s[i] != UInt8(ascii: "\"") {
            // No value in vault.json needs an escape or a control character.
            guard s[i] != UInt8(ascii: "\\"), s[i] >= 0x20 else {
                throw NdesError.malformed("vault.json: escape or control character in string")
            }
            i += 1
        }
        guard i < s.count else { throw NdesError.malformed("vault.json: unterminated string") }
        let out = s.copy(from: start, count: i - start)
        i += 1
        return out
    }

    private mutating func integer() throws -> Int64 {
        var neg = false
        if s[i] == UInt8(ascii: "-") { neg = true; i += 1 }
        let start = i
        var v: Int64 = 0
        while i < s.count, s[i] >= UInt8(ascii: "0"), s[i] <= UInt8(ascii: "9") {
            let d = Int64(s[i] - UInt8(ascii: "0"))
            let (m, o1) = v.multipliedReportingOverflow(by: 10)
            let (r, o2) = neg ? m.subtractingReportingOverflow(d) : m.addingReportingOverflow(d)
            guard !o1, !o2 else { throw NdesError.malformed("vault.json: integer overflow") }
            v = r
            i += 1
        }
        guard i > start else { throw NdesError.malformed("vault.json: bad number") }
        if i < s.count, [UInt8(ascii: "."), UInt8(ascii: "e"), UInt8(ascii: "E")].contains(s[i]) {
            throw NdesError.malformed("vault.json: non-integer number")
        }
        return v
    }
}
