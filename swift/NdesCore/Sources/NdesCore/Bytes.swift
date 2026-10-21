import Foundation

// Small byte helpers. Parsing code works on [UInt8], whose indices always
// start at 0, so a Data slice's original indices can never leak into offsets.

/// Constant-time equality for secrets and tags. Lengths are not secret.
@inline(never)
func constantTimeEqual<A: ContiguousBytes, B: ContiguousBytes>(_ a: A, _ b: B) -> Bool {
    a.withUnsafeBytes { pa in
        b.withUnsafeBytes { pb in
            guard pa.count == pb.count else { return false }
            var diff: UInt8 = 0
            for i in 0..<pa.count {
                diff |= pa[i] ^ pb[i]
            }
            return diff == 0
        }
    }
}

/// Overwrites the buffer with zeros in a way the optimizer may not remove.
/// This only clears this buffer; copies made earlier (copy-on-write, CryptoKit
/// internals, String storage) are out of reach. See README.md.
func wipe(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { p in
        if let base = p.baseAddress, p.count > 0 {
            _ = memset_s(base, p.count, 0, p.count)
        }
    }
}

func wipe(_ data: inout Data) {
    data.withUnsafeMutableBytes { (p: UnsafeMutableRawBufferPointer) in
        if let base = p.baseAddress, p.count > 0 {
            _ = memset_s(base, p.count, 0, p.count)
        }
    }
}

/// Copies any byte collection into a fresh, zero-based array.
@inline(__always)
func bytes<D: DataProtocol>(_ d: D) -> [UInt8] {
    [UInt8](d)
}

extension Array where Element == UInt8 {
    mutating func appendU32BE(_ v: UInt32) {
        append(UInt8(truncatingIfNeeded: v >> 24))
        append(UInt8(truncatingIfNeeded: v >> 16))
        append(UInt8(truncatingIfNeeded: v >> 8))
        append(UInt8(truncatingIfNeeded: v))
    }

    mutating func appendU64BE(_ v: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            append(UInt8(truncatingIfNeeded: v >> UInt64(shift)))
        }
    }

    func readU32BE(at offset: Int) -> UInt32 {
        precondition(offset >= 0 && offset + 4 <= count)
        return UInt32(self[offset]) << 24 | UInt32(self[offset + 1]) << 16
            | UInt32(self[offset + 2]) << 8 | UInt32(self[offset + 3])
    }

    /// A zero-based copy of `count` bytes starting at `offset`.
    func copy(from offset: Int, count n: Int) -> [UInt8] {
        precondition(offset >= 0 && n >= 0 && offset <= count - n)
        return [UInt8](self[offset..<(offset + n)])
    }
}

// MARK: - Checked arithmetic

/// Every length and offset computed from file data goes through these, so an
/// overflow is a reported error rather than a trap or a wrap-around.
func checkedAdd(_ a: Int64, _ b: Int64) throws -> Int64 {
    let (r, o) = a.addingReportingOverflow(b)
    if o { throw NdesError.malformed("length overflow") }
    return r
}

func checkedSub(_ a: Int64, _ b: Int64) throws -> Int64 {
    let (r, o) = a.subtractingReportingOverflow(b)
    if o { throw NdesError.malformed("length overflow") }
    return r
}

func checkedMul(_ a: Int64, _ b: Int64) throws -> Int64 {
    let (r, o) = a.multipliedReportingOverflow(by: b)
    if o { throw NdesError.malformed("length overflow") }
    return r
}

// MARK: - Hex

private let hexDigits: [UInt8] = Array("0123456789abcdef".utf8)

func hexEncode<D: Sequence>(_ data: D) -> String where D.Element == UInt8 {
    var out = [UInt8]()
    for b in data {
        out.append(hexDigits[Int(b >> 4)])
        out.append(hexDigits[Int(b & 0x0f)])
    }
    return String(decoding: out, as: UTF8.self)
}

/// Decodes lowercase hex only. Uppercase or any other character returns nil.
func hexDecodeLowercase<S: Sequence>(_ s: S) -> [UInt8]? where S.Element == UInt8 {
    let chars = [UInt8](s)
    guard chars.count % 2 == 0 else { return nil }
    func val(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        default: return nil
        }
    }
    var out = [UInt8]()
    out.reserveCapacity(chars.count / 2)
    var i = 0
    while i < chars.count {
        guard let hi = val(chars[i]), let lo = val(chars[i + 1]) else { return nil }
        out.append(hi << 4 | lo)
        i += 2
    }
    return out
}

// MARK: - UTF-8

/// Strict UTF-8 validation (RFC 3629): no overlong forms, no surrogates,
/// nothing above U+10FFFF.
func isValidUTF8(_ s: [UInt8]) -> Bool {
    var i = 0
    let n = s.count
    while i < n {
        let b0 = s[i]
        if b0 < 0x80 {
            i += 1
            continue
        }
        var need = 0
        var lo: UInt8 = 0x80
        var hi: UInt8 = 0xBF
        switch b0 {
        case 0xC2...0xDF: need = 1
        case 0xE0: need = 2; lo = 0xA0
        case 0xE1...0xEC, 0xEE...0xEF: need = 2
        case 0xED: need = 2; hi = 0x9F
        case 0xF0: need = 3; lo = 0x90
        case 0xF1...0xF3: need = 3
        case 0xF4: need = 3; hi = 0x8F
        default: return false
        }
        // Continuation bytes are at i+1 ... i+need.
        guard i + need < n else { return false }
        let b1 = s[i + 1]
        guard b1 >= lo && b1 <= hi else { return false }
        var k = 2
        while k <= need {
            let b = s[i + k]
            guard b >= 0x80 && b <= 0xBF else { return false }
            k += 1
        }
        i += need + 1
    }
    return true
}
