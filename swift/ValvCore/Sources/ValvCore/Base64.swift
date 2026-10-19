// RFC 4648 standard-alphabet Base64 with padding, canonical only (SPEC 4.2).
// Hand-written so that non-canonical input (nonzero unused bits, missing or
// misplaced padding, whitespace) is rejected rather than silently accepted.

private let alphabet: [UInt8] = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)

private let decodeTable: [Int16] = {
    var t = [Int16](repeating: -1, count: 256)
    for (i, c) in alphabet.enumerated() { t[Int(c)] = Int16(i) }
    return t
}()

enum Base64 {
    static func encode(_ data: [UInt8]) -> String {
        var out = [UInt8]()
        out.reserveCapacity((data.count + 2) / 3 * 4)
        var i = 0
        while i + 3 <= data.count {
            let v = UInt32(data[i]) << 16 | UInt32(data[i + 1]) << 8 | UInt32(data[i + 2])
            out.append(alphabet[Int(v >> 18 & 63)])
            out.append(alphabet[Int(v >> 12 & 63)])
            out.append(alphabet[Int(v >> 6 & 63)])
            out.append(alphabet[Int(v & 63)])
            i += 3
        }
        let rest = data.count - i
        if rest == 1 {
            let v = UInt32(data[i]) << 16
            out.append(alphabet[Int(v >> 18 & 63)])
            out.append(alphabet[Int(v >> 12 & 63)])
            out.append(UInt8(ascii: "="))
            out.append(UInt8(ascii: "="))
        } else if rest == 2 {
            let v = UInt32(data[i]) << 16 | UInt32(data[i + 1]) << 8
            out.append(alphabet[Int(v >> 18 & 63)])
            out.append(alphabet[Int(v >> 12 & 63)])
            out.append(alphabet[Int(v >> 6 & 63)])
            out.append(UInt8(ascii: "="))
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Returns nil for anything that is not canonical padded Base64.
    static func decodeCanonical(_ c: [UInt8]) -> [UInt8]? {
        guard c.count % 4 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(c.count / 4 * 3)
        var i = 0
        while i < c.count {
            let last = i + 4 == c.count
            var vals = [UInt32](repeating: 0, count: 4)
            var pad = 0
            for k in 0..<4 {
                let ch = c[i + k]
                if ch == UInt8(ascii: "=") {
                    // Padding only in the last group, only in positions 2 and 3,
                    // and once it starts it continues to the end.
                    guard last, k >= 2 else { return nil }
                    pad += 1
                } else {
                    guard pad == 0 else { return nil }
                    let d = decodeTable[Int(ch)]
                    guard d >= 0 else { return nil }
                    vals[k] = UInt32(d)
                }
            }
            let v = vals[0] << 18 | vals[1] << 12 | vals[2] << 6 | vals[3]
            out.append(UInt8(truncatingIfNeeded: v >> 16))
            if pad < 2 { out.append(UInt8(truncatingIfNeeded: v >> 8)) }
            if pad < 1 { out.append(UInt8(truncatingIfNeeded: v)) }
            // Unused trailing bits must be zero.
            if pad == 1 && (v & 0xFF) != 0 { return nil }
            if pad == 2 && (v & 0xFFFF) != 0 { return nil }
            i += 4
        }
        return out
    }
}
