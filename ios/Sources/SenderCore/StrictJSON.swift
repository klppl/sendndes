import Foundation

/// A strict reader for the one flat JSON object the QR payload uses: string and non-negative integer values,
/// no nesting, no duplicate keys, no escapes the writer does not need. JSONSerialization would silently keep
/// the last of two equal keys and accept unknown shapes, so the payload is read by hand.
enum StrictJSON {
    enum Value: Equatable { case string(String), int(Int) }

    struct Failure: Error, Equatable { let reason: String }

    static func parseFlatObject(_ data: [UInt8]) throws -> [String: Value] {
        var p = Reader(data)
        try p.expect(0x7B)  // {
        var out: [String: Value] = [:]
        if p.peek == 0x7D { throw Failure(reason: "empty object") }
        while true {
            let key = try p.string()
            try p.expect(0x3A)  // :
            let v: Value
            if p.peek == 0x22 {
                v = .string(try p.string())
            } else if let c = p.peek, c >= 0x30, c <= 0x39 {
                v = .int(try p.int())
            } else {
                throw Failure(reason: "unexpected value")
            }
            guard out.updateValue(v, forKey: key) == nil else { throw Failure(reason: "duplicate key") }
            if p.peek == 0x2C { p.i += 1; continue }
            try p.expect(0x7D)
            break
        }
        guard p.atEnd else { throw Failure(reason: "data after the object") }
        return out
    }

    private struct Reader {
        let s: [UInt8]
        var i = 0
        init(_ s: [UInt8]) { self.s = s }
        var atEnd: Bool { i == s.count }
        var peek: UInt8? { i < s.count ? s[i] : nil }

        mutating func expect(_ b: UInt8) throws {
            guard i < s.count, s[i] == b else { throw Failure(reason: "syntax") }
            i += 1
        }

        mutating func int() throws -> Int {
            let start = i
            var v = 0
            while i < s.count, s[i] >= 0x30, s[i] <= 0x39 {
                let (m, o1) = v.multipliedReportingOverflow(by: 10)
                let (r, o2) = m.addingReportingOverflow(Int(s[i] - 0x30))
                guard !o1, !o2, i - start < 9 else { throw Failure(reason: "number too large") }
                v = r; i += 1
            }
            if i - start > 1 && s[start] == 0x30 { throw Failure(reason: "leading zero") }
            if let c = peek, c == 0x2E || c == 0x65 || c == 0x45 { throw Failure(reason: "not an integer") }
            return v
        }

        /// A string with only the escapes \" and \\ ; control characters and any other escape are errors.
        mutating func string() throws -> String {
            try expect(0x22)
            var bytes = [UInt8]()
            while true {
                guard i < s.count else { throw Failure(reason: "unterminated string") }
                let b = s[i]
                if b == 0x22 { i += 1; break }
                if b < 0x20 { throw Failure(reason: "control character") }
                if b == 0x5C {
                    guard i + 1 < s.count, s[i + 1] == 0x22 || s[i + 1] == 0x5C else { throw Failure(reason: "escape") }
                    bytes.append(s[i + 1]); i += 2
                } else { bytes.append(b); i += 1 }
            }
            guard !bytes.contains(0), let str = String(bytes: bytes, encoding: .utf8) else {
                throw Failure(reason: "invalid UTF-8")
            }
            return str
        }
    }
}
