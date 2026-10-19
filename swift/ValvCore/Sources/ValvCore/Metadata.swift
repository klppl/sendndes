import Foundation

/// Per-file metadata (SPEC 5.2). Strings are kept as their UTF-8 bytes:
/// Swift's String equality and Character-based searching follow canonical
/// equivalence and grapheme clusters, which must never decide a byte-level
/// format rule (for example, "/" followed by a combining mark is one Character
/// that is not equal to "/").
public struct Metadata: Equatable, Sendable {
    public static let paddingBlock = 512
    public static let maxPaddedSize = 65536

    public let nameUTF8: [UInt8]
    public let dirUTF8: [UInt8]
    public let mtime: Int64  // Unix time in nanoseconds; any Int64
    public let mimeUTF8: [UInt8]
    public let rev: Int64    // >= 1

    public var name: String { String(decoding: nameUTF8, as: UTF8.self) }
    public var dir: String { String(decoding: dirUTF8, as: UTF8.self) }
    public var mime: String { String(decoding: mimeUTF8, as: UTF8.self) }

    /// Writer: normalizes `name` and `dir` to NFC, then checks the field rules.
    public init(name: String, dir: String, mtime: Int64, mime: String, rev: Int64) throws {
        try self.init(nameUTF8: Array(name.utf8), dirUTF8: Array(dir.utf8), mtime: mtime,
                      mimeUTF8: Array(mime.utf8), rev: rev)
    }

    /// Writer from raw bytes: checks valid UTF-8, normalizes `name` and `dir`
    /// to NFC, then checks the field rules.
    public init<N: Sequence, D: Sequence, M: Sequence>(nameUTF8: N, dirUTF8: D, mtime: Int64, mimeUTF8: M, rev: Int64) throws
    where N.Element == UInt8, D.Element == UInt8, M.Element == UInt8 {
        let n = [UInt8](nameUTF8), d = [UInt8](dirUTF8), m = [UInt8](mimeUTF8)
        guard isValidUTF8(n), isValidUTF8(d), isValidUTF8(m) else {
            throw ValvError.metadata("strings must be valid UTF-8")
        }
        self.init(unchecked: Metadata.nfc(n), Metadata.nfc(d), mtime, m, rev)
        try checkFieldRules()
    }

    init(unchecked name: [UInt8], _ dir: [UInt8], _ mtime: Int64, _ mime: [UInt8], _ rev: Int64) {
        self.nameUTF8 = name
        self.dirUTF8 = dir
        self.mtime = mtime
        self.mimeUTF8 = mime
        self.rev = rev
    }

    static func nfc(_ s: [UInt8]) -> [UInt8] {
        Array(String(decoding: s, as: UTF8.self).precomposedStringWithCanonicalMapping.utf8)
    }

    /// Whether `name` and `dir` are already NFC. Readers accept non-NFC
    /// metadata; tools may warn about it (SPEC 5.2 step 5).
    public var isNFC: Bool {
        Metadata.nfc(nameUTF8) == nameUTF8 && Metadata.nfc(dirUTF8) == dirUTF8
    }

    /// The same metadata with `rev` incremented, for a rewrite.
    public func nextRevision() throws -> Metadata {
        let (r, o) = rev.addingReportingOverflow(1)
        guard !o else { throw ValvError.metadata("rev overflow") }
        return Metadata(unchecked: nameUTF8, dirUTF8, mtime, mimeUTF8, r)
    }

    // MARK: Field rules

    private static func isValidComponent(_ c: ArraySlice<UInt8>) -> Bool {
        if c.isEmpty { return false }
        if c.elementsEqual([0x2E]) || c.elementsEqual([0x2E, 0x2E]) { return false }  // "." and ".."
        return !c.contains(0x2F) && !c.contains(0x00)
    }

    func checkFieldRules() throws {
        guard Metadata.isValidComponent(nameUTF8[...]) else {
            throw ValvError.metadata("name must be non-empty, not . or .., without / or NUL")
        }
        if !dirUTF8.isEmpty {
            for comp in dirUTF8.split(separator: 0x2F, omittingEmptySubsequences: false) {
                guard Metadata.isValidComponent(comp) else {
                    throw ValvError.metadata("every dir component must follow the name rules")
                }
            }
        }
        guard rev >= 1 else { throw ValvError.metadata("rev must be at least 1") }
    }

    // MARK: Canonical serialization

    /// `{"name":S,"dir":S,"mtime":I,"mime":S,"rev":I}` without padding.
    public func canonicalJSON() -> [UInt8] {
        var o = [UInt8]()
        o.reserveCapacity(64 + nameUTF8.count + dirUTF8.count + mimeUTF8.count)
        o += Array(#"{"name":"#.utf8); Metadata.appendString(nameUTF8, to: &o)
        o += Array(#","dir":"#.utf8); Metadata.appendString(dirUTF8, to: &o)
        o += Array(#","mtime":"#.utf8); o += Array(String(mtime).utf8)
        o += Array(#","mime":"#.utf8); Metadata.appendString(mimeUTF8, to: &o)
        o += Array(#","rev":"#.utf8); o += Array(String(rev).utf8)
        o.append(UInt8(ascii: "}"))
        return o
    }

    private static let lowerHex: [UInt8] = Array("0123456789abcdef".utf8)

    private static func appendString(_ s: [UInt8], to o: inout [UInt8]) {
        o.append(0x22)
        for b in s {
            switch b {
            case 0x22: o += [0x5C, 0x22]          // \"
            case 0x5C: o += [0x5C, 0x5C]          // \\
            case 0x00...0x1F:                     // \u00xx, lowercase hex
                o += [0x5C, UInt8(ascii: "u"), UInt8(ascii: "0"), UInt8(ascii: "0"),
                      lowerHex[Int(b >> 4)], lowerHex[Int(b & 0x0F)]]
            default: o.append(b)
            }
        }
        o.append(0x22)
    }

    /// Canonical JSON padded with spaces to the next multiple of 512 (minimal
    /// padding). A writer fails if the result would exceed 65536 bytes.
    public func paddedPlaintext() throws -> [UInt8] {
        try checkFieldRules()
        var o = canonicalJSON()
        let rem = o.count % Metadata.paddingBlock
        if rem != 0 { o += [UInt8](repeating: 0x20, count: Metadata.paddingBlock - rem) }
        guard o.count <= Metadata.maxPaddedSize else {
            throw ValvError.metadata("padded metadata would exceed \(Metadata.maxPaddedSize) bytes")
        }
        return o
    }

    // MARK: Strict reader (SPEC 5.2 steps 2 to 6)

    /// Parses decrypted, padded metadata. Accepts only the canonical form.
    public static func parse<D: DataProtocol>(padded d: D) throws -> Metadata {
        let p = [UInt8](d)
        guard !p.isEmpty, p.count % paddingBlock == 0, p.count <= maxPaddedSize else {
            throw ValvError.metadata("padded length must be a positive multiple of 512, at most 65536")
        }
        var end = p.count
        while end > 0 && p[end - 1] == 0x20 { end -= 1 }
        guard p.count - end < paddingBlock else { throw ValvError.metadata("padding is not minimal") }
        let json = p.copy(from: 0, count: end)
        guard isValidUTF8(json) else { throw ValvError.metadata("not valid UTF-8") }

        var r = StrictReader(json)
        try r.literal(#"{"name":"#)
        let name = try r.string()
        try r.literal(#","dir":"#)
        let dir = try r.string()
        try r.literal(#","mtime":"#)
        let mtime = try r.int64()
        try r.literal(#","mime":"#)
        let mime = try r.string()
        try r.literal(#","rev":"#)
        let rev = try r.int64()
        try r.literal("}")
        guard r.atEnd else { throw ValvError.metadata("data after the object") }

        let m = Metadata(unchecked: name, dir, mtime, mime, rev)
        try m.checkFieldRules()  // no NFC check on read
        guard m.canonicalJSON() == json else { throw ValvError.metadata("not in canonical form") }
        return m
    }
}

/// Reads exactly the canonical schema. Any key name, order, whitespace,
/// escape or number form the writer does not produce is an error.
private struct StrictReader {
    let s: [UInt8]
    var i = 0

    init(_ s: [UInt8]) { self.s = s }

    var atEnd: Bool { i == s.count }

    mutating func literal(_ lit: String) throws {
        let l = Array(lit.utf8)
        guard s.count - i >= l.count, s[i..<(i + l.count)].elementsEqual(l) else {
            throw ValvError.metadata("unexpected key, key order, whitespace or structure")
        }
        i += l.count
    }

    mutating func string() throws -> [UInt8] {
        guard i < s.count, s[i] == 0x22 else { throw ValvError.metadata("expected a string") }
        i += 1
        var out = [UInt8]()
        while true {
            guard i < s.count else { throw ValvError.metadata("unterminated string") }
            let b = s[i]
            if b == 0x22 { i += 1; return out }
            if b < 0x20 { throw ValvError.metadata("unescaped control character") }
            if b != 0x5C { out.append(b); i += 1; continue }
            guard i + 1 < s.count else { throw ValvError.metadata("unterminated escape") }
            switch s[i + 1] {
            case 0x22: out.append(0x22); i += 2
            case 0x5C: out.append(0x5C); i += 2
            case UInt8(ascii: "u"):
                // Only \u0000 to \u001f with lowercase hex.
                guard i + 5 < s.count, s[i + 2] == UInt8(ascii: "0"), s[i + 3] == UInt8(ascii: "0"),
                      let hex = hexDecodeLowercase([s[i + 4], s[i + 5]]), hex[0] < 0x20 else {
                    throw ValvError.metadata("escape the writer does not emit")
                }
                out.append(hex[0])
                i += 6
            default:
                throw ValvError.metadata("escape the writer does not emit")
            }
        }
    }

    /// `-?(0|[1-9][0-9]*)` with int64 overflow checks; "-0" is not canonical.
    mutating func int64() throws -> Int64 {
        var neg = false
        if i < s.count, s[i] == UInt8(ascii: "-") { neg = true; i += 1 }
        let start = i
        var v: Int64 = 0
        while i < s.count, s[i] >= UInt8(ascii: "0"), s[i] <= UInt8(ascii: "9") {
            let d = Int64(s[i] - UInt8(ascii: "0"))
            let (m, o1) = v.multipliedReportingOverflow(by: 10)
            // Accumulate negative values directly so Int64.min parses.
            let (r, o2) = neg ? m.subtractingReportingOverflow(d) : m.addingReportingOverflow(d)
            guard !o1, !o2 else { throw ValvError.metadata("integer overflows int64") }
            v = r
            i += 1
        }
        let digits = i - start
        guard digits > 0 else { throw ValvError.metadata("expected an integer") }
        if digits > 1 && s[start] == UInt8(ascii: "0") { throw ValvError.metadata("leading zero") }
        if neg && v == 0 { throw ValvError.metadata("negative zero") }
        return v
    }
}
