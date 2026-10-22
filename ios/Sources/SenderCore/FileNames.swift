import Foundation

/// Names and folders that go into the sealed metadata. SPEC 5.2 says what the format accepts; this makes
/// anything a phone hands over (item provider names can be anything) fit, without ever failing a share.
public enum FileNames {
    /// A safe stored name for `suggested`, or `fallback` when nothing usable is left.
    public static func sanitize(_ suggested: String?, fallback: @autoclosure () -> String) -> String {
        guard let s = suggested else { return fallback() }
        var out = String.UnicodeScalarView()
        for u in s.precomposedStringWithCanonicalMapping.unicodeScalars {
            if u == "/" || u == "\\" || u == "\0" { out.append("_"); continue }
            if isControlOrBidi(u) { continue }
            out.append(u)
        }
        var name = String(out).trimmingCharacters(in: .whitespaces)
        while name.hasPrefix(".") { name.removeFirst() }   // no hidden files, and never "." or ".."
        name = name.trimmingCharacters(in: .whitespaces)
        if name.isEmpty { return fallback() }
        return truncate(name, toBytes: SenderLimits.maxNameBytes)
    }

    /// `shared-<yyyyMMdd-HHmmss>.<ext>`.
    public static func fallbackName(now: Date, ext: String?) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyyMMdd-HHmmss"
        let e = (ext ?? "").filter { $0.isASCII && ($0.isLetter || $0.isNumber) }.prefix(10)
        return "shared-" + f.string(from: now) + (e.isEmpty ? "" : "." + e)
    }

    /// Whether `folder` is acceptable as the destination folder (SPEC 5.2 `dir`): components joined by "/".
    public static func validateFolder(_ folder: String) -> String? {
        let t = folder.precomposedStringWithCanonicalMapping.trimmingCharacters(in: .whitespaces)
        guard t.utf8.count <= SenderLimits.maxNameBytes, !t.hasPrefix("/"), !t.hasSuffix("/") else { return nil }
        if t.isEmpty { return "" }
        for c in t.split(separator: "/", omittingEmptySubsequences: false) {
            let s = String(c)
            guard !s.isEmpty, s == s.trimmingCharacters(in: .whitespaces), s != ".", s != "..", !s.unicodeScalars.contains(where: { $0 == "\\" || $0 == "\0" || isControlOrBidi($0) }) else { return nil }
        }
        return t
    }

    static func isControlOrBidi(_ u: Unicode.Scalar) -> Bool {
        switch u.value {
        case 0x00...0x1F, 0x7F...0x9F: return true
        case 0x200B...0x200F, 0x2028, 0x2029, 0x202A...0x202E, 0x2060...0x2064, 0x2066...0x206F, 0x061C, 0xFEFF, 0x00AD, 0x180E, 0xE0000...0xE007F: return true
        default: return false
        }
    }

    /// Cuts to `n` UTF-8 bytes without splitting a character, keeping a short extension when there is one.
    static func truncate(_ s: String, toBytes n: Int) -> String {
        guard s.utf8.count > n else { return s }
        var ext = ""
        if let dot = s.lastIndex(of: "."), s.distance(from: dot, to: s.endIndex) <= 12, dot != s.startIndex { ext = String(s[dot...]) }
        var base = String(s.dropLast(ext.count))
        while (base + ext).utf8.count > n, !base.isEmpty { base.removeLast() }
        if base.isEmpty {
            // Nothing of the base fits (a long run of combining marks): cut by scalars, never by a whole "character".
            var out = String.UnicodeScalarView()
            for u in s.unicodeScalars { if (String(out) + String(u)).utf8.count > n { break }; out.append(u) }
            return String(out).isEmpty ? "_" : String(out)
        }
        return base + ext
    }
}
