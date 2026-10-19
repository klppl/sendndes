import Foundation

/// Names from the vault and the helper are untrusted text. This removes what
/// could hide or reorder characters before anything is shown.
public enum DisplayName {
    public static let maxCharacters = 256

    public static func sanitize(_ s: String) -> String {
        var out = String.UnicodeScalarView()
        var marks = 0
        var seen = 0
        for u in s.unicodeScalars {
            seen += 1
            if seen > 4096 { break } // bound the work on absurd input
            switch u.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned:
                continue
            default: break
            }
            if u.value == 0xFFFC { continue }
            switch u.properties.generalCategory {
            case .nonspacingMark, .spacingMark, .enclosingMark:
                marks += 1
                if marks > 4 { continue }
            default:
                marks = 0
            }
            out.append(u)
        }
        let text = String(out)
        if text.allSatisfy({ $0.isWhitespace }) { return "(unnamed)" }
        return String(text.prefix(maxCharacters))
    }
}
