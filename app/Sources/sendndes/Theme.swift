import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// The look: warm paper, ink outlines, hard "sticker" shadows, one hot-pink accent. Every colour has a
/// light and a dark value, and text never sits on a colour that fails contrast (pink and mint are used
/// for fills and icons; words are ink).
enum Theme {
    static func dynamic(_ light: UInt32, _ dark: UInt32) -> Color {
        Color(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            return NSColor(hex: isDark ? dark : light)
        })
    }

    static let paper = dynamic(0xFBF3E4, 0x1C1923)
    static let paperDeep = dynamic(0xF3E6CD, 0x141219)
    static let card = dynamic(0xFFFCF5, 0x29252F)
    static let ink = dynamic(0x241B2F, 0xF6EDE0)
    static let inkSoft = dynamic(0x5C5266, 0xBBB1C6)
    static let onAccent = Color(nsColor: NSColor(hex: 0x241B2F))

    static let pink = dynamic(0xFF5C8A, 0xFF7AA3)
    static let sun = dynamic(0xFFC93C, 0xFFD45C)
    static let mint = dynamic(0x2FC594, 0x4FD8A8)
    static let grape = dynamic(0x8466FF, 0xA48FFF)
    static let tomato = dynamic(0xE0334F, 0xFF7088)
    static let amber = dynamic(0xF2A31F, 0xFFB947)
    /// Readable-as-text variants for small messages on paper.
    static let tomatoText = dynamic(0xB3162F, 0xFF8EA0)
    static let amberText = dynamic(0x8A5200, 0xFFC56B)
    static let mintText = dynamic(0x0B6B4C, 0x7BE8C2)
}

extension NSColor {
    convenience init(hex: UInt32) {
        self.init(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
                  blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}

extension View {
    /// Big rounded heading face.
    func display(_ size: CGFloat) -> some View {
        font(.system(size: size, weight: .heavy, design: .rounded))
    }

    /// Rounded UI label face.
    func label(_ style: Font.TextStyle = .body, weight: Font.Weight = .semibold) -> some View {
        font(.system(style, design: .rounded, weight: weight))
    }

    /// Paper card with an ink outline; `shadow > 0` adds the hard offset sticker shadow.
    func sticker(radius: CGFloat = 16, shadow: CGFloat = 0, fill: Color = Theme.card, outlined: Bool = true) -> some View {
        modifier(StickerStyle(radius: radius, shadow: shadow, fill: fill, outlined: outlined))
    }
}

private struct StickerStyle: ViewModifier {
    let radius: CGFloat, shadow: CGFloat, fill: Color, outlined: Bool
    func body(content: Content) -> some View {
        content
            .background {
                ZStack {
                    if shadow > 0 {
                        RoundedRectangle(cornerRadius: radius, style: .continuous)
                            .fill(Theme.ink).offset(x: shadow, y: shadow)
                    }
                    RoundedRectangle(cornerRadius: radius, style: .continuous).fill(fill)
                }
            }
            .overlay { if outlined { RoundedRectangle(cornerRadius: radius, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2) } }
    }
}

// MARK: File icons

enum FileIcons {
    private static let cache = NSCache<NSString, NSImage>()

    /// The system icon for the name's extension. Only the extension is looked at; the name is untrusted.
    static func icon(for name: String) -> NSImage {
        let ext = String((name as NSString).pathExtension.lowercased().prefix(16))
        if let hit = cache.object(forKey: ext as NSString) { return hit }
        let type = (ext.isEmpty ? nil : UTType(filenameExtension: ext)) ?? .data
        let img = NSWorkspace.shared.icon(for: type)
        cache.setObject(img, forKey: ext as NSString)
        return img
    }
}

struct FileGlyph: View {
    let name: String
    var size: CGFloat = 22
    var body: some View {
        Image(nsImage: FileIcons.icon(for: name)).resizable().interpolation(.high)
            .frame(width: size, height: size).accessibilityHidden(true)
    }
}
