import SwiftUI
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

/// The look of the Mac app, on the phone: warm paper, ink outlines, hard "sticker" shadows, one hot-pink accent.
/// The palette and shapes are the same as `app/Sources/sendndes/Theme.swift`; only the platform colour type differs.
enum Theme {
    static func dynamic(_ light: UInt32, _ dark: UInt32) -> Color {
        #if canImport(UIKit)
        Color(uiColor: UIColor { $0.userInterfaceStyle == .dark ? UIColor(hex: dark) : UIColor(hex: light) })
        #else
        Color(nsColor: NSColor(name: nil) { a in
            NSColor(hex: a.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light)
        })
        #endif
    }

    static let paper = dynamic(0xFBF3E4, 0x1C1923)
    static let paperDeep = dynamic(0xF3E6CD, 0x141219)
    static let card = dynamic(0xFFFCF5, 0x29252F)
    static let ink = dynamic(0x241B2F, 0xF6EDE0)
    static let inkSoft = dynamic(0x5C5266, 0xBBB1C6)
    static let onAccent = Color(red: 0x24 / 255, green: 0x1B / 255, blue: 0x2F / 255)

    static let pink = dynamic(0xFF5C8A, 0xFF7AA3)
    static let sun = dynamic(0xFFC93C, 0xFFD45C)
    static let mint = dynamic(0x2FC594, 0x4FD8A8)
    static let grape = dynamic(0x8466FF, 0xA48FFF)
    static let tomato = dynamic(0xE0334F, 0xFF7088)
    static let amber = dynamic(0xF2A31F, 0xFFB947)
    static let tomatoText = dynamic(0xB3162F, 0xFF8EA0)
    static let amberText = dynamic(0x8A5200, 0xFFC56B)
    static let mintText = dynamic(0x0B6B4C, 0x7BE8C2)
}

#if canImport(UIKit)
extension UIColor {
    convenience init(hex: UInt32) {
        self.init(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}
#else
extension NSColor {
    convenience init(hex: UInt32) {
        self.init(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }
}
#endif

extension View {
    func display(_ size: CGFloat) -> some View { font(.system(size: size, weight: .heavy, design: .rounded)) }
    func label(_ style: Font.TextStyle = .body, weight: Font.Weight = .semibold) -> some View { font(.system(style, design: .rounded, weight: weight)) }
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
                    if shadow > 0 { RoundedRectangle(cornerRadius: radius, style: .continuous).fill(Theme.ink).offset(x: shadow, y: shadow) }
                    RoundedRectangle(cornerRadius: radius, style: .continuous).fill(fill)
                }
            }
            .overlay { if outlined { RoundedRectangle(cornerRadius: radius, style: .continuous).strokeBorder(Theme.ink, lineWidth: 2) } }
    }
}

func plural(_ n: Int, _ one: String, _ many: String) -> String { n == 1 ? one : many }
