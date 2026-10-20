import SwiftUI

/// The send n*des mark: an image file whose picture is hidden behind a pixelated censor, with an
/// asterisk badge. Drawn in code (fixed colours, no assets) so the sidebar and the app icon come from
/// one source. The pixels are fixed by a seeded generator, so the icon never changes between builds.
struct AppLogo: View {
    var size: CGFloat = 40

    var body: some View {
        Canvas { ctx, sz in
            let k = min(sz.width, sz.height) / 124
            ctx.translateBy(x: sz.width / 2, y: sz.height / 2)
            ctx.scaleBy(x: k, y: k)
            LogoArt.draw(&ctx, thickBorder: size < 64)
        }
        .frame(width: size, height: size)
        .accessibilityLabel("send n*des")
    }
}

enum LogoArt {
    static let ink = rgb(0x241B2F), pink = rgb(0xFF5C8A), cream = rgb(0xFBF3E4), mint = rgb(0x2FC594), fold = rgb(0xD3D1C7)

    private static func rgb(_ hex: UInt32) -> Color {
        Color(.sRGB, red: Double((hex >> 16) & 0xFF) / 255, green: Double((hex >> 8) & 0xFF) / 255,
              blue: Double(hex & 0xFF) / 255, opacity: 1)
    }

    private static let noise: [UInt32] = [0xFFE3D3, 0xFFD0BA, 0xFFC0A5, 0xFFB08F, 0xF59E86, 0xFFD9C7, 0xE88F7A, 0xFFCDB4]
    private static let figure: [UInt32] = [0xF59E86, 0xE88F7A, 0xFFB08F, 0xD9786A, 0xF2A58E]
    private static let backdrop: [UInt32] = [0xFFF1E8, 0xFFE9DD, 0xFFE3D3, 0xFFDCCB]

    /// Seeded Mulberry32, so the mosaic is identical every time.
    private struct Rng {
        var s: UInt32
        mutating func next() -> Double {
            s = s &+ 0x6D2B79F5
            var t = (s ^ (s >> 15)) &* (1 | s)
            t = (t &+ ((t ^ (t >> 7)) &* (61 | t))) ^ t
            return Double(t ^ (t >> 14)) / 4294967296
        }
    }

    /// 12 x 11 cells. About a third follow a faint head-and-shoulders shape, the rest are noise.
    private static let cells: [(x: Double, y: Double, w: Double, h: Double, color: Color)] = {
        let (x0, y0, w, h, c, hint) = (-34.0, -24.0, 68.0, 66.0, 6.0, 0.35)
        var rng = Rng(s: 5)
        var out: [(Double, Double, Double, Double, Color)] = []
        for i in 0..<Int((h / c).rounded(.up)) {
            for j in 0..<Int((w / c).rounded(.up)) {
                let u = (Double(j) + 0.5) * c / w * 2 - 1, v = (Double(i) + 0.5) * c / h * 2 - 1
                let head = pow(u / 0.36, 2) + pow((v + 0.3) / 0.42, 2) < 1
                let shoulders = pow(u / 0.92, 2) + pow((v - 0.95) / 0.62, 2) < 1
                let hex: UInt32
                if rng.next() < hint {
                    let pal = (head || shoulders) ? figure : backdrop
                    hex = pal[Int(rng.next() * Double(pal.count))]
                } else {
                    hex = noise[Int(rng.next() * Double(noise.count))]
                    _ = rng.next()
                }
                out.append((x0 + Double(j) * c, y0 + Double(i) * c, min(c, w - Double(j) * c) + 0.4, min(c, h - Double(i) * c) + 0.4, rgb(hex)))
            }
        }
        return out
    }()

    static func draw(_ ctx: inout GraphicsContext, thickBorder: Bool) {
        let round = { (w: CGFloat) in StrokeStyle(lineWidth: w, lineCap: .round, lineJoin: .round) }

        let hw: CGFloat = thickBorder ? 5 : 3.5
        let squircle = RoundedRectangle(cornerRadius: 30, style: .continuous)
            .path(in: CGRect(x: -62 + hw / 2, y: -62 + hw / 2, width: 124 - hw, height: 124 - hw))
        ctx.fill(squircle, with: .color(mint))
        ctx.stroke(squircle, with: .color(ink), style: round(hw))

        ctx.scaleBy(x: 0.84, y: 0.84)

        var page = Path()
        page.move(to: CGPoint(x: -40, y: -56)); page.addLine(to: CGPoint(x: 14, y: -56))
        page.addLine(to: CGPoint(x: 40, y: -30)); page.addLine(to: CGPoint(x: 40, y: 56))
        page.addLine(to: CGPoint(x: -40, y: 56)); page.closeSubpath()
        ctx.fill(page, with: .color(cream))
        ctx.stroke(page, with: .color(ink), style: round(4))

        var corner = Path()
        corner.move(to: CGPoint(x: 14, y: -56)); corner.addLine(to: CGPoint(x: 14, y: -30)); corner.addLine(to: CGPoint(x: 40, y: -30))
        corner.closeSubpath()
        ctx.fill(corner, with: .color(fold))
        ctx.stroke(corner, with: .color(ink), style: round(3.5))

        for cell in cells {
            ctx.fill(Path(CGRect(x: cell.x, y: cell.y, width: cell.w, height: cell.h)), with: .color(cell.color))
        }
        ctx.stroke(Path(CGRect(x: -34, y: -24, width: 68, height: 66)), with: .color(ink), style: round(2.5))

        let badge = Path(ellipseIn: CGRect(x: 30 - 19, y: 46 - 19, width: 38, height: 38))
        ctx.fill(badge, with: .color(pink))
        ctx.stroke(badge, with: .color(ink), style: round(3.5))
        var star = Path()
        let l = 8.7, a = l * 0.866, b = l * 0.5
        for (p, q) in [(CGPoint(x: 0, y: -l), CGPoint(x: 0, y: l)), (CGPoint(x: -a, y: b), CGPoint(x: a, y: -b)), (CGPoint(x: -a, y: -b), CGPoint(x: a, y: b))] {
            star.move(to: CGPoint(x: 30 + p.x, y: 46 + p.y)); star.addLine(to: CGPoint(x: 30 + q.x, y: 46 + q.y))
        }
        ctx.stroke(star, with: .color(ink), style: round(4.5))
        ctx.stroke(star, with: .color(cream), style: round(2.2))
    }
}
