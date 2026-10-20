import AppKit
import SwiftUI

// Renders the app icon (Aster, from app/Sources/sendndes/Mascot.swift, on a rounded square) into an
// .iconset folder (argument 1). scripts/make-icon.sh turns that into app/Resources/AppIcon.icns.
// Optional argument 2 picks the background: mint (default), cream or plum.
let backgrounds: [String: Color] = [
    "mint": Color(.sRGB, red: 0x2F / 255, green: 0xC5 / 255, blue: 0x94 / 255, opacity: 1),
    "cream": Color(.sRGB, red: 0xFB / 255, green: 0xF3 / 255, blue: 0xE4 / 255, opacity: 1),
    "plum": Color(.sRGB, red: 0x6B / 255, green: 0x4F / 255, blue: 0xB8 / 255, opacity: 1),
]
let bgName = CommandLine.arguments.count > 2 ? CommandLine.arguments[2] : "mint"
let iconBackground = backgrounds[bgName] ?? backgrounds["mint"]!

struct IconView: View {
    let pixels: CGFloat
    var body: some View {
        let inner = pixels * 824 / 1024   // Apple's icon grid: the shape fills 824 of 1024
        let shape = RoundedRectangle(cornerRadius: inner * 0.2237, style: .continuous)
        ZStack {
            shape.fill(iconBackground)
            shape.strokeBorder(Theme.onAccent, lineWidth: max(1.5, inner * (pixels < 64 ? 0.04 : 0.028)))
            Aster(mood: .happy, size: inner * 0.86, still: true)
        }
        .frame(width: inner, height: inner)
        .frame(width: pixels, height: pixels)
        .environment(\.colorScheme, .light)
    }
}

@MainActor func render(_ pixels: Int, to path: String) {
    let renderer = ImageRenderer(content: IconView(pixels: CGFloat(pixels)))
    renderer.scale = 1
    guard let cg = renderer.cgImage, let png = NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:]) else {
        FileHandle.standardError.write(Data("render failed for \(pixels)\n".utf8)); exit(1)
    }
    try! png.write(to: URL(fileURLWithPath: path))
}

let dir = CommandLine.arguments[1]
try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
MainActor.assumeIsolated {
    for (name, px) in [("icon_16x16", 16), ("icon_16x16@2x", 32), ("icon_32x32", 32), ("icon_32x32@2x", 64),
                       ("icon_128x128", 128), ("icon_128x128@2x", 256), ("icon_256x256", 256), ("icon_256x256@2x", 512),
                       ("icon_512x512", 512), ("icon_512x512@2x", 1024)] {
        render(px, to: "\(dir)/\(name).png")
    }
}
