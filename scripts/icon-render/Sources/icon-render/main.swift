import AppKit
import SwiftUI

// Renders app/Sources/sendndes/Logo.swift into an .iconset folder (argument 1). scripts/make-icon.sh
// turns that into app/Resources/AppIcon.icns.
@MainActor func render(_ pixels: Int, to path: String) {
    let body = CGFloat(pixels) * 824 / 1024   // Apple's icon grid: the shape fills 824 of 1024
    let view = AppLogo(size: body).frame(width: CGFloat(pixels), height: CGFloat(pixels))
    let renderer = ImageRenderer(content: view)
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
