// swift-tools-version: 6.1
import PackageDescription

// send n*des for iPhone. All logic is in SenderCore (platform independent, tested on macOS with `swift test`);
// SenderUI holds the SwiftUI screens; the app and the share extension (project.yml, App/, ShareExtension/) are thin.
let package = Package(
    name: "SendndesIOS",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "SenderCore", targets: ["SenderCore"]),
        .library(name: "SenderUI", targets: ["SenderUI"]),
        .library(name: "ShareExtensionEntry", targets: ["ShareExtensionEntry"]),
    ],
    dependencies: [
        .package(path: "../swift/NdesCore"),
    ],
    targets: [
        .target(name: "SenderCore", dependencies: [.product(name: "NdesCore", package: "NdesCore")]),
        .target(name: "SenderUI", dependencies: ["SenderCore"], swiftSettings: [.swiftLanguageMode(.v5)]),
        // The app and the share extension entry points. The Xcode project (project.yml) builds the same files into
        // the real app and extension; these targets exist so `xcodebuild -scheme ... -destination generic/platform=iOS`
        // can check them without XcodeGen.
        .executableTarget(name: "SendndesApp", dependencies: ["SenderUI"], path: "App", exclude: ["Info.plist", "Sendndes.entitlements"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .target(name: "ShareExtensionEntry", dependencies: ["SenderUI"], path: "ShareExtension", exclude: ["Info.plist", "ShareExtension.entitlements"], swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "SenderCoreTests", dependencies: ["SenderCore"]),
    ]
)
