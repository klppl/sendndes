// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "sendndes",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AppCore", targets: ["AppCore"]),
        .executable(name: "sendndes", targets: ["sendndes"]),
    ],
    targets: [
        .target(name: "AppCore"),
        .executableTarget(name: "sendndes", dependencies: ["AppCore"]),
        .testTarget(name: "AppCoreTests", dependencies: ["AppCore"]),
    ]
)
