// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "sendndes",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AppCore", targets: ["AppCore"]),
        .executable(name: "sendndes", targets: ["sendndes"]),
    ],
    dependencies: [
        .package(path: "../swift/NdesCore"),
    ],
    targets: [
        .target(name: "AppCore", dependencies: ["NdesCore"]),
        .executableTarget(name: "sendndes", dependencies: ["AppCore"]),
        .testTarget(name: "AppCoreTests", dependencies: ["AppCore"]),
    ]
)
