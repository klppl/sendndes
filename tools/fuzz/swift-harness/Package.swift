// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "SwiftHarness",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../../../swift/NdesCore"),
    ],
    targets: [
        .executableTarget(
            name: "SwiftHarness",
            dependencies: [
                .product(name: "NdesCore", package: "NdesCore")
            ]
        )
    ]
)
