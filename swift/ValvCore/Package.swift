// swift-tools-version: 6.1
import PackageDescription

// Fixed keys, ids and nonces for the test vectors exist only when the
// VALV_TESTVECTORS trait is enabled:
//
//     swift test --traits VALV_TESTVECTORS
//
// The trait is not a default trait, so a normal build (debug or release, and
// any package that depends on ValvCore) contains no way to inject randomness.
// scripts/check-release-symbols.sh checks this.
let package = Package(
    name: "ValvCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "ValvCore", targets: ["ValvCore"]),
        .executable(name: "valv-swift-tool", targets: ["valv-swift-tool"]),
    ],
    traits: [
        .trait(name: "VALV_TESTVECTORS", description: "Test-only hook for fixed keys, ids and nonces."),
    ],
    dependencies: [
        // Used only for Argon2id (crypto_pwhash). Pinned to an exact revision:
        // swift-sodium's last tag (0.9.1, 2020) bundles libsodium 1.0.18; this
        // revision bundles libsodium 1.0.22.
        .package(url: "https://github.com/jedisct1/swift-sodium.git",
                 revision: "cfd195c76882aa9b997560ca7cb95d72fbf5db00"),
    ],
    targets: [
        .target(
            name: "ValvCore",
            dependencies: [.product(name: "Clibsodium", package: "swift-sodium")]
        ),
        .executableTarget(
            name: "valv-swift-tool",
            dependencies: ["ValvCore"]
        ),
        .testTarget(
            name: "ValvCoreTests",
            dependencies: ["ValvCore"]
        ),
    ]
)
