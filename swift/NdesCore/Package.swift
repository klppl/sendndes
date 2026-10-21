// swift-tools-version: 6.1
import PackageDescription

// Fixed keys, ids and nonces for the test vectors exist only when the
// NDES_TESTVECTORS trait is enabled:
//
//     swift test --traits NDES_TESTVECTORS
//
// The trait is not a default trait, so a normal build (debug or release, and
// any package that depends on NdesCore) contains no way to inject randomness.
// scripts/check-release-symbols.sh checks this.
let package = Package(
    name: "NdesCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "NdesCore", targets: ["NdesCore"]),
        .executable(name: "ndes-swift-tool", targets: ["ndes-swift-tool"]),
    ],
    traits: [
        .trait(name: "NDES_TESTVECTORS", description: "Test-only hook for fixed keys, ids and nonces."),
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
            name: "NdesCore",
            dependencies: [.product(name: "Clibsodium", package: "swift-sodium")]
        ),
        .executableTarget(
            name: "ndes-swift-tool",
            dependencies: ["NdesCore"]
        ),
        .testTarget(
            name: "NdesCoreTests",
            dependencies: ["NdesCore"]
        ),
    ]
)
