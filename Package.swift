// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "gpg-sep",
    // Zero external dependencies by design: the whole tool is auditable from
    // this repo alone, and builds offline.
    platforms: [.macOS(.v13)],
    targets: [
        // Assuan line protocol (server + client) and canonical S-expressions.
        .target(name: "AssuanKit"),
        // Minimal OpenPGP v4 packet writer/reader for ECDSA nistp256 (algo 19)
        // and ECDH (algo 18): key packets, signatures, fingerprints, keygrips.
        .target(name: "OpenPGPKit"),
        // Key backends: Secure Enclave (CryptoKit) and software P-256 (tests),
        // plus the on-disk key store and policy/config handling.
        .target(name: "SEPKit", dependencies: ["OpenPGPKit"]),
        // The keygrip-routed gpg-agent proxy, as a library so the CLI and
        // integration tests can drive it in-process.
        .target(name: "GPGSepDaemonCore", dependencies: ["AssuanKit", "OpenPGPKit", "SEPKit"]),
        .executableTarget(name: "gpg-sep-agent", dependencies: ["GPGSepDaemonCore"]),
        .executableTarget(
            name: "gpg-sep",
            dependencies: ["AssuanKit", "OpenPGPKit", "SEPKit", "GPGSepDaemonCore"]
        ),
        .testTarget(name: "AssuanKitTests", dependencies: ["AssuanKit"]),
        .testTarget(name: "OpenPGPKitTests", dependencies: ["OpenPGPKit"]),
        .testTarget(name: "SEPKitTests", dependencies: ["SEPKit", "OpenPGPKit"]),
        .testTarget(
            name: "IntegrationTests",
            dependencies: ["GPGSepDaemonCore", "SEPKit", "OpenPGPKit", "AssuanKit"]
        ),
    ]
)
