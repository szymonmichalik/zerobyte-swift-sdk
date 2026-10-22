// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ZeroByte",
    platforms: [.iOS(.v16), .macOS(.v13), .watchOS(.v9), .tvOS(.v16), .visionOS(.v1)],
    products: [
        .library(name: "ZeroByte", targets: ["ZeroByte"]),
        // APNs registrations and payloads, for apps that use Apple push.
        .library(name: "ZeroBytePush", targets: ["ZeroBytePush"]),
    ],
    targets: [
        .target(name: "ZeroByte"),
        .target(name: "ZeroBytePush", dependencies: ["ZeroByte"]),
        .testTarget(
            name: "ZeroByteTests",
            dependencies: ["ZeroByte", "ZeroBytePush"],
            resources: [.copy("relay-v1.json")]
        ),
    ]
)
