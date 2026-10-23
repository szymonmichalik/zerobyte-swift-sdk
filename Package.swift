// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ZeroByte",
    platforms: [.iOS(.v16), .macOS(.v13), .watchOS(.v9), .tvOS(.v16), .visionOS(.v1)],
    products: [
        .library(name: "ZeroByte", targets: ["ZeroByte"])
    ],
    targets: [
        .target(name: "ZeroByte"),
        .testTarget(
            name: "ZeroByteTests",
            dependencies: ["ZeroByte"],
            resources: [.copy("relay-v1.json")]
        ),
    ]
)
