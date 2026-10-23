# ZeroByte Swift SDK

The Swift client for ZeroByte, an end-to-end encrypted relay between two paired
devices of one app. It runs on iOS 16, macOS 13, watchOS 9, tvOS 16 and
visionOS 1 and uses only Apple frameworks: CryptoKit for the cryptography,
URLSession for HTTP and the WebSocket.

## How it works

Two devices pair once and agree a 32-byte link key and a link id. From these,
each device derives the mailbox name, an access token and one encryption key
per direction. Every message is sealed with ChaCha20-Poly1305 on the device
that sends it. The relay holds the sealed envelope until the other device
collects it, and it never has a key to open it with.

The wire format is specified in
[Relay Protocol v1](https://github.com/szymonmichalik/zerobyte-protocol/blob/master/relay-v1.md).

## Installation

In Xcode, choose File > Add Package Dependencies and enter the repository URL.
In `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/szymonmichalik/zerobyte-swift-sdk.git", from: "1.0.0")
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "ZeroByte", package: "zerobyte-swift-sdk")
    ])
]
```

## Usage

```swift
import ZeroByte

// Both devices agreed `linkKey` (32 bytes) and `linkID` when they paired.
let credentials = try Credentials(linkKey: linkKey, linkID: linkID)
let base = URL(string: "https://relay.example.com/v1/")!  // your relay
let relay = Relay(appID: "<your app id>", credentials: credentials, base: base)
let link = Link(
    credentials: credentials,
    sends: .primaryToCompanion,
    transport: relay,
    lastReceived: savedLastReceived
)

try await link.send(Data("hello".utf8))

for await _ in relay.watch(direction: .companionToPrimary) {
    for message in try await link.receive() {
        handle(message.plaintext)
    }
}
```

- **Pairing** is the app's job: for example a QR code carrying a fresh 32-byte
  key, or an ECDH exchange confirmed by comparing digits on both screens. Store
  the link key in the Keychain.
- **Directions.** The primary holds the source of truth and sends
  `.primaryToCompanion`; the companion sends `.companionToPrimary`.
- **State.** Persist `link.lastReceived` and pass it back on the next launch,
  so messages are not delivered twice.
- **Unpairing.** Call `try await link.erase()` to delete the mailbox at once.
- **The relay.** `base` is your relay's `/v1/` URL, with the trailing slash.
  There is no default.

The app id identifies your app on your relay. Generate one with
`npm run app-id` in a clone of
[zerobyte-relay](https://github.com/szymonmichalik/zerobyte-relay) and add it
to `RELAY_APPS`.

## Testing

```sh
swift test
```

This runs the protocol vectors and the `Link` tests. To also test against a
real relay, start one locally (see zerobyte-relay) and run:

```sh
RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<app id> swift test
```

`Tests/ZeroByteTests/relay-v1.json` is copied from the independent reference in
[zerobyte-protocol](https://github.com/szymonmichalik/zerobyte-protocol/tree/master/spec).
Never regenerate it from this package.

## Licence

Apache-2.0, see [`LICENSE`](LICENSE).

## About ZeroByte

ZeroByte is an open-source project by Szymon Michalik: the protocol, the relay
and the SDKs. relay.zerobyte.cloud runs the same code for Derived and isn't
open to other apps. To use ZeroByte in your app, run your own relay: see
[zerobyte-relay](https://github.com/szymonmichalik/zerobyte-relay).
