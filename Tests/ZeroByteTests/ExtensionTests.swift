import CryptoKit
import Foundation
import Testing

@testable import ZeroByte
import ZeroBytePush

/// Records what `Link` asks of the transport.
actor NotifyingRelay: RelayTransport {
    var notified: [(UInt64, Notify)] = []
    let inner = MemoryRelay()

    func claim() async throws {}
    func put(_ envelope: Data, direction: Direction, sequence: UInt64) async throws {
        try await put(envelope, direction: direction, sequence: sequence, notify: .none)
    }
    func put(_ envelope: Data, direction: Direction, sequence: UInt64, notify: Notify) async throws {
        try await inner.put(envelope, direction: direction, sequence: sequence)
        notified.append((sequence, notify))
    }
    func fetch(direction: Direction, after sequence: UInt64?) async throws -> (
        envelopes: [Data], more: Bool
    ) { try await inner.fetch(direction: direction, after: sequence) }
    func lastSequence(direction: Direction) async throws -> UInt64? {
        try await inner.lastSequence(direction: direction)
    }
    func prune(direction: Direction, through sequence: UInt64) async throws {
        try await inner.prune(direction: direction, through: sequence)
    }
    func erase() async throws { try await inner.erase() }
}

@Suite("Extensions")
struct ExtensionTests {
    let credentials = try! Vectors.shared.credentials(1)

    @Test("send(notify:) reaches the transport; a transport without push still stores")
    func notify() async throws {
        let relay = NotifyingRelay()
        let phone = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        try await phone.send(Data("a".utf8))
        try await phone.send(Data("b".utf8), notify: .alert)
        try await phone.send(Data("c".utf8), notify: .silent)
        #expect(await relay.notified.map(\.1) == [.none, .alert, .silent])

        let plain = MemoryRelay()
        let other = Link(credentials: credentials, sends: .primaryToCompanion, transport: plain)
        #expect(try await other.send(Data("x".utf8), notify: .alert) == 1)
        #expect(await plain.boxes[.primaryToCompanion]?.count == 1)
    }

    @Test("A push registration is the JSON the relay expects")
    func registration() throws {
        let token = Data((0..<32).map(UInt8.init))
        let json = PushRegistration.apns(
            deviceToken: token, environment: .development, tag: "t-1", alert: "Nowa wiadomość"
        ).json
        let object = try #require(try JSONSerialization.jsonObject(with: json) as? [String: String])
        #expect(
            object == [
                "service": "apns", "token": token.lowercaseHex, "environment": "development",
                "tag": "t-1", "alert": "Nowa wiadomość",
            ])
        let tag = PushRegistration.randomTag()
        #expect(tag.count == 22)
        #expect(tag.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        let other = PushRegistration(service: "unifiedpush", fields: ["endpoint": "https://up.example/x"], tag: "t")
        let parsed = try #require(try JSONSerialization.jsonObject(with: other.json) as? [String: String])
        #expect(parsed == ["service": "unifiedpush", "endpoint": "https://up.example/x", "tag": "t"])
    }

    @Test("The tag is read back from a push, and only a valid one")
    func payloadTag() {
        #expect(ZeroBytePushPayload.tag(in: ["aps": [:], "zerobyte": ["tag": "Zq3k-8_r"]]) == "Zq3k-8_r")
        #expect(ZeroBytePushPayload.tag(in: ["aps": [:]]) == nil)
        #expect(ZeroBytePushPayload.tag(in: ["zerobyte": ["tag": "a/b"]]) == nil)
        #expect(ZeroBytePushPayload.tag(in: ["zerobyte": ["tag": ""]]) == nil)
        #expect(ZeroBytePushPayload.tag(in: ["zerobyte": ["tag": String(repeating: "a", count: 65)]]) == nil)
    }

    @Test("Signal keys differ from envelope keys and between directions")
    func signalKeys() {
        let keys = [
            credentials.p2cKey, credentials.c2pKey, credentials.signalP2CKey,
            credentials.signalC2PKey,
        ]
        #expect(Set(keys).count == 4)
        let expected = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: hex(Vectors.shared.credentials[1].linkKey)),
            salt: hex(Vectors.shared.credentials[1].linkId),
            info: Data("zerobyte-signal-p2c-v1".utf8), outputByteCount: 32
        ).withUnsafeBytes { Data($0) }
        #expect(credentials.signalP2CKey == expected)
    }

    @Test("Signal frames open once, in order, in time, in their direction, under their key")
    func signalFrames() throws {
        let now = SignalFrame.milliseconds()
        let frame = try SignalFrame.seal(
            Data("offer".utf8), direction: .primaryToCompanion, counter: now,
            credentials: credentials)
        #expect(frame.count == 5 + SignalFrame.overhead)
        let opened = try SignalFrame.open(
            frame, direction: .primaryToCompanion, after: nil, now: now, credentials: credentials)
        #expect(opened.plaintext == Data("offer".utf8))

        #expect(throws: ZeroByteError.replayed(sequence: now)) {
            try SignalFrame.open(
                frame, direction: .primaryToCompanion, after: now, now: now,
                credentials: credentials)
        }
        #expect(throws: ZeroByteError.replayed(sequence: now)) {
            try SignalFrame.open(
                frame, direction: .primaryToCompanion, after: nil,
                now: now + SignalFrame.window + 1, credentials: credentials)
        }
        #expect(throws: ZeroByteError.wrongDirection) {
            try SignalFrame.open(
                frame, direction: .companionToPrimary, after: nil, now: now,
                credentials: credentials)
        }
        let other = try Vectors.shared.credentials(0)
        #expect(throws: ZeroByteError.authenticationFailed) {
            try SignalFrame.open(
                frame, direction: .primaryToCompanion, after: nil, now: now, credentials: other)
        }
        // An envelope sealed for the same direction is not a signal frame.
        let envelope = try Envelope.seal(
            Data("offer".utf8), direction: .primaryToCompanion, sequence: now,
            credentials: credentials)
        #expect(throws: ZeroByteError.authenticationFailed) {
            try SignalFrame.open(
                envelope, direction: .primaryToCompanion, after: nil, now: now,
                credentials: credentials)
        }
        var flipped = frame
        flipped[flipped.count - 1] ^= 1
        #expect(throws: ZeroByteError.authenticationFailed) {
            try SignalFrame.open(
                flipped, direction: .primaryToCompanion, after: nil, now: now,
                credentials: credentials)
        }
        #expect(throws: ZeroByteError.tooLarge) {
            try SignalFrame.seal(
                Data(count: SignalFrame.maximumPlaintextBytes + 1), direction: .primaryToCompanion,
                counter: now, credentials: credentials)
        }
        let largest = try SignalFrame.seal(
            Data(count: SignalFrame.maximumPlaintextBytes), direction: .primaryToCompanion,
            counter: now, credentials: credentials)
        #expect(largest.count == SignalFrame.maximumFrameBytes)
    }
}
