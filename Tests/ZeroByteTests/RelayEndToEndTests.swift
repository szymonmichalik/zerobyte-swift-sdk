import Foundation
import Testing

@testable import ZeroByte
import ZeroBytePush

/// Against a running relay:
/// `RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<id> swift test`
@Test(
    "End to end against a real relay",
    .enabled(if: ProcessInfo.processInfo.environment["RELAY_BASE"] != nil))
func endToEndAgainstARealRelay() async throws {
    let environment = ProcessInfo.processInfo.environment
    let base = try #require(environment["RELAY_BASE"].flatMap(URL.init(string:)))
    let app = try #require(environment["RELAY_APP"])
    let credentials = try Credentials(
        linkKey: Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }), linkID: UUID())
    let phone = Link(
        credentials: credentials, sends: .primaryToCompanion,
        transport: Relay(appID: app, credentials: credentials, base: base))
    let laptop = Link(
        credentials: credentials, sends: .companionToPrimary,
        transport: Relay(appID: app, credentials: credentials, base: base))

    #expect(try await phone.send(Data("hello".utf8)) == 1)
    #expect(try await phone.send(Data("again".utf8)) == 2)
    let got = try await laptop.receive()
    #expect(got.map { String(decoding: $0.plaintext, as: UTF8.self) } == ["hello", "again"])
    #expect(try await laptop.receive().isEmpty)
    _ = try await laptop.send(Data("ack".utf8))
    #expect(try await phone.receive().map(\.plaintext) == [Data("ack".utf8)])
    try await phone.erase()
}

/// Against a relay whose app enables `signal` (and optionally `push`):
/// `RELAY_BASE=… RELAY_SIGNAL_APP=<id> swift test`
@Test(
    "Signal and push against a real relay",
    .enabled(if: ProcessInfo.processInfo.environment["RELAY_SIGNAL_APP"] != nil))
func signalAgainstARealRelay() async throws {
    let environment = ProcessInfo.processInfo.environment
    let base = try #require(environment["RELAY_BASE"].flatMap(URL.init(string:)))
    let app = try #require(environment["RELAY_SIGNAL_APP"])
    let credentials = try Credentials(
        linkKey: Data((0..<32).map { _ in UInt8.random(in: .min ... .max) }), linkID: UUID())
    let relay = Relay(appID: app, credentials: credentials, base: base)
    try await relay.claim()

    // Push registration is accepted (sending needs real APNs keys).
    if environment["RELAY_PUSH"] != nil {
        try await relay.registerPush(
            .apns(
                deviceToken: Data(repeating: 0xab, count: 32), environment: .development,
                tag: PushRegistration.randomTag()),
            direction: .primaryToCompanion)
        let laptop = Link(credentials: credentials, sends: .companionToPrimary, transport: relay)
        let phone = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        try await phone.send(Data("wake".utf8), notify: .alert)
        #expect(try await laptop.receive().map(\.plaintext) == [Data("wake".utf8)])
        try await relay.unregisterPush(direction: .primaryToCompanion)
    }

    let primary = relay.signal(sends: .primaryToCompanion)
    let companion = relay.signal(sends: .companionToPrimary)
    var a = await primary.events().makeAsyncIterator()
    var b = await companion.events().makeAsyncIterator()
    #expect(await a.next() == .peer(true))
    #expect(await b.next() == .peer(true))
    try await primary.send(Data("offer".utf8))
    #expect(await b.next() == .message(Data("offer".utf8)))
    try await companion.send(Data("answer".utf8))
    #expect(await a.next() == .message(Data("answer".utf8)))
    await companion.close()
    #expect(await a.next() == .peer(false))
    await primary.close()
    try await relay.erase()
}
