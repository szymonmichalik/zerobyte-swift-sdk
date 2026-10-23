import Foundation
import Testing

@testable import ZeroByte

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
