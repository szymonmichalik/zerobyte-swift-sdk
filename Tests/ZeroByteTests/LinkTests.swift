import Foundation
import Testing

@testable import ZeroByte

/// A relay in memory with the server's rules: increasing sequences per
/// direction, pages of at most 16, prune through a sequence.
actor MemoryRelay: RelayTransport {
    var boxes: [Direction: [(UInt64, Data)]] = [:]
    var last: [Direction: UInt64] = [:]
    var claims = 0
    var prunes: [(Direction, UInt64)] = []

    func claim() async throws { claims += 1 }

    func put(_ envelope: Data, direction: Direction, sequence: UInt64) async throws {
        if let previous = last[direction], sequence <= previous {
            throw RelayError.sequenceConflict(last: previous)
        }
        boxes[direction, default: []].append((sequence, envelope))
        last[direction] = sequence
    }

    func fetch(direction: Direction, after sequence: UInt64?) async throws -> (
        envelopes: [Data], more: Bool
    ) {
        let waiting = (boxes[direction] ?? []).filter { $0.0 > (sequence ?? 0) }
        return (waiting.prefix(16).map(\.1), waiting.count > 16)
    }

    func lastSequence(direction: Direction) async throws -> UInt64? { last[direction] }

    func prune(direction: Direction, through sequence: UInt64) async throws {
        prunes.append((direction, sequence))
        boxes[direction]?.removeAll { $0.0 <= sequence }
    }

    func erase() async throws {
        boxes = [:]
        last = [:]
    }

    /// What a hostile relay or a second writer could do.
    func inject(_ envelope: Data, direction: Direction, sequence: UInt64) {
        boxes[direction, default: []].append((sequence, envelope))
        boxes[direction]!.sort { $0.0 < $1.0 }
        last[direction] = max(last[direction] ?? 0, sequence)
    }
}

@Suite("Link")
struct LinkTests {
    let credentials = try! Vectors.shared.credentials(1)

    @Test("Messages arrive in order, once, and are pruned from the relay")
    func roundTrip() async throws {
        let relay = MemoryRelay()
        let phone = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        let laptop = Link(credentials: credentials, sends: .companionToPrimary, transport: relay)
        for i in 1...20 { try await phone.send(Data("m\(i)".utf8)) }
        let got = try await laptop.receive()
        #expect(got.map(\.sequence) == Array(1...20))
        #expect(got.map { String(decoding: $0.plaintext, as: UTF8.self) } == (1...20).map { "m\($0)" })
        #expect(await relay.boxes[.primaryToCompanion]?.isEmpty == true)
        #expect(try await laptop.receive().isEmpty)
        #expect(await laptop.lastReceived == 20)
        // One prune for the batch, none for the empty receive.
        #expect(await relay.prunes.map(\.1) == [20])

        try await laptop.send(Data("ack".utf8))
        #expect(try await phone.receive().map(\.plaintext) == [Data("ack".utf8)])
    }

    @Test("A restarted sender continues after the relay's last sequence")
    func restart() async throws {
        let relay = MemoryRelay()
        let first = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        try await first.send(Data("a".utf8))
        let again = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        #expect(try await again.send(Data("b".utf8)) == 2)
    }

    @Test("A sender that lost a race for a sequence moves past it")
    func conflict() async throws {
        let relay = MemoryRelay()
        let a = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        let b = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        try await a.send(Data("a1".utf8))
        try await b.send(Data("b2".utf8))
        #expect(try await a.send(Data("a3".utf8)) == 3)
    }

    @Test("Forged and replayed envelopes are dropped; the real ones still arrive")
    func hostileRelay() async throws {
        let relay = MemoryRelay()
        let phone = Link(credentials: credentials, sends: .primaryToCompanion, transport: relay)
        let laptop = Link(
            credentials: credentials, sends: .companionToPrimary, transport: relay, lastReceived: 1)
        let other = try Vectors.shared.credentials(0)
        let forged = try Envelope.seal(
            Data("forged".utf8), direction: .primaryToCompanion, sequence: 3, credentials: other)
        let old = try Envelope.seal(
            Data("old".utf8), direction: .primaryToCompanion, sequence: 1, credentials: credentials)
        try await phone.send(Data("x".utf8))  // 1, already received per lastReceived
        try await phone.send(Data("real".utf8))  // 2
        await relay.inject(forged, direction: .primaryToCompanion, sequence: 3)
        await relay.inject(old, direction: .primaryToCompanion, sequence: 4)
        let got = try await laptop.receive()
        #expect(got.map(\.plaintext) == [Data("real".utf8)])
        #expect(await laptop.lastReceived == 2)
        // Nothing the forger wrote can be received later either.
        #expect(try await laptop.receive().isEmpty)
    }

    @Test("The endpoint is built from the base URL")
    func endpoint() {
        let relay = Relay(
            appID: "01a1601b-fa85-7d58-b2a2-1416e0a6b054", credentials: credentials,
            base: URL(string: "https://relay.example.com/v1/")!)
        #expect(
            relay.mailbox.absoluteString
                == "https://relay.example.com/v1/01a1601b-fa85-7d58-b2a2-1416e0a6b054/mailbox/"
                + credentials.mailboxName)
    }
}
