//
//  Link.swift
//  ZeroByte — Relay Protocol v1
//
//  One side of a paired link: seals and sends in its own direction, fetches,
//  opens and prunes in the other. Sequence numbers and replay protection are
//  handled here; persist `lastReceived` (and nothing else) between launches.
//

import Foundation

public actor Link {
    public let credentials: Credentials
    /// The direction this side writes; it reads the reverse.
    public let sends: Direction
    private let transport: any RelayTransport
    private var claimed = false
    private var nextSequence: UInt64?
    /// The highest sequence accepted from the other side. Persist it: a
    /// receiver that forgets it would accept a replay of an old envelope.
    public private(set) var lastReceived: UInt64?

    /// - Parameters:
    ///   - credentials: Derived from the link key both devices agreed.
    ///   - sends: `.primaryToCompanion` on one device, `.companionToPrimary`
    ///     on the other.
    ///   - transport: Usually a `Relay`.
    ///   - lastReceived: What `lastReceived` was when the app last ran.
    public init(
        credentials: Credentials, sends: Direction, transport: any RelayTransport,
        lastReceived: UInt64? = nil
    ) {
        self.credentials = credentials
        self.sends = sends
        self.transport = transport
        self.lastReceived = lastReceived
    }

    private func ensureClaimed() async throws {
        guard !claimed else { return }
        try await transport.claim()
        claimed = true
    }

    /// Seals and stores one message. Returns its sequence number.
    @discardableResult
    public func send(_ plaintext: Data) async throws -> UInt64 {
        try await ensureClaimed()
        var sequence = try await nextSequenceToSend()
        for _ in 0..<3 {
            let envelope = try Envelope.seal(
                plaintext, direction: sends, sequence: sequence, credentials: credentials)
            do {
                try await transport.put(envelope, direction: sends, sequence: sequence)
                nextSequence = sequence + 1
                return sequence
            } catch RelayError.sequenceConflict(let last) {
                // Another install of this side wrote meanwhile: continue after it.
                sequence = (last ?? sequence) + 1
            }
        }
        throw RelayError.sequenceConflict(last: sequence - 1)
    }

    private func nextSequenceToSend() async throws -> UInt64 {
        if let nextSequence { return nextSequence }
        return (try await transport.lastSequence(direction: sends) ?? 0) + 1
    }

    /// Fetches everything the other side wrote since `lastReceived`, opens it,
    /// and prunes it from the relay. An envelope that fails to open is skipped
    /// and pruned with the rest: it can never open later.
    public func receive() async throws -> [(sequence: UInt64, plaintext: Data)] {
        try await ensureClaimed()
        let direction = sends.reversed
        var received: [(UInt64, Data)] = []
        var cursor = lastReceived
        var seen: UInt64?
        while true {
            let page = try await transport.fetch(direction: direction, after: cursor)
            let before = cursor
            for envelope in page.envelopes {
                if let header = try? Envelope.header(of: envelope) {
                    cursor = max(cursor ?? 0, header.sequence)
                    seen = max(seen ?? 0, header.sequence)
                }
                guard
                    let opened = try? Envelope.open(
                        envelope, direction: direction, after: lastReceived,
                        credentials: credentials)
                else { continue }
                received.append((opened.sequence, opened.plaintext))
                lastReceived = opened.sequence
            }
            // A page that does not move the cursor would repeat forever.
            guard page.more, cursor != before else { break }
        }
        if let seen {
            try await transport.prune(direction: direction, through: seen)
        }
        return received
    }

    /// Deletes the mailbox and everything in it, for both sides. Use when
    /// the devices unpair.
    public func erase() async throws {
        try await transport.erase()
        claimed = false
        nextSequence = nil
    }
}
