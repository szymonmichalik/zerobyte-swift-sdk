//
//  Envelope.swift
//  ZeroByte — Relay Protocol v1
//
//  `version ‖ direction ‖ sequence(UInt64 BE) ‖ nonce(12) ‖ ciphertext ‖ tag(16)`,
//  sealed with ChaCha20-Poly1305 (RFC 8439). The ten-byte header and the
//  mailbox id are the authenticated data, so neither a relay nor anyone between
//  can move an envelope to another mailbox, flip its direction or renumber it.
//  Each direction has its own key. The nonce is random: a sender that lost its
//  counter (a reinstall) can never reuse a nonce under a key.
//

import CryptoKit
import Foundation

public enum Envelope {
    public static let version: UInt8 = 1
    public static let headerLength = 10
    public static let nonceLength = 12
    public static let tagLength = 16
    public static let overhead = headerLength + nonceLength + tagLength
    public static let maximumPlaintextBytes = 1_048_576
    public static let maximumEnvelopeBytes = maximumPlaintextBytes + overhead

    public static func seal(
        _ plaintext: Data, direction: Direction, sequence: UInt64, credentials: Credentials
    ) throws -> Data {
        try seal(
            plaintext, direction: direction, sequence: sequence, credentials: credentials,
            nonce: ChaChaPoly.Nonce())
    }

    /// The fixed-nonce form exists for known-answer tests only.
    static func seal(
        _ plaintext: Data, direction: Direction, sequence: UInt64, credentials: Credentials,
        nonce: ChaChaPoly.Nonce
    ) throws -> Data {
        guard plaintext.count <= maximumPlaintextBytes else { throw ZeroByteError.tooLarge }
        let header = header(direction: direction, sequence: sequence)
        let box = try ChaChaPoly.seal(
            plaintext, using: credentials.key(for: direction), nonce: nonce,
            authenticating: header + credentials.mailboxID)
        var envelope = header
        envelope.append(contentsOf: nonce)
        envelope.append(box.ciphertext)
        envelope.append(box.tag)
        return envelope
    }

    /// Reads the clear header without opening the envelope: what a relay may
    /// check, and what a receiver uses to order envelopes before opening them.
    public static func header(of envelope: Data) throws -> (direction: Direction, sequence: UInt64) {
        let bytes = [UInt8](envelope.prefix(headerLength))
        guard envelope.count >= overhead, bytes.count == headerLength else {
            throw ZeroByteError.malformedEnvelope
        }
        guard bytes[0] == version else { throw ZeroByteError.unsupportedVersion(bytes[0]) }
        guard let direction = Direction(rawValue: bytes[1]) else {
            throw ZeroByteError.malformedEnvelope
        }
        let sequence = bytes[2..<10].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        return (direction, sequence)
    }

    /// Opens an envelope the other side wrote.
    ///
    /// - Parameters:
    ///   - direction: The direction this receiver reads; anything else is
    ///     refused before decryption.
    ///   - lastSequence: The highest sequence already accepted; an envelope at
    ///     or below it is a replay.
    public static func open(
        _ envelope: Data, direction: Direction, after lastSequence: UInt64?,
        credentials: Credentials
    ) throws -> (sequence: UInt64, plaintext: Data) {
        guard envelope.count <= maximumEnvelopeBytes else { throw ZeroByteError.tooLarge }
        let header = try header(of: envelope)
        guard header.direction == direction else { throw ZeroByteError.wrongDirection }
        if let lastSequence, header.sequence <= lastSequence {
            throw ZeroByteError.replayed(sequence: header.sequence)
        }
        let bytes = Data(envelope)
        let cipherStart = headerLength + nonceLength
        let tagStart = bytes.count - tagLength
        do {
            let box = try ChaChaPoly.SealedBox(
                nonce: ChaChaPoly.Nonce(data: bytes[headerLength..<cipherStart]),
                ciphertext: bytes[cipherStart..<tagStart],
                tag: bytes[tagStart...])
            let plaintext = try ChaChaPoly.open(
                box, using: credentials.key(for: direction),
                authenticating: bytes.prefix(headerLength) + credentials.mailboxID)
            return (header.sequence, plaintext)
        } catch {
            throw ZeroByteError.authenticationFailed
        }
    }

    static func header(direction: Direction, sequence: UInt64) -> Data {
        var data = Data([version, direction.rawValue])
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8(truncatingIfNeeded: sequence >> UInt64(shift)))
        }
        return data
    }
}

/// A fetch response body: `count(UInt32 BE)`, then `length(UInt32 BE) ‖ bytes`
/// per envelope.
public enum Wire {
    public static let maximumCount = 64

    public static func join(_ envelopes: [Data]) -> Data {
        var data = Data()
        append(UInt32(envelopes.count), to: &data)
        for envelope in envelopes {
            append(UInt32(envelope.count), to: &data)
            data.append(envelope)
        }
        return data
    }

    public static func split(_ data: Data) throws -> [Data] {
        let bytes = [UInt8](data)
        var offset = 0
        func read() throws -> Int {
            guard offset + 4 <= bytes.count else { throw RelayError.malformedResponse }
            let value = bytes[offset..<offset + 4].reduce(0) { ($0 << 8) | Int($1) }
            offset += 4
            return value
        }
        let count = try read()
        guard count <= maximumCount else { throw RelayError.malformedResponse }
        var envelopes: [Data] = []
        for _ in 0..<count {
            let length = try read()
            guard length <= Envelope.maximumEnvelopeBytes, offset + length <= bytes.count else {
                throw RelayError.malformedResponse
            }
            envelopes.append(Data(bytes[offset..<offset + length]))
            offset += length
        }
        guard offset == bytes.count else { throw RelayError.malformedResponse }
        return envelopes
    }

    private static func append(_ value: UInt32, to data: inout Data) {
        for shift in stride(from: 24, through: 0, by: -8) {
            data.append(UInt8(truncatingIfNeeded: value >> UInt32(shift)))
        }
    }
}
