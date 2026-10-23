//
//  Credentials.swift
//  ZeroByte — Relay Protocol v1 (https://docs.zerobyte.cloud/protocol/)
//
//  Everything one paired link needs to use a relay, derived with HKDF-SHA256
//  (RFC 5869) from the 32-byte link key the two devices agreed when they
//  paired. Both devices derive the same values; only the mailbox name and the
//  bearer token ever leave the device.
//

import CryptoKit
import Foundation

public enum ZeroByteError: Error, Equatable, Sendable {
    /// The link key is not 32 bytes, or the link id not 16.
    case invalidKey
    /// Shorter than the 38-byte overhead, or an unknown direction byte.
    case malformedEnvelope
    case unsupportedVersion(UInt8)
    /// The envelope was written in the other direction.
    case wrongDirection
    /// The envelope's sequence is at or below one already accepted.
    case replayed(sequence: UInt64)
    /// The envelope was altered, or sealed under another link's keys.
    case authenticationFailed
    /// The plaintext is over 1 MiB.
    case tooLarge
}

/// Which side of a link wrote an envelope. The names are the protocol's; what
/// "primary" and "companion" mean is up to the app.
public enum Direction: UInt8, Sendable, Hashable, CaseIterable {
    case primaryToCompanion = 1
    case companionToPrimary = 2

    /// The path segment the relay files the direction under.
    public var pathComponent: String {
        switch self {
        case .primaryToCompanion: "p2c"
        case .companionToPrimary: "c2p"
        }
    }

    /// The direction the other side writes.
    public var reversed: Direction {
        self == .primaryToCompanion ? .companionToPrimary : .primaryToCompanion
    }
}

public struct Credentials: Sendable, Hashable {
    // The labels keep the name of the protocol's first application. They are
    // part of the wire format: changing one is a new protocol version.
    static let mailboxInfo = Data("derived-relay-mailbox-v1".utf8)
    static let tokenInfo = Data("derived-relay-token-v1".utf8)
    static let p2cInfo = Data("derived-relay-p2c-v1".utf8)
    static let c2pInfo = Data("derived-relay-c2p-v1".utf8)

    /// 16 bytes: the only thing the relay files envelopes under.
    public let mailboxID: Data
    /// 32 bytes: the relay keeps its SHA-256, never the token.
    public let accessToken: Data
    let p2cKey: Data
    let c2pKey: Data

    /// - Parameters:
    ///   - linkKey: The 32-byte secret the two devices agreed when they paired.
    ///   - linkID: 16 bytes naming the link, the same on both devices (a UUID
    ///     works). It salts every derivation, so two links never share a
    ///     mailbox even if a key repeated.
    public init(linkKey: Data, linkID: Data) throws {
        guard linkKey.count == 32, linkID.count == 16 else { throw ZeroByteError.invalidKey }
        let key = SymmetricKey(data: linkKey)
        func derive(_ info: Data, _ count: Int) -> Data {
            HKDF<SHA256>.deriveKey(
                inputKeyMaterial: key, salt: linkID, info: info, outputByteCount: count
            ).withUnsafeBytes { Data($0) }
        }
        mailboxID = derive(Self.mailboxInfo, 16)
        accessToken = derive(Self.tokenInfo, 32)
        p2cKey = derive(Self.p2cInfo, 32)
        c2pKey = derive(Self.c2pInfo, 32)
    }

    /// - Parameter linkID: A UUID naming the link, the same on both devices.
    public init(linkKey: Data, linkID: UUID) throws {
        let id = withUnsafeBytes(of: linkID.uuid) { Data($0) }
        try self.init(linkKey: linkKey, linkID: id)
    }

    /// Lowercase hex: the mailbox's name in the relay's URL.
    public var mailboxName: String { mailboxID.lowercaseHex }

    /// Unpadded base64url (RFC 4648 §5) of the access token, for a bearer header.
    public var bearerToken: String { accessToken.base64URLEncoded }

    /// What the relay stores in place of the token: lowercase hex SHA-256.
    public var tokenDigest: String { Data(SHA256.hash(data: accessToken)).lowercaseHex }

    func key(for direction: Direction) -> SymmetricKey {
        SymmetricKey(data: direction == .primaryToCompanion ? p2cKey : c2pKey)
    }
}

extension Data {
    var lowercaseHex: String { map { String(format: "%02x", $0) }.joined() }

    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
