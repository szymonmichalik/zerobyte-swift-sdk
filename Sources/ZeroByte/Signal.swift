//
//  Signal.swift
//  ZeroByte — Relay Protocol v1, signal extension
//
//  A rendezvous for a direct connection between the two devices of a link:
//  both open `…/signal/<side>`, the relay forwards binary frames from one to
//  the other and says when the other side is there. Use it to swap WebRTC
//  offers, answers and ICE candidates; the heavy traffic then goes device to
//  device. The relay cannot read or forge a frame: each is sealed like an
//  envelope, under signal keys derived from the link key.
//
//  Frame: `version(1) = 0x01 ‖ direction(1) ‖ counter(UInt64 BE) ‖ nonce(12) ‖
//  ciphertext ‖ tag(16)`, ChaCha20-Poly1305, AAD = the 10-byte header ‖
//  mailbox id. The counter is milliseconds since 1970, bumped so it always
//  increases; a receiver refuses a frame at or below the last it accepted,
//  or more than five minutes away from its own clock.
//

import CryptoKit
import Foundation

public enum SignalFrame {
    public static let version: UInt8 = 1
    public static let overhead = Envelope.overhead
    /// The relay forwards frames of at most 64 KiB.
    public static let maximumFrameBytes = 65_536
    public static let maximumPlaintextBytes = maximumFrameBytes - overhead
    /// How far a frame's counter may be from the receiver's clock.
    public static let window: UInt64 = 5 * 60 * 1000

    public static func seal(
        _ plaintext: Data, direction: Direction, counter: UInt64, credentials: Credentials
    ) throws -> Data {
        try seal(
            plaintext, direction: direction, counter: counter, credentials: credentials,
            nonce: ChaChaPoly.Nonce())
    }

    /// The fixed-nonce form exists for known-answer tests only.
    static func seal(
        _ plaintext: Data, direction: Direction, counter: UInt64, credentials: Credentials,
        nonce: ChaChaPoly.Nonce
    ) throws -> Data {
        guard plaintext.count <= maximumPlaintextBytes else { throw ZeroByteError.tooLarge }
        guard counter > 0 else { throw ZeroByteError.malformedEnvelope }
        let header = Envelope.header(direction: direction, sequence: counter)
        let box = try ChaChaPoly.seal(
            plaintext, using: credentials.signalKey(for: direction), nonce: nonce,
            authenticating: header + credentials.mailboxID)
        return header + box.combined
    }

    /// Opens a frame the other side sent to `direction`'s reader.
    public static func open(
        _ frame: Data, direction: Direction, after last: UInt64?, now: UInt64,
        credentials: Credentials
    ) throws -> (counter: UInt64, plaintext: Data) {
        guard frame.count <= maximumFrameBytes else { throw ZeroByteError.tooLarge }
        let header = try Envelope.header(of: frame)
        guard header.direction == direction else { throw ZeroByteError.wrongDirection }
        if let last, header.sequence <= last { throw ZeroByteError.replayed(sequence: header.sequence) }
        let distance = header.sequence > now ? header.sequence - now : now - header.sequence
        guard distance <= window else { throw ZeroByteError.replayed(sequence: header.sequence) }
        let bytes = Data(frame)
        do {
            let box = try ChaChaPoly.SealedBox(
                combined: bytes.dropFirst(Envelope.headerLength))
            let plaintext = try ChaChaPoly.open(
                box, using: credentials.signalKey(for: direction),
                authenticating: bytes.prefix(Envelope.headerLength) + credentials.mailboxID)
            return (header.sequence, plaintext)
        } catch {
            throw ZeroByteError.authenticationFailed
        }
    }

    static func milliseconds(_ date: Date = Date()) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970 * 1000))
    }
}

/// One side of the rendezvous. Call `events()` once to connect, `send(_:)` to
/// talk to the other side, `close()` when the direct connection is up.
public actor SignalChannel {
    public enum Event: Sendable, Equatable {
        /// The other side connected (`true`) or left (`false`).
        case peer(Bool)
        /// A frame from the other side, opened.
        case message(Data)
    }

    public enum Failure: Error, Equatable, Sendable {
        /// `send` before `events()`, or after the socket closed.
        case notConnected
        /// The relay closed the socket: 4000 another connection of this side
        /// replaced it, 1003/1009 a bad frame, 1000 the mailbox was erased.
        case closed(code: Int)
    }

    /// The side this device speaks for: `.primaryToCompanion` is the primary.
    public let sends: Direction
    private let relay: Relay
    private var task: URLSessionWebSocketTask?
    private var lastSent: UInt64 = 0
    private var lastReceived: UInt64?

    init(relay: Relay, sends: Direction) {
        self.relay = relay
        self.sends = sends
    }

    private var side: String { sends == .primaryToCompanion ? "primary" : "companion" }

    /// Connects and yields what the other side does. The stream finishes when
    /// the socket closes; frames that do not open are dropped silently.
    public func events() -> AsyncStream<Event> {
        task?.cancel(with: .goingAway, reason: nil)
        let task = relay.webSocket(
            relay.mailbox.appending(path: "signal").appending(path: side))
        self.task = task
        lastReceived = nil
        let credentials = relay.credentials
        let reads = sends.reversed
        return AsyncStream { continuation in
            let keepAlive = Task {
                while !Task.isCancelled {
                    try? await Task.sleep(for: Relay.keepAliveInterval)
                    try? await task.send(.string("ping"))
                }
            }
            continuation.onTermination = { _ in
                keepAlive.cancel()
                task.cancel(with: .goingAway, reason: nil)
            }
            task.resume()
            Task {
                while true {
                    guard let message = try? await task.receive() else { break }
                    switch message {
                    case .string("peer 1"): continuation.yield(.peer(true))
                    case .string("peer 0"): continuation.yield(.peer(false))
                    case .data(let frame):
                        if let plaintext = self.accept(
                            frame, reads: reads, credentials: credentials)
                        {
                            continuation.yield(.message(plaintext))
                        }
                    default: break
                    }
                }
                keepAlive.cancel()
                continuation.finish()
            }
        }
    }

    private func accept(_ frame: Data, reads: Direction, credentials: Credentials) -> Data? {
        guard
            let opened = try? SignalFrame.open(
                frame, direction: reads, after: lastReceived,
                now: SignalFrame.milliseconds(), credentials: credentials)
        else { return nil }
        lastReceived = opened.counter
        return opened.plaintext
    }

    /// Seals and sends one message, at most `SignalFrame.maximumPlaintextBytes`.
    /// The relay drops it if the other side is not connected: wait for
    /// `.peer(true)` first.
    public func send(_ plaintext: Data) async throws {
        guard let task, task.state == .running else { throw Failure.notConnected }
        let counter = max(lastSent + 1, SignalFrame.milliseconds())
        let frame = try SignalFrame.seal(
            plaintext, direction: sends, counter: counter, credentials: relay.credentials)
        lastSent = counter
        do {
            try await task.send(.data(frame))
        } catch {
            throw Failure.closed(code: task.closeCode.rawValue)
        }
    }

    public func close() {
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
    }
}
