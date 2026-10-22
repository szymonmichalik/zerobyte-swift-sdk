//
//  Relay.swift
//  ZeroByte — Relay Protocol v1
//
//  The HTTPS side: a quota-bound mailbox that files opaque envelopes by
//  mailbox, direction and sequence, checks one bearer token against the
//  SHA-256 it stored at the claim, and tells watchers that something arrived.
//  Ephemeral session: no cookies, no cache, no credential store.
//

import Foundation

public enum RelayError: Error, Equatable, Sendable {
    /// 401 or 403: the mailbox is not claimed, or belongs to another token.
    case unauthorized
    /// 409: the sequence is at or below the last one stored.
    case sequenceConflict(last: UInt64?)
    /// 402, 413 or 507: the app's plan is used up, the envelope is too large or
    /// the mailbox is full.
    case quotaExceeded
    /// 429: too many requests for this mailbox. Nothing was stored; retry
    /// after the given number of seconds.
    case rateLimited(retryAfter: TimeInterval?)
    case unavailable(status: Int)
    case malformedResponse
}

/// Whether a write should wake the reader with a push, on relays and apps
/// that have push enabled. Elsewhere it is ignored.
public enum Notify: String, Sendable, Hashable {
    /// No push.
    case none
    /// A visible notification the reader's notification service extension
    /// replaces with the decrypted message.
    case alert
    /// A background push.
    case silent
}

/// Where envelopes go. A protocol so code built on it can be tested in memory.
public protocol RelayTransport: Sendable {
    /// Claims the mailbox for this token, or confirms the claim; idempotent.
    func claim() async throws
    func put(_ envelope: Data, direction: Direction, sequence: UInt64) async throws
    /// Stores one envelope and asks the relay to wake the reader.
    func put(_ envelope: Data, direction: Direction, sequence: UInt64, notify: Notify) async throws
    /// Envelopes after `sequence`, oldest first, and whether more are waiting.
    func fetch(direction: Direction, after sequence: UInt64?) async throws -> (
        envelopes: [Data], more: Bool
    )
    /// The highest sequence stored in a direction, or nil when none was.
    func lastSequence(direction: Direction) async throws -> UInt64?
    /// Drops a direction's envelopes up to and including `sequence`.
    func prune(direction: Direction, through sequence: UInt64) async throws
    /// Deletes the mailbox and everything in it.
    func erase() async throws
}

extension RelayTransport {
    /// A transport without push stores the envelope and ignores `notify`.
    public func put(
        _ envelope: Data, direction: Direction, sequence: UInt64, notify: Notify
    ) async throws {
        try await put(envelope, direction: direction, sequence: sequence)
    }
}

/// Where the relay sends pushes for one direction. Register on the direction
/// the device reads.
///
/// The relay knows push services as separate modules; this type carries the
/// generic part and the service's own fields as they are. For APNs, use the
/// `ZeroBytePush` library: `PushRegistration.apns(deviceToken:environment:tag:)`.
public struct PushRegistration: Sendable, Hashable {
    /// The push service, as the relay names its module: `apns`, for example.
    public var service: String
    /// The service's own fields, such as the device token.
    public var fields: [String: String]
    /// 1-64 of `A-Z a-z 0-9 _ -`. Comes back in the push as
    /// `userInfo["zerobyte"]["tag"]` so the app can find the link. Make it
    /// random per link: the push service sees it.
    public var tag: String
    /// The placeholder text of a visible notification, at most 160
    /// characters, shown if the app cannot decrypt in time.
    public var alert: String?

    public init(service: String, fields: [String: String], tag: String, alert: String? = nil) {
        self.service = service
        self.fields = fields
        self.tag = tag
        self.alert = alert
    }

    /// A fresh random tag.
    public static func randomTag() -> String {
        Data((0..<16).map { _ in UInt8.random(in: .min ... .max) }).base64URLEncoded
    }

    /// The request body: the service's fields, then the generic members.
    public var json: Data {
        var object = fields
        object["service"] = service
        object["tag"] = tag
        object["alert"] = alert
        return (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    }
}

/// One STUN or TURN server, in the shape of WebRTC's `RTCIceServer`.
public struct ICEServer: Sendable, Hashable, Decodable {
    public let urls: [String]
    public let username: String?
    public let credential: String?
}

/// Servers for a direct connection, and how long their credentials last.
public struct ICEConfiguration: Sendable, Hashable, Decodable {
    public let iceServers: [ICEServer]
    /// Seconds.
    public let ttl: Int
}

public struct Relay: RelayTransport {
    /// One response carries at most this many envelopes.
    public static let fetchLimit = 16

    /// How often watch and signal sockets send `ping`. Keeps NATs open and
    /// tells the relay this reader is awake, so it sends no push.
    public static let keepAliveInterval: Duration = .seconds(30)

    public let endpoint: URL
    let credentials: Credentials
    let session: URLSession

    /// - Parameters:
    ///   - appID: Your registered app id (a UUIDv7).
    ///   - credentials: The link's credentials.
    ///   - base: Your relay's `/v1/` URL, with the trailing slash.
    public init(appID: String, credentials: Credentials, base: URL) {
        self.init(endpoint: base.appending(path: appID + "/"), credentials: credentials)
    }

    /// - Parameter endpoint: The full `https://<relay>/v1/<app id>/` URL.
    public init(endpoint: URL, credentials: Credentials) {
        self.endpoint = endpoint
        self.credentials = credentials
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.waitsForConnectivity = false
        session = URLSession(configuration: configuration)
    }

    var mailbox: URL {
        endpoint.appending(path: "mailbox").appending(path: credentials.mailboxName)
    }

    func request(_ url: URL, method: String) -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(credentials.bearerToken)", forHTTPHeaderField: "Authorization")
        return request
    }

    private func send(_ request: URLRequest, body: Data? = nil) async throws -> (
        Data, HTTPURLResponse
    ) {
        let (data, response) =
            if let body {
                try await session.upload(for: request, from: body)
            } else {
                try await session.data(for: request)
            }
        guard let http = response as? HTTPURLResponse else { throw RelayError.malformedResponse }
        switch http.statusCode {
        case 200..<300: return (data, http)
        case 401, 403: throw RelayError.unauthorized
        case 409:
            throw RelayError.sequenceConflict(
                last: http.value(forHTTPHeaderField: "X-Relay-Last").flatMap(UInt64.init))
        case 402, 413, 507: throw RelayError.quotaExceeded
        case 429:
            throw RelayError.rateLimited(
                retryAfter: http.value(forHTTPHeaderField: "Retry-After").flatMap(TimeInterval.init))
        default: throw RelayError.unavailable(status: http.statusCode)
        }
    }

    public func claim() async throws {
        var request = request(mailbox, method: "PUT")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        _ = try await send(
            request, body: Data(#"{"tokenDigest":"\#(credentials.tokenDigest)"}"#.utf8))
    }

    public func put(_ envelope: Data, direction: Direction, sequence: UInt64) async throws {
        try await put(envelope, direction: direction, sequence: sequence, notify: .none)
    }

    public func put(
        _ envelope: Data, direction: Direction, sequence: UInt64, notify: Notify
    ) async throws {
        var request = request(
            mailbox.appending(path: direction.pathComponent).appending(path: String(sequence)),
            method: "PUT")
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        if notify != .none { request.setValue(notify.rawValue, forHTTPHeaderField: "X-Relay-Notify") }
        _ = try await send(request, body: envelope)
    }

    /// Asks the relay to wake this device when the other side writes to
    /// `direction` with `notify`. Register on the direction you read, after
    /// every launch (device tokens change). Needs `push` enabled for the app.
    public func registerPush(_ registration: PushRegistration, direction: Direction) async throws {
        var request = request(
            mailbox.appending(path: direction.pathComponent).appending(path: "push"), method: "PUT")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        _ = try await send(request, body: registration.json)
    }

    public func unregisterPush(direction: Direction) async throws {
        _ = try await send(
            request(
                mailbox.appending(path: direction.pathComponent).appending(path: "push"),
                method: "DELETE"))
    }

    /// STUN and TURN servers for a direct connection. Needs `ice` enabled.
    public func iceServers() async throws -> ICEConfiguration {
        let (data, _) = try await send(request(mailbox.appending(path: "ice"), method: "GET"))
        do {
            return try JSONDecoder().decode(ICEConfiguration.self, from: data)
        } catch {
            throw RelayError.malformedResponse
        }
    }

    /// A rendezvous with the other device. See `SignalChannel`.
    public func signal(sends direction: Direction) -> SignalChannel {
        SignalChannel(relay: self, sends: direction)
    }

    func webSocket(_ url: URL) -> URLSessionWebSocketTask {
        var components = URLComponents(url: url, resolvingAgainstBaseURL: false)!
        components.scheme = components.scheme == "http" ? "ws" : "wss"
        var request = request(components.url!, method: "GET")
        request.setValue("zerobyte.v1", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        let task = session.webSocketTask(with: request)
        task.maximumMessageSize = 1 << 17
        return task
    }

    public func fetch(direction: Direction, after sequence: UInt64?) async throws -> (
        envelopes: [Data], more: Bool
    ) {
        var url = mailbox.appending(path: direction.pathComponent)
        url.append(queryItems: [
            URLQueryItem(name: "after", value: String(sequence ?? 0)),
            URLQueryItem(name: "limit", value: String(Self.fetchLimit)),
        ])
        let (data, response) = try await send(request(url, method: "GET"))
        return (try Wire.split(data), response.value(forHTTPHeaderField: "X-Relay-More") == "1")
    }

    public func lastSequence(direction: Direction) async throws -> UInt64? {
        let (_, response) = try await send(
            request(mailbox.appending(path: direction.pathComponent), method: "HEAD"))
        return response.value(forHTTPHeaderField: "X-Relay-Last").flatMap(UInt64.init)
    }

    public func prune(direction: Direction, through sequence: UInt64) async throws {
        var url = mailbox.appending(path: direction.pathComponent)
        url.append(queryItems: [URLQueryItem(name: "through", value: String(sequence))])
        _ = try await send(request(url, method: "DELETE"))
    }

    public func erase() async throws {
        _ = try await send(request(mailbox, method: "DELETE"))
    }

    /// Sequence numbers as the other side writes them. The socket carries no
    /// data: the receiver still fetches and opens envelopes, so the relay
    /// learns nothing new from it. The stream ends when the socket closes;
    /// reconnect with backoff and fetch on reconnect. While it is open the
    /// relay sends no push for this direction.
    public func watch(direction: Direction) -> AsyncStream<UInt64> {
        let task = webSocket(
            mailbox.appending(path: direction.pathComponent).appending(path: "watch"))
        return AsyncStream { continuation in
            let keepAlive = Task {
                while !Task.isCancelled {
                    try? await task.send(.string("ping"))
                    try? await Task.sleep(for: Self.keepAliveInterval)
                }
            }
            continuation.onTermination = { _ in
                keepAlive.cancel()
                task.cancel(with: .goingAway, reason: nil)
            }
            task.resume()
            Task {
                while true {
                    guard case .string(let text)? = try? await task.receive() else { break }
                    // "pong" is not a number and is skipped.
                    if let sequence = UInt64(text) { continuation.yield(sequence) }
                }
                keepAlive.cancel()
                continuation.finish()
            }
        }
    }
}
