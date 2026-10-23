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
    /// 413 or 507: the envelope is too large or the mailbox is full.
    case quotaExceeded
    case unavailable(status: Int)
    case malformedResponse
}

/// Where envelopes go. A protocol so code built on it can be tested in memory.
public protocol RelayTransport: Sendable {
    /// Claims the mailbox for this token, or confirms the claim; idempotent.
    func claim() async throws
    func put(_ envelope: Data, direction: Direction, sequence: UInt64) async throws
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

public struct Relay: RelayTransport {
    /// One response carries at most this many envelopes.
    public static let fetchLimit = 16

    public let endpoint: URL
    private let credentials: Credentials
    private let session: URLSession

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

    private func request(_ url: URL, method: String) -> URLRequest {
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
        case 413, 507: throw RelayError.quotaExceeded
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
        var request = request(
            mailbox.appending(path: direction.pathComponent).appending(path: String(sequence)),
            method: "PUT")
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        _ = try await send(request, body: envelope)
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
    /// reconnect with backoff and fetch on reconnect.
    public func watch(direction: Direction) -> AsyncStream<UInt64> {
        var components = URLComponents(
            url: mailbox.appending(path: direction.pathComponent).appending(path: "watch"),
            resolvingAgainstBaseURL: false)!
        components.scheme = components.scheme == "http" ? "ws" : "wss"
        var request = request(components.url!, method: "GET")
        request.setValue("zerobyte.v1", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        let task = session.webSocketTask(with: request)
        return AsyncStream { continuation in
            continuation.onTermination = { _ in task.cancel(with: .goingAway, reason: nil) }
            task.resume()
            Task {
                while true {
                    guard case .string(let text)? = try? await task.receive() else { break }
                    if let sequence = UInt64(text) { continuation.yield(sequence) }
                }
                continuation.finish()
            }
        }
    }
}
