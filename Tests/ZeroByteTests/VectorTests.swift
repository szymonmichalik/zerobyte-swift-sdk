import CryptoKit
import Foundation
import Testing

@testable import ZeroByte

// Known answers from the independent reference (zerobyte-protocol, spec/vectors.py),
// copied as relay-v1.json. Never regenerate them from this package.

struct Vectors: Decodable {
    struct Set: Decodable {
        let linkKey, linkId, mailbox, bearer, tokenDigest, p2cKey, c2pKey: String
    }
    struct Sealed: Decodable {
        let credentials: Int
        let direction: UInt8
        let sequence, nonce, plaintext, envelope: String
    }
    struct Rejection: Decodable {
        let credentials: Int
        let direction: UInt8
        let after: String?
        let envelope, error, why: String
    }
    struct WireCase: Decodable {
        let envelopes: [String]
        let body: String
    }
    struct WireRejection: Decodable {
        let body, why: String
    }
    let credentials: [Set]
    let envelopes: [Sealed]
    let rejections: [Rejection]
    let wire: [WireCase]
    let wireRejections: [WireRejection]

    static let shared: Vectors = {
        let url = Bundle.module.url(forResource: "relay-v1", withExtension: "json")!
        return try! JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url))
    }()

    func credentials(_ index: Int) throws -> Credentials {
        try Credentials(
            linkKey: hex(credentials[index].linkKey), linkID: hex(credentials[index].linkId))
    }
}

func hex(_ string: String) -> Data {
    var data = Data()
    var index = string.startIndex
    while index < string.endIndex {
        let next = string.index(index, offsetBy: 2)
        data.append(UInt8(string[index..<next], radix: 16)!)
        index = next
    }
    return data
}

@Suite("Protocol vectors")
struct VectorTests {
    let v = Vectors.shared

    @Test("Credentials match every vector set")
    func credentials() throws {
        for (index, set) in v.credentials.enumerated() {
            let c = try v.credentials(index)
            #expect(c.mailboxName == set.mailbox)
            #expect(c.bearerToken == set.bearer)
            #expect(c.tokenDigest == set.tokenDigest)
            #expect(c.p2cKey == hex(set.p2cKey))
            #expect(c.c2pKey == hex(set.c2pKey))
        }
    }

    @Test("A UUID link id derives the same as its 16 bytes")
    func uuidLinkID() throws {
        let set = v.credentials[0]
        let uuid = UUID(uuidString: "6F1C2A3B-4D5E-4F60-8172-93A4B5C6D7E8")!
        let c = try Credentials(linkKey: hex(set.linkKey), linkID: uuid)
        #expect(c.mailboxName == set.mailbox)
    }

    @Test("Sealing with the vector nonce gives the vector envelope, and it opens")
    func envelopes() throws {
        for e in v.envelopes {
            let c = try v.credentials(e.credentials)
            let direction = Direction(rawValue: e.direction)!
            let sequence = UInt64(e.sequence)!
            let sealed = try Envelope.seal(
                hex(e.plaintext), direction: direction, sequence: sequence, credentials: c,
                nonce: ChaChaPoly.Nonce(data: hex(e.nonce)))
            #expect(sealed == hex(e.envelope))
            let opened = try Envelope.open(
                hex(e.envelope), direction: direction, after: nil, credentials: c)
            #expect(opened.sequence == sequence)
            #expect(opened.plaintext == hex(e.plaintext))
        }
    }

    @Test("Every rejection vector is refused with its error")
    func rejections() throws {
        for r in v.rejections {
            let c = try v.credentials(r.credentials)
            let error = #expect(throws: ZeroByteError.self, "\(r.why)") {
                try Envelope.open(
                    hex(r.envelope), direction: Direction(rawValue: r.direction)!,
                    after: r.after.flatMap(UInt64.init), credentials: c)
            }
            let code: String =
                switch error {
                case .authenticationFailed: "authentication_failed"
                case .wrongDirection: "wrong_direction"
                case .replayed: "replayed"
                case .unsupportedVersion: "unsupported_version"
                case .malformedEnvelope: "malformed"
                default: "other"
                }
            #expect(code == r.error, "\(r.why)")
        }
    }

    @Test("Fetch bodies join and split as the vectors say")
    func wire() throws {
        for w in v.wire {
            #expect(Wire.join(w.envelopes.map(hex)) == hex(w.body))
            #expect(try Wire.split(hex(w.body)) == w.envelopes.map(hex))
        }
        for w in v.wireRejections {
            #expect(throws: RelayError.malformedResponse, "\(w.why)") {
                try Wire.split(hex(w.body))
            }
        }
    }

    @Test("Keys of the wrong size are refused; plaintext over 1 MiB is refused")
    func limits() throws {
        #expect(throws: ZeroByteError.invalidKey) {
            try Credentials(linkKey: Data(count: 31), linkID: Data(count: 16))
        }
        #expect(throws: ZeroByteError.invalidKey) {
            try Credentials(linkKey: Data(count: 32), linkID: Data(count: 15))
        }
        let c = try v.credentials(0)
        #expect(throws: ZeroByteError.tooLarge) {
            try Envelope.seal(
                Data(count: Envelope.maximumPlaintextBytes + 1), direction: .primaryToCompanion,
                sequence: 1, credentials: c)
        }
    }
}
