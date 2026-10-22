//
//  APNs.swift
//  ZeroBytePush — the APNs side of the relay's push extension
//
//  A separate library: an app that does not use Apple push notifications
//  links only `ZeroByte`. This one builds APNs registrations for the relay's
//  APNs module and reads what a ZeroByte push carries.
//

import Foundation
import ZeroByte

/// Which APNs host the relay sends to. Debug builds signed with a development
/// provisioning profile get development tokens.
public enum APNsEnvironment: String, Sendable, Hashable {
    case production, development
}

extension PushRegistration {
    /// A registration for the relay's APNs module.
    ///
    /// - Parameters:
    ///   - deviceToken: The token from
    ///     `application(_:didRegisterForRemoteNotificationsWithDeviceToken:)`.
    ///   - environment: `.development` for debug builds, else `.production`.
    ///   - tag: Comes back in the push. Random per link: Apple sees it.
    ///   - alert: The visible text if the notification service extension
    ///     cannot replace it in time.
    public static func apns(
        deviceToken: Data, environment: APNsEnvironment, tag: String, alert: String? = nil
    ) -> PushRegistration {
        PushRegistration(
            service: "apns",
            fields: [
                "token": deviceToken.map { String(format: "%02x", $0) }.joined(),
                "environment": environment.rawValue,
            ],
            tag: tag, alert: alert)
    }
}

/// What a ZeroByte push carries, read from a notification's `userInfo`.
public enum ZeroBytePushPayload {
    /// The tag registered for the link, or nil when the notification is not
    /// from a ZeroByte relay. Look the link up by it, then `receive()`.
    public static func tag(in userInfo: [AnyHashable: Any]) -> String? {
        guard let zerobyte = userInfo["zerobyte"] as? [String: Any],
            let tag = zerobyte["tag"] as? String,
            !tag.isEmpty, tag.count <= 64,
            tag.unicodeScalars.allSatisfy({
                ("A"..."Z").contains($0) || ("a"..."z").contains($0)
                    || ("0"..."9").contains($0) || $0 == "_" || $0 == "-"
            })
        else { return nil }
        return tag
    }
}
