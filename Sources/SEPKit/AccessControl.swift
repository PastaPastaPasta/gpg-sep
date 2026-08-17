import Foundation
import Security

/// Maps a `PresencePolicy` to a `SecAccessControl` used when creating Secure
/// Enclave keys. `.privateKeyUsage` is always required for SEP keys; the
/// presence flags gate whether user authentication is demanded on each use.
///
/// Constructing the object never prompts — it only encodes the policy — so this
/// is safe to unit-test without hardware or interaction.
public enum SEPAccessControl {
    /// Build the `SecAccessControl` for `policy`. Returns the flags used
    /// alongside so callers/tests can assert the mapping.
    public static func flags(for policy: PresencePolicy) -> SecAccessControlCreateFlags {
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        switch policy {
        case .none:
            break
        case .presence:
            flags.insert(.userPresence)
        case .biometry:
            flags.insert(.biometryAny)
        case .biometryCurrentSet:
            flags.insert(.biometryCurrentSet)
        }
        return flags
    }

    /// Create the access-control object for `policy`. Keys are scoped
    /// `WhenUnlockedThisDeviceOnly` — they are non-exportable and never leave
    /// this device regardless.
    public static func make(for policy: PresencePolicy) throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags(for: policy),
            &error
        ) else {
            let msg = (error?.takeRetainedValue()).map { String(describing: $0) } ?? "unknown error"
            throw SEPError.accessControlCreationFailed(msg)
        }
        return ac
    }
}
