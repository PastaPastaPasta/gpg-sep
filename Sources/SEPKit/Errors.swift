import Foundation

/// Errors raised by SEPKit backends and the key store.
public enum SEPError: Error, Equatable, CustomStringConvertible {
    /// The Secure Enclave is not available on this host (e.g. a CI VM). Callers
    /// should fall back to the software backend or skip enclave paths.
    case secureEnclaveUnavailable
    /// A raw digest handed to `sign` was not a supported width (32/48/64 bytes
    /// for SHA-256/384/512).
    case unsupportedDigestLength(Int)
    /// `SecAccessControlCreateWithFlags` failed for the requested policy.
    case accessControlCreationFailed(String)
    /// No record exists in the store for the requested keygrip.
    case keyNotFound(String)
    /// A record's backend string did not match a known backend.
    case unknownBackend(String)
    /// A record's stored role did not match the requested operation
    /// (e.g. asking for a signing backend on an encryption key).
    case roleMismatch(expected: String, got: String)
    /// A stored public point could not be reconstructed into a valid key.
    case invalidStoredKey(String)

    public var description: String {
        switch self {
        case .secureEnclaveUnavailable:
            return "the Secure Enclave is not available on this host"
        case .unsupportedDigestLength(let n):
            return "unsupported digest length \(n) (expected 32, 48, or 64 bytes)"
        case .accessControlCreationFailed(let m):
            return "failed to create SecAccessControl: \(m)"
        case .keyNotFound(let g):
            return "no key found for keygrip \(g)"
        case .unknownBackend(let b):
            return "unknown backend \"\(b)\""
        case .roleMismatch(let e, let g):
            return "key role mismatch: expected \(e), got \(g)"
        case .invalidStoredKey(let m):
            return "invalid stored key: \(m)"
        }
    }
}
