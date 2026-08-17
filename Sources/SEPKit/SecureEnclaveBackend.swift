import Foundation
import CryptoKit
import LocalAuthentication
import OpenPGPKit

/// ECDSA signing backed by a P-256 key sealed in the Secure Enclave.
///
/// The private key never leaves the enclave; the key material we persist is the
/// opaque `dataRepresentation` sealed blob, which only this machine's SEP can
/// unseal. Signing operates on a caller-supplied precomputed digest.
public struct SecureEnclaveBackend: SigningBackend {
    private let key: SecureEnclave.P256.Signing.PrivateKey
    public let publicPoint: ECPoint

    public init(key: SecureEnclave.P256.Signing.PrivateKey) throws {
        self.key = key
        self.publicPoint = try ecPoint(fromX963: key.publicKey.x963Representation)
    }

    /// Reload from a sealed `dataRepresentation` blob, optionally supplying an
    /// `LAContext` so a Touch ID authentication can be reused within the grace
    /// window.
    public init(dataRepresentation: Data, context: LAContext?) throws {
        let key: SecureEnclave.P256.Signing.PrivateKey
        if let context {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: context)
        } else {
            key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
        }
        try self.init(key: key)
    }

    /// Generate a fresh enclave signing key under `policy`. An optional
    /// `LAContext` is bound so the first use can reuse an existing auth.
    public static func generate(policy: PresencePolicy, context: LAContext?) throws -> (backend: SecureEnclaveBackend, sealedBlob: Data) {
        guard SecureEnclave.isAvailable else { throw SEPError.secureEnclaveUnavailable }
        let accessControl = try SEPAccessControl.make(for: policy)
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl, authenticationContext: context)
        return (try SecureEnclaveBackend(key: key), key.dataRepresentation)
    }

    public func sign(digest: Data, hash: PGPHashAlgorithm) throws -> (r: Data, s: Data) {
        try signRawDigest(key, digest: digest, hash: hash)
    }
}

/// ECDH agreement backed by a P-256 key sealed in the Secure Enclave.
public struct SecureEnclaveAgreementBackend: AgreementBackend {
    private let key: SecureEnclave.P256.KeyAgreement.PrivateKey
    public let publicPoint: ECPoint

    public init(key: SecureEnclave.P256.KeyAgreement.PrivateKey) throws {
        self.key = key
        self.publicPoint = try ecPoint(fromX963: key.publicKey.x963Representation)
    }

    public init(dataRepresentation: Data, context: LAContext?) throws {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        if let context {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: context)
        } else {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
        }
        try self.init(key: key)
    }

    public static func generate(policy: PresencePolicy, context: LAContext?) throws -> (backend: SecureEnclaveAgreementBackend, sealedBlob: Data) {
        guard SecureEnclave.isAvailable else { throw SEPError.secureEnclaveUnavailable }
        let accessControl = try SEPAccessControl.make(for: policy)
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl, authenticationContext: context)
        return (try SecureEnclaveAgreementBackend(key: key), key.dataRepresentation)
    }

    public func sharedSecretX(ephemeral: ECPoint) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeral.uncompressed)
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        // For P-256 the SharedSecret is the 32-byte X coordinate of d*ephemeral,
        // which is exactly what RFC 6637's KDF consumes.
        return shared.withUnsafeBytes { Data($0) }
    }
}
