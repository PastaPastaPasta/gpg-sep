import Foundation
import CryptoKit
import OpenPGPKit

// TEST / CI ONLY.
//
// The GitHub macOS runners are VMs with no Secure Enclave, so the enclave paths
// cannot be exercised there. These software backends persist the private key
// UNSEALED (raw representation) so the same generate/reload/sign/agree logic can
// run without hardware. They MUST NOT be used to hold real OpenPGP keys — a
// software key defeats the entire point of gpg-sep.

/// ECDSA signing with a plain, unsealed CryptoKit P-256 key. Test/CI only.
public struct SoftwareSigningBackend: SigningBackend {
    private let key: P256.Signing.PrivateKey
    public let publicPoint: ECPoint

    public init(key: P256.Signing.PrivateKey) throws {
        self.key = key
        self.publicPoint = try ecPoint(fromX963: key.publicKey.x963Representation)
    }

    /// Reload from the raw (unsealed) private-key representation.
    public init(rawRepresentation: Data) throws {
        try self.init(key: P256.Signing.PrivateKey(rawRepresentation: rawRepresentation))
    }

    /// Generate a fresh software signing key. Returns the raw private key bytes
    /// to persist (unsealed — test/CI only).
    public static func generate() throws -> (backend: SoftwareSigningBackend, rawBlob: Data) {
        let key = P256.Signing.PrivateKey()
        return (try SoftwareSigningBackend(key: key), key.rawRepresentation)
    }

    public func sign(digest: Data, hash: PGPHashAlgorithm) throws -> (r: Data, s: Data) {
        try signRawDigest(key, digest: digest, hash: hash)
    }
}

/// ECDH agreement with a plain, unsealed CryptoKit P-256 key. Test/CI only.
public struct SoftwareAgreementBackend: AgreementBackend {
    private let key: P256.KeyAgreement.PrivateKey
    public let publicPoint: ECPoint

    public init(key: P256.KeyAgreement.PrivateKey) throws {
        self.key = key
        self.publicPoint = try ecPoint(fromX963: key.publicKey.x963Representation)
    }

    public init(rawRepresentation: Data) throws {
        try self.init(key: P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation))
    }

    public static func generate() throws -> (backend: SoftwareAgreementBackend, rawBlob: Data) {
        let key = P256.KeyAgreement.PrivateKey()
        return (try SoftwareAgreementBackend(key: key), key.rawRepresentation)
    }

    public func sharedSecretX(ephemeral: ECPoint) throws -> Data {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: ephemeral.uncompressed)
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        return shared.withUnsafeBytes { Data($0) }
    }
}
