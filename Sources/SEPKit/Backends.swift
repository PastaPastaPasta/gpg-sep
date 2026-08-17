import Foundation
import CryptoKit
import OpenPGPKit

// MARK: - Policy

/// Presence / authentication requirement for using a key. Maps to
/// `SecAccessControlCreateFlags` at enclave-key creation time.
public enum PresencePolicy: String, Codable {
    /// No user interaction required to sign/decrypt.
    case none
    /// Any enrolled user-presence factor (Touch ID or device password).
    case presence
    /// Any currently enrolled biometric (Touch ID). Does not survive to password.
    case biometry
    /// Currently enrolled biometric set. WARNING: adding/removing a fingerprint
    /// permanently invalidates the key (`.biometryCurrentSet`).
    case biometryCurrentSet
}

/// Per-key policy: the presence requirement plus the Touch ID grace window
/// (seconds) during which a prior authentication is reused. `graceSeconds == 0`
/// forces authentication on every signature.
public struct KeyPolicy: Codable, Equatable {
    public var presence: PresencePolicy
    public var graceSeconds: Int

    public init(presence: PresencePolicy, graceSeconds: Int) {
        self.presence = presence
        self.graceSeconds = graceSeconds
    }
}

// PresencePolicy is Equatable for tests/config comparison.
extension PresencePolicy: Equatable {}

// MARK: - Backend protocols

/// A backend that produces raw ECDSA `(r, s)` signatures over a *precomputed*
/// digest. Implementations MUST sign the supplied digest bytes directly and must
/// not re-hash.
public protocol SigningBackend {
    /// The public point of the signing key (`0x04 || X || Y` split into X/Y).
    var publicPoint: ECPoint { get }
    /// Sign the raw `digest` (already the output of `hash`). Returns raw
    /// big-endian `(r, s)`; OpenPGP MPI encoding re-derives exact bit lengths.
    func sign(digest: Data, hash: PGPHashAlgorithm) throws -> (r: Data, s: Data)
}

/// A backend that performs raw ECDH: returns the 32-byte X coordinate of
/// `d * ephemeral`. The RFC 6637 KDF and AES key-unwrap are the OpenPGP layer's
/// responsibility, not this backend's.
public protocol AgreementBackend {
    var publicPoint: ECPoint { get }
    func sharedSecretX(ephemeral: ECPoint) throws -> Data
}

// MARK: - Precomputed-digest signing

/// A concrete `Digest` conformer wrapping a raw big-endian hash of a fixed
/// width. CryptoKit's `signature(for: some Digest)` signs these bytes directly
/// (for P-256 it truncates to the leftmost 256 bits, per FIPS 186), so wrapping
/// gpg's precomputed digest lets us sign it without re-hashing.
struct RawDigest32: Digest {
    static var byteCount: Int { 32 }
    let bytes: [UInt8]
    init?(_ data: Data) { guard data.count == 32 else { return nil }; bytes = [UInt8](data) }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    static func == (l: RawDigest32, r: RawDigest32) -> Bool { l.bytes == r.bytes }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
}

struct RawDigest48: Digest {
    static var byteCount: Int { 48 }
    let bytes: [UInt8]
    init?(_ data: Data) { guard data.count == 48 else { return nil }; bytes = [UInt8](data) }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    static func == (l: RawDigest48, r: RawDigest48) -> Bool { l.bytes == r.bytes }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
}

struct RawDigest64: Digest {
    static var byteCount: Int { 64 }
    let bytes: [UInt8]
    init?(_ data: Data) { guard data.count == 64 else { return nil }; bytes = [UInt8](data) }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    static func == (l: RawDigest64, r: RawDigest64) -> Bool { l.bytes == r.bytes }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
}

/// Abstracts the shared `signature(for:)` surface of CryptoKit's software and
/// Secure Enclave P-256 signing keys so the raw-digest dispatch below is written
/// once for both.
protocol RawDigestSigner {
    func rawDERSignature<D: Digest>(for digest: D) throws -> Data
}

extension P256.Signing.PrivateKey: RawDigestSigner {
    func rawDERSignature<D: Digest>(for digest: D) throws -> Data {
        try signature(for: digest).derRepresentation
    }
}

extension SecureEnclave.P256.Signing.PrivateKey: RawDigestSigner {
    func rawDERSignature<D: Digest>(for digest: D) throws -> Data {
        try signature(for: digest).derRepresentation
    }
}

/// Sign a raw precomputed digest with the given signer, dispatching on the
/// digest width to the matching `Digest` conformer, and return raw `(r, s)`.
func signRawDigest(_ signer: RawDigestSigner, digest: Data, hash: PGPHashAlgorithm) throws -> (r: Data, s: Data) {
    let der: Data
    switch digest.count {
    case 32:
        der = try signer.rawDERSignature(for: RawDigest32(digest)!)
    case 48:
        der = try signer.rawDERSignature(for: RawDigest48(digest)!)
    case 64:
        der = try signer.rawDERSignature(for: RawDigest64(digest)!)
    default:
        throw SEPError.unsupportedDigestLength(digest.count)
    }
    return try ecdsaDERToRawRS(der)
}

// MARK: - Public point extraction

/// Split a SEC1/X9.63 uncompressed point (`0x04 || X || Y`, 65 bytes) into an
/// `ECPoint`.
func ecPoint(fromX963 rep: Data) throws -> ECPoint {
    guard rep.count == 65, rep.first == 0x04 else {
        throw SEPError.invalidStoredKey("expected 65-byte uncompressed point")
    }
    let x = rep.subdata(in: (rep.startIndex + 1)..<(rep.startIndex + 33))
    let y = rep.subdata(in: (rep.startIndex + 33)..<(rep.startIndex + 65))
    return try ECPoint(validatingX: x, y: y)
}
