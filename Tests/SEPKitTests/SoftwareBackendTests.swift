import XCTest
import CryptoKit
@testable import SEPKit
import OpenPGPKit

/// Software-backend crypto tests. These run everywhere, including CI VMs with no
/// Secure Enclave, and pin the full sign / agree paths.
final class SoftwareBackendTests: XCTestCase {

    /// Reconstruct a CryptoKit ECDSA signature from raw big-endian (r, s) so we
    /// can verify a backend signature against the public key.
    private func p256Signature(r: Data, s: Data) throws -> P256.Signing.ECDSASignature {
        let rawR = try leftPad(r, to: 32)
        let rawS = try leftPad(s, to: 32)
        return try P256.Signing.ECDSASignature(rawRepresentation: rawR + rawS)
    }

    private func publicKey(from point: ECPoint) throws -> P256.Signing.PublicKey {
        try P256.Signing.PublicKey(x963Representation: point.uncompressed)
    }

    func testSoftwareSignVerifyRoundTrip() throws {
        let (backend, rawBlob) = try SoftwareSigningBackend.generate()

        // A known 32-byte SHA-256 digest of a fixed message.
        let message = Data("gpg-sep software backend test vector".utf8)
        let digest = Data(SHA256.hash(data: message))

        let (r, s) = try backend.sign(digest: digest, hash: .sha256)

        // Verify via reconstructed (r, s) against the digest.
        let sig = try p256Signature(r: r, s: s)
        let pub = try publicKey(from: backend.publicPoint)
        XCTAssertTrue(pub.isValidSignature(sig, for: RawDigest32(digest)!),
                      "reconstructed r,s must verify over the exact digest")

        // Cross-check by rebuilding DER and using CryptoKit's DER path.
        let derSig = try P256.Signing.ECDSASignature(rawRepresentation: (try leftPad(r, to: 32)) + (try leftPad(s, to: 32)))
        XCTAssertTrue(pub.isValidSignature(derSig, for: RawDigest32(digest)!))

        // Reload from the persisted (unsealed) blob and sign again; still valid.
        let reloaded = try SoftwareSigningBackend(rawRepresentation: rawBlob)
        XCTAssertEqual(reloaded.publicPoint, backend.publicPoint)
        let (r2, s2) = try reloaded.sign(digest: digest, hash: .sha256)
        XCTAssertTrue(pub.isValidSignature(try p256Signature(r: r2, s: s2), for: RawDigest32(digest)!))
    }

    func testSoftwareSignSHA384AndSHA512() throws {
        let (backend, _) = try SoftwareSigningBackend.generate()
        let pub = try publicKey(from: backend.publicPoint)
        let message = Data("multi-hash test".utf8)

        let d384 = Data(SHA384.hash(data: message))
        let (r3, s3) = try backend.sign(digest: d384, hash: .sha384)
        XCTAssertTrue(pub.isValidSignature(try p256Signature(r: r3, s: s3), for: RawDigest48(d384)!))

        let d512 = Data(SHA512.hash(data: message))
        let (r5, s5) = try backend.sign(digest: d512, hash: .sha512)
        XCTAssertTrue(pub.isValidSignature(try p256Signature(r: r5, s: s5), for: RawDigest64(d512)!))
    }

    func testUnsupportedDigestLengthThrows() throws {
        let (backend, _) = try SoftwareSigningBackend.generate()
        XCTAssertThrowsError(try backend.sign(digest: Data(repeating: 0, count: 20), hash: .sha256)) { error in
            guard case SEPError.unsupportedDigestLength(20) = error else {
                return XCTFail("expected unsupportedDigestLength, got \(error)")
            }
        }
    }

    func testSoftwareECDHSharedSecretMatchesPeer() throws {
        // Our key.
        let (backend, _) = try SoftwareAgreementBackend.generate()

        // Peer (ephemeral) key computed with CryptoKit directly.
        let peerPriv = P256.KeyAgreement.PrivateKey()
        let peerPoint = try ecPoint(fromX963: peerPriv.publicKey.x963Representation)

        // Our backend agrees against the peer's public point.
        let ourX = try backend.sharedSecretX(ephemeral: peerPoint)

        // Peer agrees against our public point; X coordinates must match.
        let ourPub = try P256.KeyAgreement.PublicKey(x963Representation: backend.publicPoint.uncompressed)
        let peerShared = try peerPriv.sharedSecretFromKeyAgreement(with: ourPub)
        let peerX = peerShared.withUnsafeBytes { Data($0) }

        XCTAssertEqual(ourX.count, 32)
        XCTAssertEqual(ourX, peerX, "ECDH shared X must match the counterparty computation")
    }
}
