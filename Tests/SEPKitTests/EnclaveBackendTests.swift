import XCTest
import CryptoKit
@testable import SEPKit
import OpenPGPKit

/// Real Secure Enclave tests. These are guarded by `SecureEnclave.isAvailable`
/// and `XCTSkip` when it is absent (e.g. GitHub macOS VMs). On Apple Silicon
/// with a real SEP they generate enclave-held keys with `PresencePolicy.none`
/// (so no interactive Touch ID prompt blocks the suite) and verify signing,
/// persistence across a fresh reload, and ECDH.
final class EnclaveBackendTests: XCTestCase {

    private func requireSEP() throws {
        try XCTSkipUnless(SecureEnclave.isAvailable, "Secure Enclave unavailable on this host")
    }

    private func p256Signature(r: Data, s: Data) throws -> P256.Signing.ECDSASignature {
        try P256.Signing.ECDSASignature(rawRepresentation: (try leftPad(r, to: 32)) + (try leftPad(s, to: 32)))
    }

    func testEnclaveSignVerifyAndReloadPersistence() throws {
        try requireSEP()

        let (backend, sealed) = try SecureEnclaveBackend.generate(policy: .none, context: nil)
        let pub = try P256.Signing.PublicKey(x963Representation: backend.publicPoint.uncompressed)

        let digest = Data(SHA256.hash(data: Data("enclave sign test".utf8)))
        let (r, s) = try backend.sign(digest: digest, hash: .sha256)
        XCTAssertTrue(pub.isValidSignature(try p256Signature(r: r, s: s), for: RawDigest32(digest)!),
                      "enclave signature must verify over the exact digest")

        // Reload the sealed blob into a fresh backend and sign again.
        let reloaded = try SecureEnclaveBackend(dataRepresentation: sealed, context: nil)
        XCTAssertEqual(reloaded.publicPoint, backend.publicPoint,
                       "reloaded enclave key must have the same public point")
        let (r2, s2) = try reloaded.sign(digest: digest, hash: .sha256)
        XCTAssertTrue(pub.isValidSignature(try p256Signature(r: r2, s: s2), for: RawDigest32(digest)!))
    }

    func testEnclaveSignThroughKeyStorePersistsAcrossFreshStore() throws {
        try requireSEP()

        let root = try makeTempRoot()
        defer { try? FileManager.default.removeItem(at: root) }

        let store = KeyStore(root: root)
        let policy = KeyPolicy(presence: .none, graceSeconds: 0)
        let record = try store.generateSigningKey(policy: policy, label: "enclave-store-test", creationTime: 1_700_000_000, forceSoftware: false)
        XCTAssertEqual(record.backend, BackendKind.secureEnclave)

        let digest = Data(SHA256.hash(data: Data("store sign test".utf8)))

        // Sign through a brand-new KeyStore instance pointed at the same root.
        let freshStore = KeyStore(root: root)
        let backend = try freshStore.signingBackend(keygripHex: record.keygripHex, context: nil)
        let (r, s) = try backend.sign(digest: digest, hash: .sha256)
        let pub = try P256.Signing.PublicKey(x963Representation: record.point.uncompressed)
        XCTAssertTrue(pub.isValidSignature(try p256Signature(r: r, s: s), for: RawDigest32(digest)!))
    }

    func testEnclaveECDHRoundTrip() throws {
        try requireSEP()

        let (backend, sealed) = try SecureEnclaveAgreementBackend.generate(policy: .none, context: nil)

        // Ephemeral peer.
        let peer = P256.KeyAgreement.PrivateKey()
        let peerPoint = try ecPoint(fromX963: peer.publicKey.x963Representation)

        let ourX = try backend.sharedSecretX(ephemeral: peerPoint)

        let ourPub = try P256.KeyAgreement.PublicKey(x963Representation: backend.publicPoint.uncompressed)
        let peerX = (try peer.sharedSecretFromKeyAgreement(with: ourPub)).withUnsafeBytes { Data($0) }
        XCTAssertEqual(ourX.count, 32)
        XCTAssertEqual(ourX, peerX, "enclave ECDH shared X must match the peer")

        // Reload and confirm the shared secret is stable.
        let reloaded = try SecureEnclaveAgreementBackend(dataRepresentation: sealed, context: nil)
        let reloadedX = try reloaded.sharedSecretX(ephemeral: peerPoint)
        XCTAssertEqual(reloadedX, ourX)
    }

    private func makeTempRoot() throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("sepkit-test-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}
