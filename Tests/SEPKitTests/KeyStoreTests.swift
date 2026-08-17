import XCTest
import CryptoKit
@testable import SEPKit
import OpenPGPKit

final class KeyStoreTests: XCTestCase {
    private var root: URL!

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sepkit-store-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        if let root { try? FileManager.default.removeItem(at: root) }
    }

    func testGenerateStoreReloadAndKeygripAlignment() throws {
        let store = KeyStore(root: root)
        let policy = KeyPolicy(presence: .none, graceSeconds: 15)
        let record = try store.generateSigningKey(policy: policy, label: "sig", creationTime: 1_700_000_000, forceSoftware: true)

        XCTAssertEqual(record.backend, BackendKind.software)
        XCTAssertEqual(record.role, .signing)
        XCTAssertEqual(record.pointX.count, 32)
        XCTAssertEqual(record.pointY.count, 32)

        // Keygrip in the record must equal what OpenPGPKit computes for the point.
        let packet = PGPPublicKeyPacket(creationTime: 1_700_000_000, algorithm: .ecdsa, point: record.point)
        XCTAssertEqual(record.keygripHex, packet.keygrip.hexUpper,
                       "store keygrip must match OpenPGPKit's PGPPublicKeyPacket.keygrip")

        // Round-trip through disk with a fresh store.
        let fresh = KeyStore(root: root)
        let loaded = try XCTUnwrap(try fresh.record(keygripHex: record.keygripHex))
        XCTAssertEqual(loaded, record)

        // Case-insensitive lookup.
        XCTAssertNotNil(try fresh.record(keygripHex: record.keygripHex.lowercased()))

        // allRecords finds it.
        let all = try fresh.allRecords()
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all.first, record)
    }

    func testEncryptionKeyUsesECDHAlgorithmForKeygrip() throws {
        let store = KeyStore(root: root)
        let record = try store.generateEncryptionKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: "enc", creationTime: 1_700_000_000, forceSoftware: true)
        XCTAssertEqual(record.role, .encryption)
        let packet = PGPPublicKeyPacket(creationTime: 1_700_000_000, algorithm: .ecdh, point: record.point)
        XCTAssertEqual(record.keygripHex, packet.keygrip.hexUpper)
    }

    func testSigningBackendRoleMismatchThrows() throws {
        let store = KeyStore(root: root)
        let enc = try store.generateEncryptionKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: "enc", creationTime: 1_700_000_000, forceSoftware: true)
        XCTAssertThrowsError(try store.signingBackend(keygripHex: enc.keygripHex, context: nil)) { error in
            guard case SEPError.roleMismatch = error else {
                return XCTFail("expected roleMismatch, got \(error)")
            }
        }
    }

    func testKeyNotFoundThrows() throws {
        let store = KeyStore(root: root)
        XCTAssertThrowsError(try store.signingBackend(keygripHex: "DEADBEEF", context: nil)) { error in
            guard case SEPError.keyNotFound = error else {
                return XCTFail("expected keyNotFound, got \(error)")
            }
        }
    }

    func testDeleteRemovesRecord() throws {
        let store = KeyStore(root: root)
        let record = try store.generateSigningKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: "sig", creationTime: 1_700_000_000, forceSoftware: true)
        XCTAssertNotNil(try store.record(keygripHex: record.keygripHex))
        try store.delete(keygripHex: record.keygripHex)
        XCTAssertNil(try store.record(keygripHex: record.keygripHex))
    }

    func testFilePermissionsAreRestrictive() throws {
        let store = KeyStore(root: root)
        let record = try store.generateSigningKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: "sig", creationTime: 1_700_000_000, forceSoftware: true)
        let url = root.appendingPathComponent("keys/\(record.keygripHex).json")
        let attrs = try FileManager.default.attributesOfItem(atPath: url.path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let dirAttrs = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent("keys").path)
        XCTAssertEqual((dirAttrs[.posixPermissions] as? NSNumber)?.intValue, 0o700)
    }

    func testGPGSepHomeOverride() throws {
        setenv("GPG_SEP_HOME", root.path, 1)
        defer { unsetenv("GPG_SEP_HOME") }
        XCTAssertEqual(KeyStore.defaultRoot().path, root.path)
    }

    // MARK: - H1: keygrip validation / path-traversal defense

    func testNormalizedKeygripAcceptsOnly40Hex() {
        XCTAssertNil(KeyStore.normalizedKeygrip("../../foo"))
        XCTAssertNil(KeyStore.normalizedKeygrip("../EVIL"))
        XCTAssertNil(KeyStore.normalizedKeygrip("xyz"))
        XCTAssertNil(KeyStore.normalizedKeygrip(String(repeating: "a", count: 39))) // short
        XCTAssertNil(KeyStore.normalizedKeygrip(String(repeating: "a", count: 41))) // long
        XCTAssertNil(KeyStore.normalizedKeygrip("")) // empty
        let good = String(repeating: "aB0", count: 13) + "a" // 40 hex, mixed case
        XCTAssertEqual(KeyStore.normalizedKeygrip(good), good.uppercased())
    }

    /// Reproduces the reviewer's planted-record attack: a foreign, perfectly
    /// valid record placed OUTSIDE the keys directory must never be reachable via
    /// a traversal keygrip, and must never be used to sign.
    func testTraversalKeygripCannotLoadOrSignOutOfStoreRecord() throws {
        let store = KeyStore(root: root)
        // A legitimate key, both to create the keys dir and to clone as bait.
        let legit = try store.generateSigningKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: "legit", creationTime: 1_700_000_000, forceSoftware: true)

        // Plant that record one level ABOVE keys/, at <root>/EVIL.json, which the
        // pre-fix `recordURL` would have resolved for the grip "../EVIL".
        let planted = root.appendingPathComponent("EVIL.json")
        let legitURL = root.appendingPathComponent("keys/\(legit.keygripHex).json")
        try FileManager.default.copyItem(at: legitURL, to: planted)
        XCTAssertTrue(FileManager.default.fileExists(atPath: planted.path))

        // The malformed grip is rejected at the store boundary: no load, no sign.
        XCTAssertNil(try store.record(keygripHex: "../EVIL"))
        XCTAssertNil(try store.record(keygripHex: "../../foo"))
        XCTAssertThrowsError(try store.signingBackend(keygripHex: "../EVIL", context: nil)) { error in
            guard case SEPError.keyNotFound = error else {
                return XCTFail("expected keyNotFound for a traversal grip, got \(error)")
            }
        }
    }

    // MARK: - LOW: corrupt-record reporting

    func testLoadRecordsReportsUndecodableFiles() throws {
        let store = KeyStore(root: root)
        _ = try store.generateSigningKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: "ok", creationTime: 1_700_000_000, forceSoftware: true)
        // Drop a corrupt JSON file into the keys dir.
        let bad = root.appendingPathComponent("keys/deadbeef.json")
        try Data("{ not valid json".utf8).write(to: bad)

        let (records, errors) = try store.loadRecords()
        XCTAssertEqual(records.count, 1, "the good record still loads")
        XCTAssertEqual(errors.count, 1, "the corrupt file is reported, not silently dropped")
        XCTAssertTrue(errors[0].contains("deadbeef.json"), errors[0])
    }

    func testSigningBackendFromSoftwareRecordSigns() throws {
        let store = KeyStore(root: root)
        let record = try store.generateSigningKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: "sig", creationTime: 1_700_000_000, forceSoftware: true)
        let backend = try store.signingBackend(keygripHex: record.keygripHex, context: nil)
        let digest = Data(SHA256.hash(data: Data("hi".utf8)))
        let (r, s) = try backend.sign(digest: digest, hash: .sha256)
        let pub = try P256.Signing.PublicKey(x963Representation: record.point.uncompressed)
        let sig = try P256.Signing.ECDSASignature(rawRepresentation: (try leftPad(r, to: 32)) + (try leftPad(s, to: 32)))
        XCTAssertTrue(pub.isValidSignature(sig, for: RawDigest32(digest)!))
    }
}
