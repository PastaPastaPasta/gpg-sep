import Darwin
import Foundation
import XCTest
import AssuanKit
import OpenPGPKit
import SEPKit
@testable import GPGSepDaemonCore

/// In-process unit tests for the routing/consent logic in ``SepProxyHandler``,
/// driven over a socket pair with a real software-backed key store and no gpg.
/// These cover H1 (keygrip validation), H3 (Touch ID consent text), M5 (KEYINFO
/// fields), M7 (HAVEKEY --list bound) and the C1 KILLAGENT interception.
final class SepProxyHandlerUnitTests: XCTestCase {
    private var roots: [URL] = []

    override func tearDownWithError() throws {
        for r in roots { try? FileManager.default.removeItem(at: r) }
        roots.removeAll()
    }

    private func makeStore() throws -> KeyStore {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sepproxy-\(UUID().uuidString)", isDirectory: true)
        roots.append(root)
        return KeyStore(root: root)
    }

    @discardableResult
    private func addSigningKey(_ store: KeyStore, label: String = "t") throws -> EnclaveKeyRecord {
        try store.generateSigningKey(
            policy: KeyPolicy(presence: .none, graceSeconds: 0),
            label: label, creationTime: 1_700_000_000, forceSoftware: true)
    }

    /// Run a handler on a background thread and return a client plus the handler.
    private func runHandler(
        store: KeyStore, auth: AuthSession = AuthSession(defaultGraceSeconds: 0),
        backend: AssuanClient? = nil, peerPID: pid_t? = 4242
    ) throws -> (client: AssuanClient, handler: SepProxyHandler) {
        let (serverSide, clientSide) = try AssuanConnection.makePair()
        let handler = SepProxyHandler(
            keyStore: store, authSession: auth, backend: backend, peerProcessID: peerPID)
        let server = AssuanServer(client: serverSide, handler: handler, backend: backend?.connection)
        let thread = Thread { try? server.run() }
        thread.start()
        let client = AssuanClient(connection: clientSide)
        try client.readGreeting()
        return (client, handler)
    }

    /// 32-byte SHA-256 digest, hex-encoded, for SETHASH.
    private let digestHex = String(repeating: "AB", count: 32)

    // MARK: - H1: keygrip validation at the protocol boundary

    func testMalformedSelectKeyIsForwardedNotHandledLocally() throws {
        let store = try makeStore()
        let rec = try addSigningKey(store)
        // No backend: a forwarded command returns ERR (no agent), which proves it
        // was NOT treated as one of our keys.
        let (client, _) = try runHandler(store: store, backend: nil)
        defer { client.connection.close() }

        for bad in ["SIGKEY ../../foo", "SIGKEY ../EVIL", "SIGKEY xyz",
                    "SIGKEY \(String(repeating: "a", count: 39))"] {
            let r = try client.transact(bad)
            XCTAssertNotNil(r.error, "\(bad) must be forwarded (malformed grip), not handled locally")
        }
        // A well-formed store grip IS handled locally.
        XCTAssertTrue(try client.transact("SIGKEY \(rec.keygripHex)").isOK)
    }

    func testMalformedSelectionDoesNotSign() throws {
        let store = try makeStore()
        _ = try addSigningKey(store)
        let (client, _) = try runHandler(store: store, backend: nil)
        defer { client.connection.close() }

        _ = try client.transact("SIGKEY ../EVIL")          // forwarded -> ERR
        _ = try client.transact("SETHASH 8 \(digestHex)")  // forwarded -> ERR
        let sign = try client.transact("PKSIGN")
        XCTAssertNotNil(sign.error, "a malformed selection must never produce a signature")
        XCTAssertTrue(sign.data.isEmpty)
    }

    // MARK: - H3: Touch ID prompt carries SETKEYDESC / an attributable reason

    func testSetKeyDescBecomesLocalizedReason() throws {
        let store = try makeStore()
        let rec = try addSigningKey(store)
        let (client, handler) = try runHandler(store: store)
        defer { client.connection.close() }

        // Percent-plus: '+' decodes to a space.
        _ = try client.transact("SETKEYDESC Please+sign+release+v7")
        _ = try client.transact("SIGKEY \(rec.keygripHex)")
        _ = try client.transact("SETHASH 8 \(digestHex)")
        XCTAssertTrue(try client.transact("PKSIGN").isOK)

        XCTAssertEqual(handler.lastLocalizedReason, "Please sign release v7",
                       "the enclave prompt must quote the client's SETKEYDESC")
    }

    func testSynthesizedReasonAttributesToPeerPID() throws {
        let store = try makeStore()
        let rec = try addSigningKey(store, label: "release key")
        let (client, handler) = try runHandler(store: store, peerPID: 4242)
        defer { client.connection.close() }

        _ = try client.transact("SIGKEY \(rec.keygripHex)")
        _ = try client.transact("SETHASH 8 \(digestHex)")
        XCTAssertTrue(try client.transact("PKSIGN").isOK)

        let reason = handler.lastLocalizedReason ?? ""
        XCTAssertFalse(reason.isEmpty, "a non-empty consent reason must always be set")
        XCTAssertTrue(reason.contains("pid 4242"), reason)
        XCTAssertTrue(reason.contains("release key"), reason)
    }

    // MARK: - M5: KEYINFO reports a protected on-disk key (D ... P ...)

    func testKeyInfoReportsProtectedNotClear() throws {
        let store = try makeStore()
        let rec = try addSigningKey(store)
        let (client, _) = try runHandler(store: store)
        defer { client.connection.close() }

        let r = try client.transact("KEYINFO \(rec.keygripHex)")
        XCTAssertTrue(r.isOK)
        let info = r.statuses.first { $0.keyword == "KEYINFO" }
        XCTAssertNotNil(info, "KEYINFO must emit a status line for a store key")
        XCTAssertTrue(info!.args.hasSuffix("D - - - P - - -"),
                      "expected protected on-disk fields, got: \(info!.args)")
    }

    // MARK: - M7: HAVEKEY --list=N must not exceed N

    func testHaveKeyListHonorsRequestedBound() throws {
        let store = try makeStore()
        _ = try addSigningKey(store, label: "k1")
        _ = try addSigningKey(store, label: "k2")
        let (client, _) = try runHandler(store: store, backend: nil)
        defer { client.connection.close() }

        // Two store keys, so an unbounded list returns both (40 bytes).
        XCTAssertEqual(try client.transact("HAVEKEY --list").data.count, 40)
        // --list=1 must return at most one 20-byte keygrip.
        let one = try client.transact("HAVEKEY --list=1")
        XCTAssertTrue(one.isOK)
        XCTAssertLessThanOrEqual(one.data.count, 20, "must not exceed the requested N=1")
        XCTAssertEqual(one.data.count % 20, 0)
    }

    // MARK: - C1: KILLAGENT must not wedge the daemon

    func testKillAgentIsAckedLocallyAndDaemonKeepsSigning() throws {
        let store = try makeStore()
        let rec = try addSigningKey(store)
        // Even with NO backend, KILLAGENT must be acked and SEP signing continue.
        let (client, _) = try runHandler(store: store, backend: nil)
        defer { client.connection.close() }

        XCTAssertTrue(try client.transact("KILLAGENT").isOK,
                      "KILLAGENT must be acked locally, never forwarded into a wedge")

        // The daemon is still alive and signs an enclave key afterwards.
        _ = try client.transact("SIGKEY \(rec.keygripHex)")
        _ = try client.transact("SETHASH 8 \(digestHex)")
        let sign = try client.transact("PKSIGN")
        XCTAssertTrue(sign.isOK, "a SEP signature must still succeed after KILLAGENT")
        XCTAssertFalse(sign.data.isEmpty)
    }
}
