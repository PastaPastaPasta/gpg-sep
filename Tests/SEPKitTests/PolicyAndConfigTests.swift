import XCTest
import Security
@testable import SEPKit

final class PolicyAndConfigTests: XCTestCase {

    // MARK: PresencePolicy -> SecAccessControlCreateFlags mapping

    func testAccessControlFlagMapping() {
        XCTAssertEqual(SEPAccessControl.flags(for: .none), [.privateKeyUsage])
        XCTAssertEqual(SEPAccessControl.flags(for: .presence), [.privateKeyUsage, .userPresence])
        XCTAssertEqual(SEPAccessControl.flags(for: .biometry), [.privateKeyUsage, .biometryAny])
        XCTAssertEqual(SEPAccessControl.flags(for: .biometryCurrentSet), [.privateKeyUsage, .biometryCurrentSet])
    }

    func testAccessControlObjectConstructsWithoutPrompting() throws {
        // Constructing a SecAccessControl only encodes policy; it never prompts.
        for policy in [PresencePolicy.none, .presence, .biometry, .biometryCurrentSet] {
            XCTAssertNoThrow(try SEPAccessControl.make(for: policy),
                             "policy \(policy.rawValue) must produce a SecAccessControl")
        }
    }

    // MARK: Config

    func testConfigDefaults() {
        let c = Config()
        XCTAssertEqual(c.defaultPolicy.presence, .presence)
        XCTAssertEqual(c.defaultPolicy.graceSeconds, 15)
    }

    func testConfigLoadMissingReturnsDefaults() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sepkit-cfg-\(UUID().uuidString)", isDirectory: true)
        let c = try Config.load(root: root)
        XCTAssertEqual(c, Config())
    }

    func testConfigSaveLoadRoundTrip() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("sepkit-cfg-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }

        var c = Config()
        c.defaultPolicy = KeyPolicy(presence: .biometry, graceSeconds: 30)
        try c.save(root: root)

        let loaded = try Config.load(root: root)
        XCTAssertEqual(loaded, c)

        // File is 0600.
        let attrs = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent("config.json").path)
        XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testGPGSepConfigOverride() {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("cfgroot", isDirectory: true)
        setenv("GPG_SEP_CONFIG", root.path, 1)
        defer { unsetenv("GPG_SEP_CONFIG") }
        XCTAssertEqual(Config.defaultConfigRoot().path, root.path)
    }

    // MARK: AuthSession grace window

    func testAuthSessionReusesSharedContextWithinGrace() {
        let session = AuthSession(defaultGraceSeconds: 15)
        let a = session.context()
        let b = session.context()
        XCTAssertTrue(a === b, "within the grace window the same LAContext is reused")
        XCTAssertEqual(a.touchIDAuthenticationAllowableReuseDuration, 15)
    }

    func testAuthSessionZeroGraceForcesFreshContext() {
        let session = AuthSession(defaultGraceSeconds: 15)
        // A per-key override of 0 must force a brand-new context each call.
        let a = session.context(graceSeconds: 0)
        let b = session.context(graceSeconds: 0)
        XCTAssertFalse(a === b, "graceSeconds 0 must force per-signature auth (fresh context)")
        XCTAssertEqual(a.touchIDAuthenticationAllowableReuseDuration, 0)
    }

    func testAuthSessionInvalidateDropsSharedContext() {
        let session = AuthSession(defaultGraceSeconds: 15)
        let a = session.context()
        session.invalidate()
        let b = session.context()
        XCTAssertFalse(a === b, "after invalidate a fresh context is issued")
    }

    // MARK: - Manual-check note (NOT automated)
    //
    // The presence-required Touch ID path is intentionally not asserted here: a
    // key created with PresencePolicy.presence/.biometry prompts interactively
    // and would hang CI. To exercise it by hand:
    //
    //   let (b, _) = try SecureEnclaveBackend.generate(policy: .presence, context: nil)
    //   _ = try b.sign(digest: Data(SHA256.hash(data: Data("touch".utf8))), hash: .sha256)
    //
    // A Touch ID prompt should appear. The `gpg-sep doctor` command drives this
    // as an opt-in on-metal check.
}
