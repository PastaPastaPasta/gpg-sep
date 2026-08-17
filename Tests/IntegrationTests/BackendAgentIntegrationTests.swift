import Foundation
import XCTest
import AssuanKit
@testable import GPGSepDaemonCore

/// Integration tests for the managed backend agent's home mirroring (M4) and its
/// restart-on-death path (C1 part 2). Everything runs in ephemeral `/tmp` homes;
/// only agents rooted at those unique paths are ever killed.
final class BackendAgentIntegrationTests: XCTestCase {
    private var homes: [String] = []

    override func tearDownWithError() throws {
        if FileManager.default.isExecutableFile(atPath: "/usr/bin/pkill") {
            for home in homes {
                _ = ProxyIntegrationTests.run("/usr/bin/pkill", ["-f", "gpg-agent --homedir \(home)"])
            }
        }
        for home in homes { try? FileManager.default.removeItem(atPath: home) }
        homes.removeAll()
    }

    private func mkTmp(_ prefix: String) throws -> String {
        let path = "/tmp/\(prefix)" + String(UInt32.random(in: 0..<0xFFFF_FFFF), radix: 16)
        try FileManager.default.createDirectory(
            atPath: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        homes.append(path)
        return path
    }

    private func tools() throws -> (gpg: String, gpgAgent: String, gpgconf: String) {
        guard let gpg = ProxyIntegrationTests.toolPath("gpg"),
              let gpgAgent = ProxyIntegrationTests.toolPath("gpg-agent"),
              let gpgconf = ProxyIntegrationTests.toolPath("gpgconf") else {
            throw XCTSkip("gpg toolchain is not installed")
        }
        return (gpg, gpgAgent, gpgconf)
    }

    // MARK: - M4: keys generated through the backend land in the REAL home

    func testGeneratedSecretKeyLandsInRealHomeNotBackendHome() throws {
        let (gpg, gpgAgent, gpgconf) = try tools()
        let realHome = try mkTmp("gsr")     // note: NO private-keys-v1.d created here
        let backendHome = try mkTmp("gsb")
        try "allow-loopback-pinentry\n".write(
            toFile: backendHome + "/gpg-agent.conf", atomically: true, encoding: .utf8)

        let backend = BackendAgent(
            backendHome: URL(fileURLWithPath: backendHome),
            realGnupgHome: URL(fileURLWithPath: realHome),
            gpgAgentPath: gpgAgent, gpgconfPath: gpgconf)
        try backend.start()
        defer { backend.stop() }

        // The store dir was auto-created in the REAL home and linked, not created
        // standalone inside the backend home.
        let backendStore = backendHome + "/private-keys-v1.d"
        let realStore = realHome + "/private-keys-v1.d"
        let linkDest = try FileManager.default.destinationOfSymbolicLink(atPath: backendStore)
        XCTAssertEqual(linkDest, realStore, "backend private-keys-v1.d must symlink to the real home")
        var isDir: ObjCBool = false
        XCTAssertTrue(FileManager.default.fileExists(atPath: realStore, isDirectory: &isDir) && isDir.boolValue,
                      "the real home's private-keys-v1.d must have been created")

        // Generate a key THROUGH the backend agent; its secret must physically
        // land in the real home's store via the symlink.
        let gen = ProxyIntegrationTests.run(gpg, [
            "--homedir", backendHome, "--batch", "--pinentry-mode", "loopback",
            "--passphrase", "", "--quick-gen-key", "Mirror <m@x.tld>", "nistp256", "sign", "never"])
        XCTAssertEqual(gen.status, 0, "backend keygen failed: \(gen.out)")

        let realKeys = (try? FileManager.default.contentsOfDirectory(atPath: realStore))?
            .filter { $0.hasSuffix(".key") } ?? []
        XCTAssertFalse(realKeys.isEmpty,
                       "the generated secret key must be stored in the REAL home, not stranded in the backend home")
    }

    // MARK: - C1 part 2: ensureRunning restarts a dead backend

    func testEnsureRunningRestartsAKilledBackend() throws {
        let (_, gpgAgent, gpgconf) = try tools()
        let realHome = try mkTmp("gsr")
        let backendHome = try mkTmp("gsb")

        let backend = BackendAgent(
            backendHome: URL(fileURLWithPath: backendHome),
            realGnupgHome: URL(fileURLWithPath: realHome),
            gpgAgentPath: gpgAgent, gpgconfPath: gpgconf)
        try backend.start()
        defer { backend.stop() }
        let socket = try XCTUnwrap(backend.socketPath)

        // Live before the kill.
        XCTAssertNoThrow(try AssuanConnection.connect(toUnixSocket: socket).close())

        // Kill it, then let ensureRunning bring it back.
        backend.stop()
        // Give the agent a moment to actually exit.
        usleep(300_000)
        backend.ensureRunning()

        let resolved = try AssuanSocketRedirection.resolve(try XCTUnwrap(backend.socketPath))
        let client = try AssuanClient.connect(toSocket: resolved)
        defer { client.connection.close() }
        XCTAssertTrue(try client.transact("GETINFO version").isOK,
                      "ensureRunning must restart a killed backend so forwards work again")
    }
}
