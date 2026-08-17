import Darwin
import Foundation
import XCTest
import AssuanKit
import OpenPGPKit
import SEPKit
@testable import GPGSepDaemonCore

/// End-to-end proof that the proxy routes enclave keygrips to the (software)
/// backend and forwards everything else to a real gpg-agent 2.5.20.
///
/// Everything happens in ephemeral homes under `/tmp` (short paths, because
/// `sun_path` is 104 octets). The software signing/agreement backends stand in
/// for the Secure Enclave so this runs on CI VMs that have no SEP. The user's
/// `~/.gnupg` and running agent are never touched; only agents spawned here are
/// killed.
final class ProxyIntegrationTests: XCTestCase {

    // MARK: Tool discovery

    static func toolPath(_ name: String) -> String? {
        for path in ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)", "/usr/bin/\(name)"]
        where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        return nil
    }

    // MARK: Subprocess helper

    @discardableResult
    static func run(_ tool: String, _ args: [String], input: String? = nil) -> (out: String, status: Int32) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let outPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = outPipe
        if let input {
            let stdin = Pipe()
            p.standardInput = stdin
            try? p.run()
            stdin.fileHandleForWriting.write(Data(input.utf8))
            try? stdin.fileHandleForWriting.close()
        } else {
            p.standardInput = FileHandle.nullDevice
            try? p.run()
        }
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (String(decoding: data, as: UTF8.self), p.terminationStatus)
    }

    // MARK: Fixture

    /// A full proxy stack: a backend gpg-agent in one ephemeral home, a store of
    /// software "enclave" keys, and a `SepAgentServer` bound at a user home's
    /// agent socket.
    final class Fixture {
        let gpg: String
        let gpgAgent: String
        let gpgconf: String

        let userHome: String
        let backendHome: String
        let sepHome: String

        let store: KeyStore
        let signingRecord: EnclaveKeyRecord
        let encryptionRecord: EnclaveKeyRecord
        let primaryFingerprint: String

        let backendSocket: String
        let server: SepAgentServer
        let userSocket: String

        /// A passphrase-protected on-disk key living in the backend agent, to
        /// prove passthrough signing and bidirectional INQUIRE relay.
        let onDiskProtectedFpr: String
        let onDiskPassphrase = "backend-secret-pass"
        /// A passphrase-less on-disk key in the backend, for plain passthrough.
        let onDiskPlainFpr: String

        init(gpg: String, gpgAgent: String, gpgconf: String) throws {
            self.gpg = gpg
            self.gpgAgent = gpgAgent
            self.gpgconf = gpgconf

            func mkTmp(_ prefix: String) throws -> String {
                let path = "/tmp/\(prefix)" + String(UInt32.random(in: 0..<0xFFFF_FFFF), radix: 16)
                try FileManager.default.createDirectory(
                    atPath: path, withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o700])
                return path
            }
            userHome = try mkTmp("gsu")
            backendHome = try mkTmp("gsb")
            sepHome = try mkTmp("gss")

            // Backend agent config: allow loopback pinentry and never cache the
            // passphrase, so a protected-key sign reliably triggers an INQUIRE.
            try """
            allow-loopback-pinentry
            default-cache-ttl 0
            max-cache-ttl 0
            """.write(toFile: backendHome + "/gpg-agent.conf", atomically: true, encoding: .utf8)

            // Two on-disk keys held by the backend agent.
            let plain = ProxyIntegrationTests.run(gpg, [
                "--homedir", backendHome, "--batch", "--pinentry-mode", "loopback",
                "--passphrase", "", "--quick-gen-key", "OnDisk Plain <plain@x.tld>",
                "nistp256", "sign", "never"])
            guard plain.status == 0 else { throw Failure("backend plain keygen failed: \(plain.out)") }

            let prot = ProxyIntegrationTests.run(gpg, [
                "--homedir", backendHome, "--batch", "--pinentry-mode", "loopback",
                "--passphrase", onDiskPassphrase, "--quick-gen-key", "OnDisk Prot <prot@x.tld>",
                "nistp256", "sign", "never"])
            guard prot.status == 0 else { throw Failure("backend protected keygen failed: \(prot.out)") }

            let backendFprs = ProxyIntegrationTests.fingerprints(gpg: gpg, home: backendHome)
            guard backendFprs.count >= 2 else { throw Failure("expected 2 backend keys, got \(backendFprs)") }
            onDiskPlainFpr = backendFprs[0]
            onDiskProtectedFpr = backendFprs[1]

            // Discover the backend agent socket (autostarted by the keygen above).
            let sock = ProxyIntegrationTests.run(gpgconf, [
                "--homedir", backendHome, "--list-dirs", "agent-socket"]).out
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !sock.isEmpty else { throw Failure("no backend agent socket") }
            backendSocket = sock

            // Software "enclave" store keys: a signing primary and an ECDH subkey.
            store = KeyStore(root: URL(fileURLWithPath: sepHome, isDirectory: true))
            let creation = UInt32(1_700_000_000)
            let policy = KeyPolicy(presence: .none, graceSeconds: 0)
            signingRecord = try store.generateSigningKey(
                policy: policy, label: "sep-sign", creationTime: creation, forceSoftware: true)
            encryptionRecord = try store.generateEncryptionKey(
                policy: policy, label: "sep-encr", creationTime: creation, forceSoftware: true)

            // Assemble the transferable public key (primary self-sig + subkey
            // binding), signing with the software backend — the same path the
            // CLI will drive.
            let armored = try Fixture.buildPublicKey(
                store: store, signing: signingRecord, encryption: encryptionRecord,
                uid: "Pasta (SEP test) <sep@x.tld>", creation: creation)
            let primary = PGPPublicKeyPacket(
                creationTime: creation, algorithm: .ecdsa, point: signingRecord.point)
            primaryFingerprint = primary.fingerprint.hexUpperString

            // Import the enclave public key and both backend keys' public halves
            // into the user home.
            let keyFile = userHome + "/sep.asc"
            try armored.write(toFile: keyFile, atomically: true, encoding: .utf8)
            let imp = ProxyIntegrationTests.run(gpg, ["--homedir", userHome, "--import", keyFile])
            guard imp.status == 0 else { throw Failure("import of SEP key failed: \(imp.out)") }

            for fpr in [onDiskPlainFpr, onDiskProtectedFpr] {
                let pub = ProxyIntegrationTests.run(gpg, [
                    "--homedir", backendHome, "--armor", "--export", fpr]).out
                let f = userHome + "/\(fpr).asc"
                try pub.write(toFile: f, atomically: true, encoding: .utf8)
                _ = ProxyIntegrationTests.run(gpg, ["--homedir", userHome, "--import", f])
            }

            // Bind the proxy at the user home's standard agent socket.
            userSocket = ProxyIntegrationTests.run(gpgconf, [
                "--homedir", userHome, "--list-dirs", "agent-socket"]).out
                .trimmingCharacters(in: .whitespacesAndNewlines)
            guard !userSocket.isEmpty else { throw Failure("no user agent socket path") }

            let auth = AuthSession(defaultGraceSeconds: 0)
            let backend = BackendAgent(existingSocketPath: backendSocket)
            try backend.start()
            server = try SepAgentServer(
                standardSocketPath: userSocket, keyStore: store,
                authSession: auth, backendSocketPath: backendSocket)
            server.startInBackground()
        }

        func gpgUser(_ args: [String], input: String? = nil) -> (out: String, status: Int32) {
            ProxyIntegrationTests.run(gpg, ["--homedir", userHome] + args, input: input)
        }

        func tearDown() {
            server.stop()
            _ = ProxyIntegrationTests.run(gpgconf, ["--homedir", backendHome, "--kill", "all"])
            // gpg may have autostarted a stock agent against the user home
            // alongside our proxy; kill only the agents rooted at our ephemeral
            // homes (the paths are unique, so this touches nothing else).
            if FileManager.default.isExecutableFile(atPath: "/usr/bin/pkill") {
                for home in [userHome, backendHome] {
                    _ = ProxyIntegrationTests.run("/usr/bin/pkill", ["-f", "gpg-agent --homedir \(home)"])
                }
            }
            for dir in [userHome, backendHome, sepHome] {
                try? FileManager.default.removeItem(atPath: dir)
            }
        }

        struct Failure: Error, CustomStringConvertible {
            let message: String
            init(_ m: String) { message = m }
            var description: String { message }
        }

        /// Build the armored transferable public key, self-certifying the UID and
        /// binding the ECDH subkey, all signed by the software signing backend.
        static func buildPublicKey(
            store: KeyStore, signing: EnclaveKeyRecord, encryption: EnclaveKeyRecord,
            uid: String, creation: UInt32
        ) throws -> String {
            let signer = try store.signingBackend(keygripHex: signing.keygripHex, context: nil)
            let primary = PGPPublicKeyPacket(
                creationTime: creation, algorithm: .ecdsa, point: signing.point)
            let uidPacket = PGPUserIDPacket(uid)

            let certBuilder = PGPSignatureBuilder(
                type: .positiveCertification, hashAlgorithm: .sha256, signingKeyAlgorithm: .ecdsa)
            certBuilder.addHashed(.signatureCreationTime(creation))
            certBuilder.addHashed(.keyFlags([.certify, .sign]))
            certBuilder.addHashed(.preferredHashAlgorithms([.sha256, .sha384, .sha512]))
            certBuilder.addHashed(.issuerFingerprint(primary.fingerprint))
            certBuilder.addUnhashed(.issuerKeyID(primary.keyID))
            let cert = try certBuilder.build(over: .certification(primary: primary, userID: uidPacket)) {
                digest, hash in try signer.sign(digest: digest, hash: hash)
            }

            let subkey = PGPPublicKeyPacket(
                creationTime: creation, algorithm: .ecdh, point: encryption.point)
            let bindBuilder = PGPSignatureBuilder(
                type: .subkeyBinding, hashAlgorithm: .sha256, signingKeyAlgorithm: .ecdsa)
            bindBuilder.addHashed(.signatureCreationTime(creation))
            bindBuilder.addHashed(.keyFlags([.encryptCommunications, .encryptStorage]))
            bindBuilder.addHashed(.issuerFingerprint(primary.fingerprint))
            bindBuilder.addUnhashed(.issuerKeyID(primary.keyID))
            let binding = try bindBuilder.build(over: .subkey(primary: primary, subkey: subkey)) {
                digest, hash in try signer.sign(digest: digest, hash: hash)
            }

            let tpk = PGPTransferablePublicKey(
                primary: primary,
                userIDs: [.init(userID: uidPacket, certification: cert)],
                subkeys: [.init(subkey: subkey, binding: binding)])
            return tpk.armored()
        }
    }

    static func fingerprints(gpg: String, home: String) -> [String] {
        let out = run(gpg, ["--homedir", home, "--list-keys", "--with-colons"]).out
        return out.split(separator: "\n").compactMap { line -> String? in
            let f = line.split(separator: ":", omittingEmptySubsequences: false)
            guard f.count > 9, f[0] == "fpr" else { return nil }
            return String(f[9])
        }
    }

    // MARK: Harness

    func withFixture(_ body: (Fixture) throws -> Void) throws {
        guard let gpg = Self.toolPath("gpg"),
              let gpgAgent = Self.toolPath("gpg-agent"),
              let gpgconf = Self.toolPath("gpgconf") else {
            throw XCTSkip("gpg toolchain is not installed")
        }
        let fixture = try Fixture(gpg: gpg, gpgAgent: gpgAgent, gpgconf: gpgconf)
        defer { fixture.tearDown() }
        try body(fixture)
    }

    // MARK: 1. Signing round-trip (enclave + passthrough)

    func testEnclaveSigningRoundTrip() throws {
        try withFixture { fx in
            let doc = fx.userHome + "/doc.txt"
            try "sign me through the enclave\n".write(toFile: doc, atomically: true, encoding: .utf8)

            // Sign with the SEP primary (routes SIGKEY/PKSIGN to the store key).
            let sign = fx.gpgUser([
                "--batch", "--yes", "-u", fx.primaryFingerprint,
                "--detach-sign", "-o", doc + ".sig", doc])
            XCTAssertEqual(sign.status, 0, "enclave detach-sign failed: \(sign.out)")

            let verify = fx.gpgUser(["--verify", doc + ".sig", doc])
            XCTAssertEqual(verify.status, 0, "verify of enclave signature failed: \(verify.out)")
            XCTAssertTrue(verify.out.contains("Good signature"), verify.out)
        }
    }

    func testPassthroughOnDiskSigning() throws {
        try withFixture { fx in
            let doc = fx.userHome + "/passthrough.txt"
            try "sign me via the backend\n".write(toFile: doc, atomically: true, encoding: .utf8)

            // Passphrase-less on-disk key: pure forward to the backend agent.
            let sign = fx.gpgUser([
                "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", "",
                "-u", fx.onDiskPlainFpr, "--detach-sign", "-o", doc + ".sig", doc])
            XCTAssertEqual(sign.status, 0, "passthrough sign failed: \(sign.out)")

            let verify = fx.gpgUser(["--verify", doc + ".sig", doc])
            XCTAssertEqual(verify.status, 0, "verify of passthrough signature failed: \(verify.out)")
            XCTAssertTrue(verify.out.contains("Good signature"), verify.out)
        }
    }

    // MARK: 2. `gpg -K` visibility

    func testSecretKeyListingSeesEnclaveKey() throws {
        try withFixture { fx in
            let listing = fx.gpgUser(["-K", "--with-keygrip"])
            XCTAssertEqual(listing.status, 0, "gpg -K failed: \(listing.out)")
            XCTAssertTrue(listing.out.contains(fx.primaryFingerprint),
                          "enclave key not shown as secret:\n\(listing.out)")
            // The signing keygrip must appear as an available secret key.
            XCTAssertTrue(listing.out.uppercased().contains(fx.signingRecord.keygripHex.uppercased()),
                          "signing keygrip missing from -K:\n\(listing.out)")
        }
    }

    // MARK: 3. Decryption round-trip (RFC 6637)

    func testEnclaveDecryptionRoundTrip() throws {
        try withFixture { fx in
            let secret = "the enclave decrypt secret 4242"
            let enc = fx.gpgUser([
                "--batch", "--yes", "--trust-model", "always",
                "--encrypt", "-r", fx.primaryFingerprint, "-o", fx.userHome + "/msg.gpg"],
                input: secret)
            XCTAssertEqual(enc.status, 0, "encrypt to enclave subkey failed: \(enc.out)")

            let dec = fx.gpgUser(["--batch", "--yes", "--decrypt", fx.userHome + "/msg.gpg"])
            XCTAssertEqual(dec.status, 0, "decrypt through proxy failed: \(dec.out)")
            XCTAssertTrue(dec.out.contains(secret),
                          "recovered plaintext missing; got:\n\(dec.out)")
        }
    }

    // MARK: 4. Bidirectional INQUIRE passthrough

    func testBackendInquireRelay() throws {
        try withFixture { fx in
            let doc = fx.userHome + "/inquire.txt"
            try "trigger a passphrase inquiry\n".write(toFile: doc, atomically: true, encoding: .utf8)

            // A protected backend key with an empty passphrase cache forces the
            // backend agent to INQUIRE the passphrase, which the proxy must relay
            // to gpg (loopback) and gpg's answer back to the backend.
            let sign = fx.gpgUser([
                "--batch", "--yes", "--pinentry-mode", "loopback",
                "--passphrase", fx.onDiskPassphrase,
                "-u", fx.onDiskProtectedFpr, "--detach-sign", "-o", doc + ".sig", doc])
            XCTAssertEqual(sign.status, 0, "protected passthrough sign failed: \(sign.out)")

            let verify = fx.gpgUser(["--verify", doc + ".sig", doc])
            XCTAssertEqual(verify.status, 0, "verify failed: \(verify.out)")
            XCTAssertTrue(verify.out.contains("Good signature"), verify.out)
        }
    }

    // MARK: 5. EXPORT_KEY refusal

    func testExportKeyRefusedForEnclaveGrip() throws {
        try withFixture { fx in
            let client = try AssuanClient.connect(toSocket: fx.userSocket)
            defer { client.connection.close() }
            let result = try client.transact("EXPORT_KEY \(fx.signingRecord.keygripHex)")
            XCTAssertNotNil(result.error, "EXPORT_KEY of an enclave grip must fail")
            XCTAssertTrue(result.data.isEmpty, "EXPORT_KEY must not leak key material")
        }
    }
}

private extension Data {
    /// Uppercase hex string.
    var hexUpperString: String { map { String(format: "%02X", $0) }.joined() }
}
