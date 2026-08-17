import Foundation
import XCTest
import CryptoKit
import AssuanKit
import OpenPGPKit
import SEPKit
@testable import GPGSepDaemonCore

/// Black-box tests of the `gpg-sep` CLI: the hand-rolled argument parser, key
/// generation (software and, on real hardware, the Secure Enclave), binding a
/// subkey under an RSA primary through gpg-agent, install/uninstall's composable
/// pieces, and `doctor`'s end-to-end self-test.
///
/// The CLI is exercised as a subprocess — the way users run it — against
/// ephemeral `GNUPGHOME`/`GPG_SEP_HOME`/`GPG_SEP_CONFIG` roots under `/tmp`
/// (short paths, because `sun_path` is 104 octets). The user's `~/.gnupg` and
/// their running agent are never touched: every gpg invocation is pinned to an
/// ephemeral home, and teardown only kills agents rooted at those homes.
final class CLITests: XCTestCase {

    // MARK: Locating the built binaries

    /// The debug/release bin directory holding `gpg-sep` and `gpg-sep-agent`
    /// (the test bundle lives right next to them).
    static let binDir: URL = Bundle(for: CLITests.self).bundleURL.deletingLastPathComponent()

    static var cliPath: String { binDir.appendingPathComponent("gpg-sep").path }
    static var agentPath: String { binDir.appendingPathComponent("gpg-sep-agent").path }

    static func toolPath(_ name: String) -> String? {
        for p in ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)", "/usr/bin/\(name)"]
        where FileManager.default.isExecutableFile(atPath: p) { return p }
        return nil
    }

    // MARK: Ephemeral environment

    /// A throwaway trio of homes plus helpers to invoke the CLI and gpg against
    /// them. Nothing here can reach the user's real GnuPG state.
    final class Env {
        let root: String
        let gnupgHome: String
        let sepHome: String
        let configHome: String
        let gpg: String
        let gpgconf: String
        private var proxy: SepAgentServer?
        private var backend: BackendAgent?
        private var daemon: Process?

        init(gpg: String, gpgconf: String) throws {
            self.gpg = gpg
            self.gpgconf = gpgconf
            root = "/tmp/gsc" + String(UInt32.random(in: 0..<0xFFFF_FFFF), radix: 16)
            gnupgHome = root + "/g"
            sepHome = root + "/s"
            configHome = root + "/c"
            for d in [gnupgHome, sepHome, configHome] {
                try FileManager.default.createDirectory(
                    atPath: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            }
        }

        var environment: [String: String] {
            var env = ProcessInfo.processInfo.environment
            env["GNUPGHOME"] = gnupgHome
            env["GPG_SEP_HOME"] = sepHome
            env["GPG_SEP_CONFIG"] = configHome
            return env
        }

        /// Run `gpg-sep <args>` against this environment.
        @discardableResult
        func cli(_ args: [String], stdin: String? = nil) -> (out: String, err: String, code: Int32) {
            Env.exec(CLITests.cliPath, args, env: environment, stdin: stdin)
        }

        /// Run gpg pinned to this environment's home.
        @discardableResult
        func gpgRun(_ args: [String], stdin: String? = nil) -> (out: String, err: String, code: Int32) {
            Env.exec(gpg, ["--homedir", gnupgHome, "--batch", "--no-tty"] + args,
                     env: environment, stdin: stdin)
        }

        /// The binary packet stream of `gpg --export <fpr>`, obtained via armor so
        /// no bytes are lost to UTF-8 decoding.
        func exportPackets(_ fpr: String) throws -> Data {
            let armored = gpgRun(["--armor", "--export", fpr])
            return try Armor.dearmor(armored.out)
        }

        static func exec(_ tool: String, _ args: [String], env: [String: String], stdin: String? = nil)
            -> (out: String, err: String, code: Int32) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: tool)
            p.arguments = args
            p.environment = env
            let o = Pipe(), e = Pipe()
            p.standardOutput = o
            p.standardError = e
            if let stdin {
                let i = Pipe()
                p.standardInput = i
                do { try p.run() } catch { return ("", "\(error)", -1) }
                i.fileHandleForWriting.write(Data(stdin.utf8))
                try? i.fileHandleForWriting.close()
            } else {
                p.standardInput = FileHandle.nullDevice
                do { try p.run() } catch { return ("", "\(error)", -1) }
            }
            let od = o.fileHandleForReading.readDataToEndOfFile()
            let ed = e.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            return (String(decoding: od, as: UTF8.self), String(decoding: ed, as: UTF8.self), p.terminationStatus)
        }

        /// The primary fingerprint of the first public key in this home.
        func firstFingerprint() -> String? {
            let out = gpgRun(["--with-colons", "--list-keys"]).out
            for line in out.split(separator: "\n") where line.hasPrefix("fpr:") {
                let f = line.split(separator: ":", omittingEmptySubsequences: false)
                if f.count > 9 { return String(f[9]) }
            }
            return nil
        }

        /// Every subkey fingerprint in this home, in listing order.
        func subkeyFingerprints() -> [String] {
            let out = gpgRun(["--with-colons", "--list-keys"]).out
            var result: [String] = []
            var inSub = false
            for line in out.split(separator: "\n") {
                if line.hasPrefix("sub:") { inSub = true; continue }
                if line.hasPrefix("pub:") || line.hasPrefix("uid:") { inSub = false; continue }
                if inSub, line.hasPrefix("fpr:") {
                    let f = line.split(separator: ":", omittingEmptySubsequences: false)
                    if f.count > 9 { result.append(String(f[9])) }
                    inSub = false
                }
            }
            return result
        }

        /// Take over this home's agent socket by launching the real
        /// `gpg-sep-agent` binary against these ephemeral homes — the actual
        /// deployed shape (a separate process, so `doctor` can identify who owns
        /// the socket), just started directly instead of by launchd.
        func startProxy() throws {
            let socket = Env.exec(gpgconf, ["--homedir", gnupgHome, "--list-dirs", "agent-socket"],
                                  env: environment).out.trimmingCharacters(in: .whitespacesAndNewlines)
            let p = Process()
            p.executableURL = URL(fileURLWithPath: CLITests.agentPath)
            p.environment = environment
            p.standardInput = FileHandle.nullDevice
            let log = Pipe()
            p.standardOutput = log
            p.standardError = log
            try p.run()
            daemon = p

            // Wait until *our daemon* answers, not merely until something does:
            // the stock agent is still alive for a moment after launch, so a bare
            // connect would succeed against it and race the takeover. The Assuan
            // greeting reports the serving process's own pid, so resolve it.
            let deadline = Date().addingTimeInterval(20)
            while Date() < deadline {
                if FileManager.default.fileExists(atPath: socket),
                   let client = try? AssuanClient.connect(toSocket: socket) {
                    let greeting = client.greeting ?? ""
                    client.connection.close()
                    if let r = greeting.range(of: "process "),
                       let pid = Int32(greeting[r.upperBound...].prefix(while: { $0.isNumber })),
                       Env.exec("/bin/ps", ["-p", "\(pid)", "-o", "comm="], env: environment)
                        .out.contains("gpg-sep-agent") {
                        return
                    }
                }
                usleep(200_000)
            }
            let logData = log.fileHandleForReading.availableData
            throw NSError(domain: "CLITests", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "gpg-sep-agent never took over \(socket); "
                    + "daemon output: \(String(decoding: logData, as: UTF8.self))"])
        }

        func tearDown() {
            if let daemon, daemon.isRunning {
                daemon.terminate()
                daemon.waitUntilExit()
            }
            proxy?.stop()
            backend?.stop()
            for home in [gnupgHome, sepHome + "/backend-home"] {
                _ = Env.exec(gpgconf, ["--homedir", home, "--kill", "all"], env: environment)
                if FileManager.default.isExecutableFile(atPath: "/usr/bin/pkill") {
                    _ = Env.exec("/usr/bin/pkill", ["-f", "gpg-agent --homedir \(home)"], env: environment)
                }
            }
            try? FileManager.default.removeItem(atPath: root)
        }
    }

    func withEnv(_ body: (Env) throws -> Void) throws {
        guard let gpg = Self.toolPath("gpg"), let gpgconf = Self.toolPath("gpgconf") else {
            throw XCTSkip("gpg toolchain is not installed")
        }
        guard FileManager.default.isExecutableFile(atPath: Self.cliPath) else {
            throw XCTSkip("gpg-sep binary not found at \(Self.cliPath)")
        }
        let env = try Env(gpg: gpg, gpgconf: gpgconf)
        defer { env.tearDown() }
        try body(env)
    }

    // MARK: - 1. Hand-rolled argument parser
    //
    // The parser lives in the executable target, which cannot be imported, so it
    // is tested through the binary — which is also how it is actually used.

    func testHelpAndUnknownCommand() throws {
        try withEnv { env in
            let top = env.cli(["--help"])
            XCTAssertEqual(top.code, 0)
            XCTAssertTrue(top.out.contains("usage: gpg-sep <command>"), top.out)

            let bogus = env.cli(["definitely-not-a-command"])
            XCTAssertEqual(bogus.code, 2)
            XCTAssertTrue(bogus.err.contains("unknown command"), bogus.err)

            // Every subcommand must answer --help without side effects.
            for cmd in ["keygen", "add-subkey", "list", "export", "revoke",
                        "policy", "install", "uninstall", "doctor"] {
                let h = env.cli([cmd, "--help"])
                XCTAssertEqual(h.code, 0, "\(cmd) --help exited \(h.code): \(h.err)")
                XCTAssertTrue(h.out.contains("usage:"), "\(cmd) --help printed no usage:\n\(h.out)")
            }
        }
    }

    func testParserRejectsUnknownAndIncompleteOptions() throws {
        try withEnv { env in
            let unknown = env.cli(["policy", "--definitely-bogus"])
            XCTAssertEqual(unknown.code, 1)
            XCTAssertTrue(unknown.err.contains("unknown option --definitely-bogus"), unknown.err)

            let missingValue = env.cli(["policy", "--set-grace"])
            XCTAssertEqual(missingValue.code, 1)
            XCTAssertTrue(missingValue.err.contains("requires a value"), missingValue.err)

            // A flag-only option must not be usable in the --name=value form.
            let badEquals = env.cli(["keygen", "--force-software=yes"])
            XCTAssertEqual(badEquals.code, 1)
            XCTAssertTrue(badEquals.err.contains("non-value option"), badEquals.err)

            let missingRequired = env.cli(["keygen"])
            XCTAssertEqual(missingRequired.code, 1)
            XCTAssertTrue(missingRequired.err.contains("missing required option --uid"), missingRequired.err)

            let notAnInt = env.cli(["policy", "--set-grace", "banana"])
            XCTAssertEqual(notAnInt.code, 1)
            XCTAssertTrue(notAnInt.err.contains("expects an integer"), notAnInt.err)

            let badPresence = env.cli(["policy", "--set-presence", "sometimes"])
            XCTAssertEqual(badPresence.code, 1)
            XCTAssertTrue(badPresence.err.contains("invalid --presence"), badPresence.err)
        }
    }

    func testParserAcceptsBothValueFormsAndPositionals() throws {
        try withEnv { env in
            // Space-separated form.
            let spaced = env.cli(["policy", "--set-grace", "42"])
            XCTAssertEqual(spaced.code, 0, spaced.err)
            XCTAssertTrue(spaced.out.contains("grace    : 42s"), spaced.out)

            // --name=value form, and the value must persist to the config.
            let equals = env.cli(["policy", "--set-grace=7", "--set-presence=biometry"])
            XCTAssertEqual(equals.code, 0, equals.err)
            XCTAssertTrue(equals.out.contains("grace    : 7s"), equals.out)
            XCTAssertTrue(equals.out.contains("presence : biometry"), equals.out)

            let reread = env.cli(["policy"])
            XCTAssertTrue(reread.out.contains("grace    : 7s"), "config did not persist:\n\(reread.out)")
            XCTAssertTrue(reread.out.contains("presence : biometry"), reread.out)

            // A positional is routed to the per-key path, not swallowed as an option.
            let perKey = env.cli(["policy", "00112233445566778899AABBCCDDEEFF00112233"])
            XCTAssertEqual(perKey.code, 1)
            XCTAssertTrue(perKey.err.contains("no gpg-sep key with keygrip 00112233"), perKey.err)
        }
    }

    func testExpiryParsing() throws {
        try withEnv { env in
            let bad = env.cli(["keygen", "--uid", "X <x@x.tld>", "--expire", "bogus", "--force-software"])
            XCTAssertEqual(bad.code, 1)
            XCTAssertTrue(bad.err.contains("malformed --expire"), bad.err)

            // 1y must land as 31536000 seconds in the report.
            let oneYear = env.cli(["keygen", "--uid", "Y <y@x.tld>", "--expire", "1y",
                                   "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(oneYear.code, 0, oneYear.err)
            XCTAssertTrue(oneYear.out.contains("expires     : 31536000s"), oneYear.out)

            // 0 must mean "never".
            let never = env.cli(["keygen", "--uid", "Z <z@x.tld>", "--expire", "0",
                                 "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(never.code, 0, never.err)
            XCTAssertTrue(never.out.contains("expires     : never"), never.out)
        }
    }

    // MARK: - 2. keygen

    /// The canonical software-backend keygen: gpg must accept the self-signature
    /// and the encryption-subkey binding, and the revocation certificate must be
    /// on disk with 0600 permissions.
    func testKeygenSoftwareProducesGpgAcceptedCertificate() throws {
        try withEnv { env in
            let gen = env.cli(["keygen", "--uid", "CI Soft <ci@example.com>",
                               "--with-encryption-subkey", "--presence", "none", "--grace", "0",
                               "--force-software"])
            XCTAssertEqual(gen.code, 0, "keygen failed: \(gen.err)")
            guard let fpr = env.firstFingerprint() else { return XCTFail("no key imported") }

            let check = env.gpgRun(["--check-signatures", fpr])
            let combined = (check.out + check.err).lowercased()
            XCTAssertFalse(combined.contains("bad signature"), "\(check.out)\(check.err)")
            XCTAssertTrue(combined.contains("2 good signatures"),
                          "expected self-sig + subkey binding:\n\(check.out)\(check.err)")
            XCTAssertTrue(check.out.contains("[SC]"), "primary lacks certify+sign:\n\(check.out)")
            XCTAssertTrue(check.out.contains("[E]"), "no encryption subkey:\n\(check.out)")

            // Revocation certificate: present, 0600, and a parseable 0x20 signature.
            let revPath = env.sepHome + "/revocations/\(fpr).rev"
            XCTAssertTrue(FileManager.default.fileExists(atPath: revPath), "no revcert at \(revPath)")
            let attrs = try FileManager.default.attributesOfItem(atPath: revPath)
            XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
            let revText = try String(contentsOfFile: revPath, encoding: .utf8)
            let revPackets = try PGPReader.parse(try Armor.dearmor(revText))
            guard case let .signature(sig)? = revPackets.first else {
                return XCTFail("revocation certificate is not a signature packet")
            }
            XCTAssertEqual(sig.type, PGPSignatureType.keyRevocation.rawValue)

            // `list` must show both keys and report them visible to gpg.
            let list = env.cli(["list"])
            XCTAssertEqual(list.code, 0, list.err)
            XCTAssertTrue(list.out.contains("role    : signing"), list.out)
            XCTAssertTrue(list.out.contains("role    : encryption"), list.out)
            XCTAssertFalse(list.out.contains("in gpg  : no"), "a store key is missing from gpg:\n\(list.out)")
        }
    }

    /// `--export-only` must print an importable certificate without touching the
    /// keyring.
    func testKeygenExportOnlyDoesNotImport() throws {
        try withEnv { env in
            let gen = env.cli(["keygen", "--uid", "Export Only <eo@example.com>",
                               "--presence", "none", "--grace", "0", "--force-software", "--export-only"])
            XCTAssertEqual(gen.code, 0, gen.err)
            XCTAssertTrue(gen.out.contains("BEGIN PGP PUBLIC KEY BLOCK"), gen.out)
            XCTAssertNil(env.firstFingerprint(), "--export-only must not import into the keyring")

            // The printed block must still be a certificate gpg accepts.
            let start = gen.out.range(of: "-----BEGIN PGP PUBLIC KEY BLOCK-----")!
            let end = gen.out.range(of: "-----END PGP PUBLIC KEY BLOCK-----")!
            let block = String(gen.out[start.lowerBound..<end.upperBound]) + "\n"
            let imp = env.gpgRun(["--import"], stdin: block)
            XCTAssertTrue(imp.code == 0 || imp.err.contains("imported"), imp.err)
            XCTAssertNotNil(env.firstFingerprint())
        }
    }

    /// The same flow on the real Secure Enclave. `--presence none` keeps it
    /// non-interactive; skipped where there is no SEP (CI VMs).
    func testKeygenOnRealSecureEnclave() throws {
        guard SecureEnclave.isAvailable else {
            throw XCTSkip("no Secure Enclave on this machine")
        }
        try withEnv { env in
            let gen = env.cli(["keygen", "--uid", "SEP Hardware <sep@example.com>",
                               "--with-encryption-subkey", "--presence", "none", "--grace", "0"])
            XCTAssertEqual(gen.code, 0, "enclave keygen failed: \(gen.err)")
            XCTAssertTrue(gen.out.contains("backend=secure-enclave"),
                          "keygen did not use the enclave:\n\(gen.out)")

            let store = KeyStore(root: URL(fileURLWithPath: env.sepHome, isDirectory: true))
            let records = try store.allRecords()
            XCTAssertEqual(records.count, 2)
            XCTAssertTrue(records.allSatisfy { $0.backend == BackendKind.secureEnclave },
                          "a key was not enclave-backed: \(records.map(\.backend))")

            guard let fpr = env.firstFingerprint() else { return XCTFail("no key imported") }
            let check = env.gpgRun(["--check-signatures", fpr])
            let combined = (check.out + check.err).lowercased()
            XCTAssertFalse(combined.contains("bad signature"), "\(check.out)\(check.err)")
            XCTAssertTrue(combined.contains("2 good signatures"), "\(check.out)\(check.err)")

            // And a detached signature made in the enclave, through the proxy,
            // must verify — the full hardware chain.
            try env.startProxy()
            let doc = env.root + "/hw.txt"
            try "signed by the secure enclave\n".write(toFile: doc, atomically: true, encoding: .utf8)
            let sign = env.gpgRun(["--yes", "-u", "\(fpr)!", "--detach-sign", "-o", doc + ".sig", doc])
            XCTAssertEqual(sign.code, 0, "enclave detach-sign failed: \(sign.err)")
            let verify = env.gpgRun(["--verify", doc + ".sig", doc])
            XCTAssertTrue(verify.err.contains("Good signature"), "verify failed: \(verify.err)")
        }
    }

    // MARK: - 3. add-subkey under an RSA primary (the YubiKey case, simulated)

    /// Create a throwaway RSA primary with gpg, then bind a gpg-sep subkey under
    /// it. The 0x18 binding is signed by the RSA primary through gpg-agent and
    /// assembled from a single RSA MPI — the exact path a YubiKey primary takes.
    private func makeRSAPrimary(_ env: Env) throws -> String {
        let gen = env.gpgRun(["--pinentry-mode", "loopback", "--passphrase", "",
                              "--quick-generate-key", "RSA Primary <rsa@example.com>",
                              "rsa2048", "sign", "never"])
        XCTAssertEqual(gen.code, 0, "RSA keygen failed: \(gen.err)")
        guard let fpr = env.firstFingerprint() else {
            throw XCTSkip("could not create an RSA primary")
        }
        return fpr
    }

    func testAddSigningSubkeyUnderRSAPrimary() throws {
        try withEnv { env in
            let primaryFpr = try makeRSAPrimary(env)

            let add = env.cli(["add-subkey", "--to", primaryFpr, "--role", "sign",
                               "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(add.code, 0, "add-subkey failed: \(add.err)")
            XCTAssertTrue(add.out.contains("primary algo: RSA (1)"),
                          "the primary was not treated as RSA:\n\(add.out)")
            XCTAssertTrue(add.out.contains("binding     : Good"), add.out)

            // gpg's own verdict on the new binding.
            let check = env.gpgRun(["--check-signatures", primaryFpr])
            let combined = (check.out + check.err).lowercased()
            XCTAssertFalse(combined.contains("bad signature"), "\(check.out)\(check.err)")
            XCTAssertFalse(combined.contains("no valid binding"), "\(check.out)\(check.err)")
            XCTAssertTrue(combined.contains("2 good signatures"),
                          "expected the self-sig plus the new binding:\n\(check.out)\(check.err)")
            // gpg grants [S] only when the embedded 0x19 back-signature verifies,
            // so this asserts cross-certification was accepted.
            XCTAssertTrue(check.out.contains("[S]"),
                          "the subkey is not usable for signing (back-signature rejected?):\n\(check.out)")
            XCTAssertFalse(combined.contains("not cross-certified"), "\(check.out)\(check.err)")

            // The binding packet must declare the RSA algorithm and carry exactly
            // one MPI, with an embedded 0x19 back-signature made by the subkey.
            let raw = try PGPPacketScanner.scan(try env.exportPackets(primaryFpr))
            let bindings = try raw.filter { $0.tag == 2 }
                .map { try PGPReader.parse($0.packet) }
                .compactMap { pkts -> ParsedSignature? in
                    if case let .signature(s)? = pkts.first, s.type == PGPSignatureType.subkeyBinding.rawValue {
                        return s
                    }
                    return nil
                }
            guard let binding = bindings.first else { return XCTFail("no 0x18 binding in the export") }
            XCTAssertEqual(binding.publicKeyAlgorithm, 1, "binding must be an RSA signature")
            XCTAssertEqual(binding.mpis.count, 1, "an RSA signature carries exactly one MPI")
            XCTAssertTrue(binding.hashedSubpacketBytes.contains(32),
                          "no embedded-signature subpacket (type 32) in the binding")

            // A signature made *by the new subkey* must verify.
            try env.startProxy()
            guard let subFpr = env.subkeyFingerprints().first else {
                return XCTFail("no subkey fingerprint")
            }
            let doc = env.root + "/sub.txt"
            try "signed by the new subkey\n".write(toFile: doc, atomically: true, encoding: .utf8)
            let sign = env.gpgRun(["--yes", "-u", "\(subFpr)!", "--detach-sign", "-o", doc + ".sig", doc])
            XCTAssertEqual(sign.code, 0, "signing with the new subkey failed: \(sign.err)")
            let verify = env.gpgRun(["--verify", doc + ".sig", doc])
            XCTAssertTrue(verify.err.contains("Good signature"), "verify failed: \(verify.err)")
        }
    }

    func testAddEncryptionSubkeyUnderRSAPrimary() throws {
        try withEnv { env in
            let primaryFpr = try makeRSAPrimary(env)

            let add = env.cli(["add-subkey", "--to", primaryFpr, "--role", "encrypt",
                               "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(add.code, 0, "add-subkey --role encrypt failed: \(add.err)")
            XCTAssertTrue(add.out.contains("primary algo: RSA (1)"), add.out)

            let check = env.gpgRun(["--check-signatures", primaryFpr])
            let combined = (check.out + check.err).lowercased()
            XCTAssertFalse(combined.contains("bad signature"), "\(check.out)\(check.err)")
            XCTAssertTrue(combined.contains("2 good signatures"), "\(check.out)\(check.err)")
            XCTAssertTrue(check.out.contains("[E]"), "no usable encryption subkey:\n\(check.out)")

            // An encryption subkey must NOT carry a back-signature (RFC 9580 only
            // requires cross-certification for signing subkeys).
            let raw = try PGPPacketScanner.scan(try env.exportPackets(primaryFpr))
            let bindings = try raw.filter { $0.tag == 2 }
                .map { try PGPReader.parse($0.packet) }
                .compactMap { pkts -> ParsedSignature? in
                    if case let .signature(s)? = pkts.first, s.type == PGPSignatureType.subkeyBinding.rawValue {
                        return s
                    }
                    return nil
                }
            guard let binding = bindings.first else { return XCTFail("no 0x18 binding in the export") }
            XCTAssertEqual(binding.publicKeyAlgorithm, 1)
            XCTAssertEqual(binding.mpis.count, 1)
            XCTAssertFalse(binding.hashedSubpacketBytes.contains(32),
                           "an encryption subkey must not embed a back-signature")

            // Encrypt to the key and decrypt through the proxy.
            try env.startProxy()
            let secret = "rsa-primary encrypt round trip 4242"
            let cipherPath = env.root + "/msg.gpg"
            let enc = env.gpgRun(["--yes", "--trust-model", "always", "--encrypt",
                                  "-r", primaryFpr, "-o", cipherPath], stdin: secret)
            XCTAssertEqual(enc.code, 0, "encrypt failed: \(enc.err)")
            let dec = env.gpgRun(["--yes", "--decrypt", cipherPath])
            XCTAssertEqual(dec.code, 0, "decrypt through the proxy failed: \(dec.err)")
            XCTAssertTrue(dec.out.contains(secret), "plaintext mismatch:\n\(dec.out)")
        }
    }

    // MARK: - 4. install / uninstall (composable pieces, without launchd)

    /// `install --no-launchd` performs everything except the `launchctl` calls:
    /// the backend mirror home, the plist, and freeing the socket. The launchd
    /// bootstrap itself is NOT exercised here (it would register a job in the
    /// developer's own gui domain); it is covered by the manual deployment step.
    func testInstallWritesPlistAndBackendHomeThenUninstallCleansUp() throws {
        try withEnv { env in
            let laDir = env.root + "/LaunchAgents"
            let plistPath = laDir + "/org.gpg-sep.agent.plist"

            // A stock key so `private-keys-v1.d` exists and can be mirrored — the
            // interesting case, since the mirror is what keeps existing keys and
            // smartcards working once gpg-sep owns the socket.
            let stock = env.gpgRun(["--pinentry-mode", "loopback", "--passphrase", "",
                                    "--quick-generate-key", "Stock <s@example.com>",
                                    "nistp256", "sign", "never"])
            XCTAssertEqual(stock.code, 0, "stock keygen failed: \(stock.err)")

            let install = env.cli(["install", "--no-launchd",
                                   "--launch-agents-dir", laDir,
                                   "--agent-path", Self.agentPath])
            XCTAssertEqual(install.code, 0, "install failed: \(install.err)")

            // The backend mirror home must exist with symlinks into the gpg home.
            let backendHome = env.sepHome + "/backend-home"
            XCTAssertTrue(FileManager.default.fileExists(atPath: backendHome), install.out)
            let link = try FileManager.default.destinationOfSymbolicLink(
                atPath: backendHome + "/private-keys-v1.d")
            XCTAssertEqual(link, env.gnupgHome + "/private-keys-v1.d")

            // The plist must be well-formed and carry the values the daemon needs.
            XCTAssertTrue(FileManager.default.fileExists(atPath: plistPath), install.out)
            let data = try Data(contentsOf: URL(fileURLWithPath: plistPath))
            let plist = try PropertyListSerialization.propertyList(
                from: data, options: [], format: nil) as? [String: Any]
            XCTAssertEqual(plist?["Label"] as? String, "org.gpg-sep.agent")
            XCTAssertEqual(plist?["KeepAlive"] as? Bool, true)
            XCTAssertEqual(plist?["RunAtLoad"] as? Bool, true)
            XCTAssertEqual((plist?["ProgramArguments"] as? [String])?.first, Self.agentPath)
            let vars = plist?["EnvironmentVariables"] as? [String: String]
            XCTAssertEqual(vars?["GPG_SEP_HOME"], env.sepHome)
            XCTAssertEqual(vars?["GNUPGHOME"], env.gnupgHome)
            XCTAssertNotNil(vars?["PATH"])

            // install must say what it changed and how to undo it.
            XCTAssertTrue(install.out.contains("To undo everything above"), install.out)
            XCTAssertTrue(install.out.contains(plistPath), install.out)

            // A second install must refuse rather than clobber, unless forced.
            let again = env.cli(["install", "--no-launchd", "--launch-agents-dir", laDir,
                                 "--agent-path", Self.agentPath])
            XCTAssertEqual(again.code, 1)
            XCTAssertTrue(again.err.contains("already exists"), again.err)
            let forced = env.cli(["install", "--no-launchd", "--launch-agents-dir", laDir,
                                  "--agent-path", Self.agentPath, "--force"])
            XCTAssertEqual(forced.code, 0, forced.err)

            // Uninstall removes the plist and is idempotent.
            let uninstall = env.cli(["uninstall", "--no-launchd", "--launch-agents-dir", laDir])
            XCTAssertEqual(uninstall.code, 0, uninstall.err)
            XCTAssertFalse(FileManager.default.fileExists(atPath: plistPath), uninstall.out)

            let uninstallAgain = env.cli(["uninstall", "--no-launchd", "--launch-agents-dir", laDir])
            XCTAssertEqual(uninstallAgain.code, 0, "uninstall is not idempotent: \(uninstallAgain.err)")
            XCTAssertTrue(uninstallAgain.out.contains("already removed"), uninstallAgain.out)

            // After uninstall the stock agent must serve the socket again.
            let after = env.gpgRun(["--list-keys"])
            XCTAssertEqual(after.code, 0, "gpg broke after uninstall: \(after.err)")
        }
    }

    func testInstallRejectsMissingAgentPath() throws {
        try withEnv { env in
            let bad = env.cli(["install", "--no-launchd",
                               "--launch-agents-dir", env.root + "/LA",
                               "--agent-path", env.root + "/nope"])
            XCTAssertEqual(bad.code, 1)
            XCTAssertTrue(bad.err.contains("not an executable"), bad.err)
        }
    }

    // MARK: - 5. doctor

    /// Before the proxy is up, `doctor` must report honestly (socket is stock,
    /// self-test skipped) and still exit 0; once the proxy owns the socket, every
    /// check including the end-to-end self-test must pass.
    func testDoctorReportsHonestlyAndSelfTestPassesThroughTheProxy() throws {
        try withEnv { env in
            let gen = env.cli(["keygen", "--uid", "Doctor <doc@example.com>",
                               "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(gen.code, 0, gen.err)

            let before = env.cli(["doctor"])
            XCTAssertEqual(before.code, 0, before.err)
            XCTAssertTrue(before.out.contains("[ OK ] Key store"), before.out)
            XCTAssertTrue(before.out.contains("[SKIP] End-to-end sign/verify self-test"),
                          "self-test must be skipped when gpg-sep does not own the socket:\n\(before.out)")

            try env.startProxy()

            let after = env.cli(["doctor"])
            XCTAssertEqual(after.code, 0, "doctor failed:\n\(after.out)\(after.err)")
            XCTAssertFalse(after.out.contains("[FAIL]"), after.out)
            XCTAssertTrue(after.out.contains("served by gpg-sep-agent")
                            || after.out.contains("Agent socket ownership"), after.out)
            XCTAssertTrue(after.out.contains("[ OK ] End-to-end sign/verify self-test"),
                          "the self-test did not pass:\n\(after.out)")
            XCTAssertTrue(after.out.contains("[ OK ] Backend agent"), after.out)

            // --hardware must skip cleanly when the store holds only software keys.
            let hw = env.cli(["doctor", "--hardware"])
            XCTAssertEqual(hw.code, 0, hw.err)
            if SecureEnclave.isAvailable {
                XCTAssertTrue(hw.out.contains("no Secure-Enclave signing key"),
                              "expected a clear skip message:\n\(hw.out)")
            } else {
                XCTAssertTrue(hw.out.contains("no Secure Enclave"), hw.out)
            }
        }
    }

    /// `doctor` must exit non-zero when a check genuinely fails — here, a store
    /// record whose keygrip no longer matches its public point.
    func testDoctorFailsOnCorruptStoreRecord() throws {
        try withEnv { env in
            let gen = env.cli(["keygen", "--uid", "Corrupt <c@example.com>",
                               "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(gen.code, 0, gen.err)

            let keysDir = env.sepHome + "/keys"
            let files = try FileManager.default.contentsOfDirectory(atPath: keysDir)
            guard let name = files.first(where: { $0.hasSuffix(".json") }) else {
                return XCTFail("no store record")
            }
            let url = URL(fileURLWithPath: keysDir + "/" + name)
            var json = try JSONSerialization.jsonObject(with: try Data(contentsOf: url)) as! [String: Any]
            // Flip the stored X coordinate so the keygrip no longer matches.
            let x = Data(base64Encoded: json["pointX"] as! String)!
            json["pointX"] = Data([x.first! ^ 0xFF] + x.dropFirst()).base64EncodedString()
            try JSONSerialization.data(withJSONObject: json).write(to: url)

            let doctor = env.cli(["doctor"])
            XCTAssertEqual(doctor.code, 1, "doctor must fail on a corrupt record:\n\(doctor.out)")
            XCTAssertTrue(doctor.out.contains("[FAIL] Key store"), doctor.out)
            XCTAssertTrue(doctor.out.contains("keygrip does not match"), doctor.out)
        }
    }

    // MARK: - 6. export / revoke / per-key policy

    func testExportAndPerKeyPolicy() throws {
        try withEnv { env in
            let gen = env.cli(["keygen", "--uid", "Export <ex@example.com>",
                               "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(gen.code, 0, gen.err)
            guard let fpr = env.firstFingerprint() else { return XCTFail("no key") }

            let export = env.cli(["export", fpr])
            XCTAssertEqual(export.code, 0, export.err)
            XCTAssertTrue(export.out.contains("BEGIN PGP PUBLIC KEY BLOCK"), export.out)
            // The exported block must round-trip to the same fingerprint.
            let packets = try PGPReader.parse(try Armor.dearmor(export.out))
            guard case let .publicKey(primary, false)? = packets.first else {
                return XCTFail("export did not start with a primary key packet")
            }
            XCTAssertEqual(primary.fingerprint.map { String(format: "%02X", $0) }.joined(), fpr)

            let missing = env.cli(["export", "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"])
            XCTAssertEqual(missing.code, 1)
            XCTAssertTrue(missing.err.contains("no key found"), missing.err)

            // Per-key policy: read, then update the grace window.
            let store = KeyStore(root: URL(fileURLWithPath: env.sepHome, isDirectory: true))
            guard let record = try store.allRecords().first else { return XCTFail("no record") }
            let show = env.cli(["policy", record.keygripHex])
            XCTAssertEqual(show.code, 0, show.err)
            XCTAssertTrue(show.out.contains("grace    : 0s"), show.out)

            let set = env.cli(["policy", record.keygripHex, "--set-grace", "30"])
            XCTAssertEqual(set.code, 0, set.err)
            XCTAssertTrue(set.out.contains("grace    : 30s"), set.out)

            let reloaded = try KeyStore(root: URL(fileURLWithPath: env.sepHome, isDirectory: true))
                .record(keygripHex: record.keygripHex)
            XCTAssertEqual(reloaded?.policy.graceSeconds, 30, "per-key policy did not persist")
            // The record must stay 0600 after a rewrite.
            let attrs = try FileManager.default.attributesOfItem(
                atPath: env.sepHome + "/keys/\(record.keygripHex).json")
            XCTAssertEqual((attrs[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        }
    }

    /// `revoke` must require confirmation, and publishing the pre-generated
    /// certificate must make gpg report the key as revoked.
    func testRevokePublishesThePreGeneratedCertificate() throws {
        try withEnv { env in
            let gen = env.cli(["keygen", "--uid", "Revoke Me <rm@example.com>",
                               "--presence", "none", "--grace", "0", "--force-software"])
            XCTAssertEqual(gen.code, 0, gen.err)
            guard let fpr = env.firstFingerprint() else { return XCTFail("no key") }

            // Declining at the prompt must leave the key alone.
            let declined = env.cli(["revoke", fpr], stdin: "n\n")
            XCTAssertEqual(declined.code, 0, declined.err)
            XCTAssertTrue(declined.out.contains("Aborted"), declined.out)
            XCTAssertFalse(env.gpgRun(["--list-keys", fpr]).out.contains("revoked"),
                           "the key was revoked despite declining")

            let missing = env.cli(["revoke", "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF", "--yes"])
            XCTAssertEqual(missing.code, 1)
            XCTAssertTrue(missing.err.contains("no pre-generated revocation certificate"), missing.err)

            let revoked = env.cli(["revoke", fpr, "--yes", "--print"])
            XCTAssertEqual(revoked.code, 0, revoked.err)
            XCTAssertTrue(revoked.out.contains("BEGIN PGP PUBLIC KEY BLOCK"), "--print showed nothing")
            let listing = env.gpgRun(["--list-keys", fpr])
            XCTAssertTrue(listing.out.contains("revoked") || listing.out.contains("[ revoked]"),
                          "gpg does not report the key as revoked:\n\(listing.out)\(listing.err)")
        }
    }
}
