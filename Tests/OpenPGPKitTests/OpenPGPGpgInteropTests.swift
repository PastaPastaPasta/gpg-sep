import XCTest
import CryptoKit
import Security
@testable import OpenPGPKit

/// Interop tests that shell out to the real `gpg` binary. These are the gold
/// standard: byte correctness is asserted against gpg, not against the spec.
final class OpenPGPGpgInteropTests: XCTestCase {

    // MARK: gpg harness

    private static let gpgPath: String? = {
        for candidate in ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"] {
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }()

    private func requireGpg() throws -> String {
        guard let p = Self.gpgPath else { throw XCTSkip("gpg not installed") }
        return p
    }

    @discardableResult
    private func gpg(_ home: String, _ args: [String], input: Data? = nil) throws -> (out: String, err: String, code: Int32) {
        let gpgPath = try requireGpg()
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: gpgPath)
        proc.arguments = ["--homedir", home, "--batch", "--no-tty"] + args
        var env = ProcessInfo.processInfo.environment
        env["GNUPGHOME"] = home
        proc.environment = env
        let outPipe = Pipe(), errPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = errPipe
        if let input {
            let inPipe = Pipe()
            proc.standardInput = inPipe
            try proc.run()
            inPipe.fileHandleForWriting.write(input)
            try inPipe.fileHandleForWriting.close()
        } else {
            try proc.run()
        }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (String(decoding: outData, as: UTF8.self),
                String(decoding: errData, as: UTF8.self),
                proc.terminationStatus)
    }

    private func makeHome() throws -> String {
        // Must stay short: gpg-agent's Unix socket path (<homedir>/S.gpg-agent)
        // has a ~104-byte limit, which the default long /var/folders temp path
        // blows past ("can't connect to the gpg-agent: File name too long").
        let dir = "/tmp/gs" + UUID().uuidString.prefix(8)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        return dir
    }

    private func killAgent(_ home: String) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/gpgconf")
        proc.arguments = ["--homedir", home, "--kill", "gpg-agent"]
        proc.standardError = Pipe(); proc.standardOutput = Pipe()
        try? proc.run(); proc.waitUntilExit()
    }

    // MARK: Signing helpers (CryptoKit / Security stand-in for the enclave)

    /// Build the ECPoint from a CryptoKit P-256 public key (x963 = 04||X||Y).
    private func point(of key: P256.Signing.PrivateKey) -> ECPoint {
        let x963 = key.publicKey.x963Representation
        let x = x963.subdata(in: 1..<33)
        let y = x963.subdata(in: 33..<65)
        return ECPoint(x: x, y: y)
    }

    /// A signer closure that signs the OpenPGP digest via Security.framework's
    /// pre-hashed ECDSA (the exact path the Secure Enclave uses), returning raw
    /// (r, s). This validates the DER->raw conversion end to end.
    private func signer(for key: P256.Signing.PrivateKey)
        -> (_ digest: Data, _ hashAlgo: PGPHashAlgorithm) throws -> (r: Data, s: Data) {
        return { digest, hashAlgo in
            let attrs: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            ]
            var error: Unmanaged<CFError>?
            guard let sec = SecKeyCreateWithData(key.x963Representation as CFData, attrs as CFDictionary, &error) else {
                throw OpenPGPError.invalidDER("SecKeyCreateWithData failed")
            }
            let alg: SecKeyAlgorithm
            switch hashAlgo {
            case .sha256: alg = .ecdsaSignatureDigestX962SHA256
            case .sha384: alg = .ecdsaSignatureDigestX962SHA384
            case .sha512: alg = .ecdsaSignatureDigestX962SHA512
            }
            guard let der = SecKeyCreateSignature(sec, alg, digest as CFData, &error) as Data? else {
                throw OpenPGPError.invalidDER("SecKeyCreateSignature failed")
            }
            return try ecdsaDERToRawRS(der)
        }
    }

    // MARK: - Tests

    /// Generate a real key with gpg, then confirm our keygrip + fingerprint code
    /// reproduces gpg's reported values for the same public point.
    func testGpgGeneratedKeygripAndFingerprintMatch() throws {
        let home = try makeHome()
        defer { killAgent(home); try? FileManager.default.removeItem(atPath: home) }

        let gen = try gpg(home, ["--pinentry-mode", "loopback", "--passphrase", "",
                                 "--quick-generate-key", "Interop ECDSA <e@x.com>", "nistp256", "sign", "never"])
        XCTAssertEqual(gen.code, 0, "keygen failed: \(gen.err)")

        // Read gpg's reported fingerprint + keygrip.
        let listing = try gpg(home, ["--with-colons", "--with-keygrip", "-K"])
        let lines = listing.out.split(separator: "\n").map(String.init)
        guard let fprLine = lines.first(where: { $0.hasPrefix("fpr:") }),
              let grpLine = lines.first(where: { $0.hasPrefix("grp:") }) else {
            return XCTFail("could not parse gpg listing:\n\(listing.out)")
        }
        let gpgFpr = fprLine.split(separator: ":", omittingEmptySubsequences: false)[9]
        let gpgGrp = grpLine.split(separator: ":", omittingEmptySubsequences: false)[9]

        // Export the pubkey, parse it, and re-derive everything ourselves.
        let export = try gpgData(home, ["--export", String(gpgFpr)])
        let packets = try PGPReader.parse(export)
        guard case let .publicKey(primary, false) = packets.first else {
            return XCTFail("first packet was not a primary public key")
        }
        XCTAssertEqual(primary.fingerprint.hexUpper, String(gpgFpr), "fingerprint mismatch")
        XCTAssertEqual(primary.keygrip.hexUpper, String(gpgGrp), "KEYGRIP MISMATCH")
    }

    /// Generate an ECDH subkey too and confirm our reader agrees with gpg's parse.
    func testGpgEcdhKeyParsingAndKeygrip() throws {
        let home = try makeHome()
        defer { killAgent(home); try? FileManager.default.removeItem(atPath: home) }

        let gen = try gpg(home, ["--pinentry-mode", "loopback", "--passphrase", "",
                                 "--quick-generate-key", "Interop2 <e2@x.com>", "nistp256", "sign", "never"])
        XCTAssertEqual(gen.code, 0, gen.err)
        let fpr = try firstFingerprint(home)
        let add = try gpg(home, ["--pinentry-mode", "loopback", "--passphrase", "",
                                 "--quick-add-key", fpr, "nistp256", "encr", "never"])
        XCTAssertEqual(add.code, 0, add.err)

        let listing = try gpg(home, ["--with-colons", "--with-keygrip", "-K"])
        // Grab the subkey keygrip (grp line following the ssb line).
        let lines = listing.out.split(separator: "\n").map(String.init)
        var subgrip: String?
        var seenSub = false
        for l in lines {
            if l.hasPrefix("ssb:") { seenSub = true }
            if seenSub, l.hasPrefix("grp:") { subgrip = String(l.split(separator: ":", omittingEmptySubsequences: false)[9]); break }
        }
        let export = try gpgData(home, ["--export", fpr])
        let packets = try PGPReader.parse(export)
        let subkeys = packets.compactMap { pkt -> PGPPublicKeyPacket? in
            if case let .publicKey(p, true) = pkt { return p }; return nil
        }
        guard let ecdh = subkeys.first else { return XCTFail("no subkey parsed") }
        XCTAssertEqual(ecdh.algorithm, .ecdh)
        XCTAssertEqual(ecdh.keygrip.hexUpper, subgrip, "ECDH subkey keygrip mismatch")
    }

    /// Build a public-key transferable ourselves from a known point, import it,
    /// and confirm gpg reports the fingerprint + keygrip we computed.
    func testRoundTripImportOurKey() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(atPath: home) }

        let primaryKey = P256.Signing.PrivateKey()
        let primaryPoint = point(of: primaryKey)
        let created: UInt32 = 1700000000
        let primary = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa, point: primaryPoint)
        let uid = PGPUserIDPacket("Roundtrip <rt@example.com>")

        let cert = PGPSignatureBuilder(type: .positiveCertification)
        cert.addHashed(.signatureCreationTime(created))
        cert.addHashed(.issuerFingerprint(primary.fingerprint))
        cert.addHashed(.keyFlags([.certify, .sign]))
        cert.addHashed(.preferredHashAlgorithms([.sha512, .sha384, .sha256]))
        cert.addUnhashed(.issuerKeyID(primary.keyID))
        let certPacket = try cert.build(over: .certification(primary: primary, userID: uid),
                                        sign: signer(for: primaryKey))

        let tk = PGPTransferablePublicKey(
            primary: primary,
            userIDs: [.init(userID: uid, certification: certPacket)])
        let armored = tk.armored()

        let imp = try gpg(home, ["--import"], input: Data(armored.utf8))
        XCTAssertTrue(imp.err.contains("imported") || imp.code == 0, "import failed: \(imp.err)")

        let listing = try gpg(home, ["--with-colons", "--with-keygrip", "-k"])
        XCTAssertTrue(listing.out.contains(primary.fingerprint.hexUpper),
                      "gpg listing missing our fingerprint:\n\(listing.out)")
        XCTAssertTrue(listing.out.contains(primary.keygrip.hexUpper),
                      "gpg listing missing our keygrip:\n\(listing.out)")
    }

    /// Full self-signed key with a signing subkey: 0x13 cert, 0x18 binding with
    /// an embedded 0x19 back-signature. gpg must accept every binding.
    func testSelfSignedKeyWithSubkeyBindingAcceptedByGpg() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(atPath: home) }

        let created: UInt32 = 1700000000
        let primaryKey = P256.Signing.PrivateKey()
        let primary = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa, point: point(of: primaryKey))
        let uid = PGPUserIDPacket("SubkeyTest <sub@example.com>")

        // Primary self-certification (0x13).
        let cert = PGPSignatureBuilder(type: .positiveCertification)
        cert.addHashed(.signatureCreationTime(created))
        cert.addHashed(.issuerFingerprint(primary.fingerprint))
        cert.addHashed(.keyFlags([.certify, .sign]))
        cert.addHashed(.preferredHashAlgorithms([.sha512, .sha384, .sha256]))
        cert.addUnhashed(.issuerKeyID(primary.keyID))
        let certPacket = try cert.build(over: .certification(primary: primary, userID: uid),
                                        sign: signer(for: primaryKey))

        // Signing subkey.
        let subkeyKey = P256.Signing.PrivateKey()
        let subkey = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa, point: point(of: subkeyKey))

        // Back-signature (0x19) made by the SUBKEY, embedded in the binding.
        let backSig = PGPSignatureBuilder(type: .primaryKeyBinding)
        backSig.addHashed(.signatureCreationTime(created))
        backSig.addHashed(.issuerFingerprint(subkey.fingerprint))
        backSig.addUnhashed(.issuerKeyID(subkey.keyID))
        let backSigBody = try backSig.buildBody(over: .subkey(primary: primary, subkey: subkey),
                                                sign: signer(for: subkeyKey))

        // Binding (0x18) made by the PRIMARY, embedding the back-sig.
        let binding = PGPSignatureBuilder(type: .subkeyBinding)
        binding.addHashed(.signatureCreationTime(created))
        binding.addHashed(.issuerFingerprint(primary.fingerprint))
        binding.addHashed(.keyFlags([.sign]))
        binding.addHashed(.embeddedSignature(backSigBody))
        binding.addUnhashed(.issuerKeyID(primary.keyID))
        let bindingPacket = try binding.build(over: .subkey(primary: primary, subkey: subkey),
                                              sign: signer(for: primaryKey))

        let tk = PGPTransferablePublicKey(
            primary: primary,
            userIDs: [.init(userID: uid, certification: certPacket)],
            subkeys: [.init(subkey: subkey, binding: bindingPacket)])

        let imp = try gpg(home, ["--import"], input: Data(tk.armored().utf8))
        XCTAssertTrue(imp.code == 0 || imp.err.contains("imported"), "import failed: \(imp.err)")

        let fpr = primary.fingerprint.hexUpper
        let check = try gpg(home, ["--check-signatures", fpr])
        // gpg reports invalid bindings as "bad signature"; missing trust is fine.
        XCTAssertFalse(check.err.lowercased().contains("bad signature"), "bad signature: \(check.err)\n\(check.out)")
        XCTAssertFalse(check.out.lowercased().contains("bad signature"), "bad signature in output:\n\(check.out)")
        // The subkey must be present and bound.
        XCTAssertTrue(check.out.contains(subkey.keyID.hexUpper) || check.out.contains("sub"),
                      "subkey not listed:\n\(check.out)")
        XCTAssertFalse(check.err.contains("no valid binding signature"), check.err)
    }

    /// A detached binary document signature our code assembled must verify.
    func testDetachedDocumentSignatureVerifies() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(atPath: home) }

        let created: UInt32 = 1700000000
        let primaryKey = P256.Signing.PrivateKey()
        let primary = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa, point: point(of: primaryKey))
        let uid = PGPUserIDPacket("DocSigner <doc@example.com>")

        let cert = PGPSignatureBuilder(type: .positiveCertification)
        cert.addHashed(.signatureCreationTime(created))
        cert.addHashed(.issuerFingerprint(primary.fingerprint))
        cert.addHashed(.keyFlags([.certify, .sign]))
        cert.addUnhashed(.issuerKeyID(primary.keyID))
        let certPacket = try cert.build(over: .certification(primary: primary, userID: uid),
                                        sign: signer(for: primaryKey))
        let tk = PGPTransferablePublicKey(primary: primary, userIDs: [.init(userID: uid, certification: certPacket)])
        _ = try gpg(home, ["--import"], input: Data(tk.armored().utf8))

        // The document.
        let docPath = home + "/message.txt"
        let docData = Data("The quick brown fox.\n".utf8)
        try docData.write(to: URL(fileURLWithPath: docPath))

        // Assemble the detached signature (0x00 binary document).
        let docSig = PGPSignatureBuilder(type: .binaryDocument)
        docSig.addHashed(.signatureCreationTime(created))
        docSig.addHashed(.issuerFingerprint(primary.fingerprint))
        docSig.addUnhashed(.issuerKeyID(primary.keyID))
        let sigPacket = try docSig.build(over: .document(docData), sign: signer(for: primaryKey))

        let sigPath = home + "/message.sig"
        try Data(armoredSignature(sigPacket).utf8).write(to: URL(fileURLWithPath: sigPath))

        let verify = try gpg(home, ["--verify", sigPath, docPath])
        XCTAssertTrue(verify.err.contains("Good signature"), "verify failed:\n\(verify.err)")
    }

    // MARK: helpers

    private func gpgData(_ home: String, _ args: [String]) throws -> Data {
        let gpgPath = try requireGpg()
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: gpgPath)
        proc.arguments = ["--homedir", home, "--batch", "--no-tty"] + args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        try proc.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return data
    }

    private func firstFingerprint(_ home: String) throws -> String {
        let listing = try gpg(home, ["--with-colons", "-K"])
        guard let fprLine = listing.out.split(separator: "\n").map(String.init).first(where: { $0.hasPrefix("fpr:") }) else {
            throw OpenPGPError.malformedPacket("no fingerprint")
        }
        return String(fprLine.split(separator: ":", omittingEmptySubsequences: false)[9])
    }
}
