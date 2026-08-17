import XCTest
import CryptoKit
import Security
@testable import OpenPGPKit

/// Tests for the RSA-issuer additions: `signingAlgorithmByte`, the `.raw`
/// signature target, `v4FingerprintPreimage`, the raw packet scanner, and
/// `finalizePacket(over:mpis:)`.
///
/// The scenario is the real one this exists for: a subkey bound under an RSA
/// primary (a YubiKey primary, simulated here with a software RSA key). The
/// assertion of record is that the real `gpg` accepts the resulting certificate.
final class RSASignatureTests: XCTestCase {

    // MARK: gpg harness

    private static let gpgPath: String? = {
        for c in ["/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"]
        where FileManager.default.isExecutableFile(atPath: c) { return c }
        return nil
    }()

    private func requireGpg() throws -> String {
        guard let p = Self.gpgPath else { throw XCTSkip("gpg not installed") }
        return p
    }

    @discardableResult
    private func gpg(_ home: String, _ args: [String], input: Data? = nil)
        throws -> (out: String, err: String, code: Int32) {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: try requireGpg())
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
            try? inPipe.fileHandleForWriting.close()
        } else {
            proc.standardInput = FileHandle.nullDevice
            try proc.run()
        }
        let o = outPipe.fileHandleForReading.readDataToEndOfFile()
        let e = errPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (String(decoding: o, as: UTF8.self), String(decoding: e, as: UTF8.self), proc.terminationStatus)
    }

    /// Short path: gpg-agent's socket is capped near 104 bytes.
    private func makeHome() throws -> String {
        let dir = "/tmp/gsr" + UUID().uuidString.prefix(8)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        return dir
    }

    // MARK: RSA key helpers (Security.framework stand-in for a YubiKey primary)

    /// A software RSA key plus its OpenPGP v4 public-key packet body.
    private struct RSAKey {
        let secKey: SecKey
        /// v4 public-key packet body: version, creation time, algo 1, MPI(n), MPI(e).
        let body: Data
        var preimage: Data { v4FingerprintPreimage(publicKeyBody: body) }
        var fingerprint: Data { Data(Insecure.SHA1.hash(data: preimage)) }
        var keyID: Data { fingerprint.suffix(8) }

        /// Sign a precomputed digest, returning the single RSA signature MPI.
        func sign(digest: Data, hash: PGPHashAlgorithm) throws -> Data {
            let alg: SecKeyAlgorithm
            switch hash {
            case .sha256: alg = .rsaSignatureDigestPKCS1v15SHA256
            case .sha384: alg = .rsaSignatureDigestPKCS1v15SHA384
            case .sha512: alg = .rsaSignatureDigestPKCS1v15SHA512
            }
            var error: Unmanaged<CFError>?
            guard let sig = SecKeyCreateSignature(secKey, alg, digest as CFData, &error) as Data? else {
                throw OpenPGPError.invalidDER("RSA SecKeyCreateSignature failed: \(String(describing: error))")
            }
            return sig
        }
    }

    private func makeRSAKey(creationTime: UInt32) throws -> RSAKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        var error: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw OpenPGPError.invalidDER("SecKeyCreateRandomKey failed: \(String(describing: error))")
        }
        guard let pub = SecKeyCopyPublicKey(priv),
              let der = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw OpenPGPError.invalidDER("could not export the RSA public key")
        }
        // PKCS#1 RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let (n, e) = try Self.parseRSAPublicKeyDER(der)

        var body = Data([0x04])
        body.append(contentsOf: [UInt8((creationTime >> 24) & 0xFF), UInt8((creationTime >> 16) & 0xFF),
                                 UInt8((creationTime >> 8) & 0xFF), UInt8(creationTime & 0xFF)])
        body.append(0x01) // RSA (Encrypt or Sign)
        body.append(MPI.encode(n))
        body.append(MPI.encode(e))
        return RSAKey(secKey: priv, body: body)
    }

    /// Minimal DER reader for `SEQUENCE { INTEGER n, INTEGER e }`.
    static func parseRSAPublicKeyDER(_ der: Data) throws -> (n: Data, e: Data) {
        let bytes = [UInt8](der)
        var i = 0
        func length() throws -> Int {
            guard i < bytes.count else { throw OpenPGPError.truncated }
            var len = Int(bytes[i]); i += 1
            if len & 0x80 != 0 {
                let count = len & 0x7F
                guard count >= 1, count <= 3, i + count <= bytes.count else {
                    throw OpenPGPError.invalidDER("bad length form")
                }
                len = 0
                for _ in 0..<count { len = (len << 8) | Int(bytes[i]); i += 1 }
            }
            return len
        }
        guard i < bytes.count, bytes[i] == 0x30 else { throw OpenPGPError.invalidDER("expected SEQUENCE") }
        i += 1
        _ = try length()
        func integer() throws -> Data {
            guard i < bytes.count, bytes[i] == 0x02 else { throw OpenPGPError.invalidDER("expected INTEGER") }
            i += 1
            let len = try length()
            guard i + len <= bytes.count else { throw OpenPGPError.truncated }
            var v = Array(bytes[i..<(i + len)])
            i += len
            while v.count > 1 && v[0] == 0x00 { v.removeFirst() } // drop DER sign padding
            return Data(v)
        }
        return (try integer(), try integer())
    }

    private func ecPoint(of key: P256.Signing.PrivateKey) -> ECPoint {
        let x963 = key.publicKey.x963Representation
        return ECPoint(x: x963.subdata(in: 1..<33), y: x963.subdata(in: 33..<65))
    }

    private func ecdsaSigner(_ key: P256.Signing.PrivateKey)
        -> (_ digest: Data, _ hash: PGPHashAlgorithm) throws -> (r: Data, s: Data) {
        { digest, _ in
            let d = try P256.Signing.ECDSASignature(rawRepresentation: key.signature(for: RawDigestShim(digest)).rawRepresentation)
            let raw = d.rawRepresentation
            return (raw.prefix(32), raw.suffix(32))
        }
    }

    /// A `Digest` wrapper so CryptoKit signs the precomputed OpenPGP digest.
    private struct RawDigestShim: Digest {
        static var byteCount: Int { 32 }
        let bytes: [UInt8]
        init(_ d: Data) { bytes = [UInt8](d.prefix(32)) }
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try bytes.withUnsafeBytes(body)
        }
        static func == (l: Self, r: Self) -> Bool { l.bytes == r.bytes }
        func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
    }

    // MARK: - Unit-level assertions on the additions

    /// `signingAlgorithmByte` must land in the hashed prefix (octet 3 of the v4
    /// signature data), because the trailer covers it and gpg re-derives it.
    func testSigningAlgorithmByteAppearsInHashedPrefix() throws {
        let created: UInt32 = 1_700_000_000
        let key = P256.Signing.PrivateKey()
        let ec = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa, point: ecPoint(of: key))

        let rsaBuilder = PGPSignatureBuilder(type: .subkeyBinding, hashAlgorithm: .sha256, signingAlgorithmByte: 1)
        rsaBuilder.addHashed(.signatureCreationTime(created))
        let rsaHashed = rsaBuilder.toBeHashed(over: .primaryKey(primary: ec))

        let ecdsaBuilder = PGPSignatureBuilder(type: .subkeyBinding, hashAlgorithm: .sha256, signingKeyAlgorithm: .ecdsa)
        ecdsaBuilder.addHashed(.signatureCreationTime(created))
        let ecdsaHashed = ecdsaBuilder.toBeHashed(over: .primaryKey(primary: ec))

        // The preimages differ in exactly one octet: the pk-algo in the signature
        // data (1 vs 19), which sits right after the key material + 0x04 + type.
        XCTAssertEqual(rsaHashed.count, ecdsaHashed.count)
        let diffs = zip(rsaHashed, ecdsaHashed).filter { $0 != $1 }
        XCTAssertEqual(diffs.count, 1, "only the pk-algo octet should differ")
        XCTAssertEqual(diffs.first?.0, 1)
        XCTAssertEqual(diffs.first?.1, 19)
    }

    /// The ECDSA `(r, s)` path and the generic `mpis: [r, s]` path must produce
    /// byte-identical output, so the refactor cannot have changed behavior.
    func testFinalizeMPIsMatchesLegacyRSPath() throws {
        let created: UInt32 = 1_700_000_000
        let key = P256.Signing.PrivateKey()
        let primary = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa, point: ecPoint(of: key))
        let builder = PGPSignatureBuilder(type: .positiveCertification)
        builder.addHashed(.signatureCreationTime(created))
        builder.addUnhashed(.issuerKeyID(primary.keyID))

        let r = Data(repeating: 0x11, count: 32)
        let s = Data(repeating: 0x22, count: 32)
        let target = PGPSignatureTarget.primaryKey(primary: primary)
        let legacy = try builder.finalizePacket(over: target, r: r, s: s)
        let generic = try builder.finalizePacket(over: target, mpis: [r, s])
        XCTAssertEqual(legacy, generic)
    }

    /// `.raw` must reproduce exactly what the typed `.subkey` target hashes.
    func testRawTargetMatchesTypedSubkeyTarget() throws {
        let created: UInt32 = 1_700_000_000
        let a = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa,
                                   point: ecPoint(of: P256.Signing.PrivateKey()))
        let b = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa,
                                   point: ecPoint(of: P256.Signing.PrivateKey()))
        let builder = PGPSignatureBuilder(type: .subkeyBinding)
        builder.addHashed(.signatureCreationTime(created))
        XCTAssertEqual(builder.toBeHashed(over: .subkey(primary: a, subkey: b)),
                       builder.toBeHashed(over: .raw(a.fingerprintPreimage + b.fingerprintPreimage)))
    }

    /// `v4FingerprintPreimage` over a modeled key's body must equal that key's
    /// own preimage — the generic helper and the typed property agree.
    func testGenericFingerprintPreimageMatchesTypedKey() throws {
        let k = PGPPublicKeyPacket(creationTime: 1_700_000_000, algorithm: .ecdsa,
                                   point: ecPoint(of: P256.Signing.PrivateKey()))
        XCTAssertEqual(v4FingerprintPreimage(publicKeyBody: k.bodyData()), k.fingerprintPreimage)
    }

    /// The raw scanner must recover the exact packet bytes of a stream the typed
    /// writer produced, including for packets the typed reader cannot decode.
    func testPacketScannerRoundTrip() throws {
        let created: UInt32 = 1_700_000_000
        let rsa = try makeRSAKey(creationTime: created)
        var rsaPacket = Data([0x80 | (6 << 2) | 0x01,
                              UInt8((rsa.body.count >> 8) & 0xFF), UInt8(rsa.body.count & 0xFF)])
        rsaPacket.append(rsa.body)
        let uid = PGPUserIDPacket("Scanner <s@x.tld>")

        let stream = rsaPacket + uid.packetData()
        let scanned = try PGPPacketScanner.scan(stream)
        XCTAssertEqual(scanned.count, 2)
        XCTAssertEqual(scanned[0].tag, 6)
        XCTAssertEqual(scanned[0].body, rsa.body)
        XCTAssertEqual(scanned[0].packet, rsaPacket)
        XCTAssertEqual(scanned[1].tag, 13)
        XCTAssertEqual(scanned[1].body, uid.bodyData())
        // The typed reader cannot decode an RSA key packet; the scanner must.
        XCTAssertThrowsError(try PGPReader.parse(stream))
    }

    // MARK: - The real test: gpg accepts an RSA-signed certificate + binding

    /// Build a complete certificate whose primary is RSA: an RSA-signed 0x13
    /// self-certification and an RSA-signed 0x18 binding over an ECDSA subkey,
    /// with the subkey's own 0x19 back-signature embedded. `gpg` must import it
    /// and report every signature good.
    func testRSAPrimaryCertificateAndSubkeyBindingAcceptedByGpg() throws {
        let home = try makeHome()
        defer { try? FileManager.default.removeItem(atPath: home) }

        let created: UInt32 = 1_700_000_000
        let rsa = try makeRSAKey(creationTime: created)
        let uid = PGPUserIDPacket("RSA Primary <rsa@example.com>")

        // 0x13 self-certification, signed by the RSA primary.
        let cert = PGPSignatureBuilder(type: .positiveCertification, hashAlgorithm: .sha256, signingAlgorithmByte: 1)
        cert.addHashed(.signatureCreationTime(created))
        cert.addHashed(.keyFlags([.certify, .sign]))
        cert.addHashed(.preferredHashAlgorithms([.sha256, .sha512, .sha384]))
        cert.addHashed(.issuerFingerprint(rsa.fingerprint))
        cert.addUnhashed(.issuerKeyID(rsa.keyID))
        let certTarget = PGPSignatureTarget.raw(rsa.preimage + uid.certificationPreimage)
        let certSig = try rsa.sign(digest: cert.digest(over: certTarget), hash: .sha256)
        let certPacket = try cert.finalizePacket(over: certTarget, mpis: [certSig])

        // An ECDSA signing subkey (the Secure Enclave's role in production).
        let subKey = P256.Signing.PrivateKey()
        let subkey = PGPPublicKeyPacket(creationTime: created, algorithm: .ecdsa, point: ecPoint(of: subKey))
        let bindTarget = PGPSignatureTarget.raw(rsa.preimage + subkey.fingerprintPreimage)

        // 0x19 back-signature made by the SUBKEY (RFC 9580 cross-certification).
        let back = PGPSignatureBuilder(type: .primaryKeyBinding)
        back.addHashed(.signatureCreationTime(created))
        back.addHashed(.issuerFingerprint(subkey.fingerprint))
        back.addUnhashed(.issuerKeyID(subkey.keyID))
        let backBody = try back.buildBody(over: bindTarget, sign: ecdsaSigner(subKey))

        // 0x18 binding made by the RSA PRIMARY, one MPI.
        let bind = PGPSignatureBuilder(type: .subkeyBinding, hashAlgorithm: .sha256, signingAlgorithmByte: 1)
        bind.addHashed(.signatureCreationTime(created))
        bind.addHashed(.keyFlags([.sign]))
        bind.addHashed(.issuerFingerprint(rsa.fingerprint))
        bind.addHashed(.embeddedSignature(backBody))
        bind.addUnhashed(.issuerKeyID(rsa.keyID))
        let bindSig = try rsa.sign(digest: bind.digest(over: bindTarget), hash: .sha256)
        let bindPacket = try bind.finalizePacket(over: bindTarget, mpis: [bindSig])

        // Assemble the transferable public key by hand (the primary is RSA, so
        // PGPTransferablePublicKey's typed primary cannot represent it).
        var rsaPacket = Data([0x80 | (6 << 2) | 0x01,
                              UInt8((rsa.body.count >> 8) & 0xFF), UInt8(rsa.body.count & 0xFF)])
        rsaPacket.append(rsa.body)
        var stream = rsaPacket
        stream.append(uid.packetData())
        stream.append(certPacket)
        stream.append(subkey.packetData(subkey: true))
        stream.append(bindPacket)

        let imp = try gpg(home, ["--import"], input: Data(Armor.armor(stream, type: .publicKey).utf8))
        XCTAssertTrue(imp.code == 0 || imp.err.contains("imported"), "import failed: \(imp.err)")

        let fpr = rsa.fingerprint.hexUpper
        let check = try gpg(home, ["--check-signatures", fpr])
        let combined = (check.out + check.err).lowercased()
        XCTAssertFalse(combined.contains("bad signature"), "gpg rejected a signature:\n\(check.out)\(check.err)")
        XCTAssertFalse(combined.contains("no valid binding"), "binding rejected:\n\(check.out)\(check.err)")
        XCTAssertTrue(check.out.contains("2 good signatures") || combined.contains("good signature"),
                      "expected good signatures, got:\n\(check.out)\(check.err)")

        // gpg only grants the [S] capability when the 0x19 cross-certification
        // verifies, so this line proves the back-signature was accepted too.
        XCTAssertTrue(check.out.contains("[S]"),
                      "signing subkey not usable (cross-certification rejected?):\n\(check.out)")

        // And the packet really is an RSA (algo 1) signature over an ECDSA subkey.
        let exported = try gpgData(home, ["--export", fpr])
        let packets = try PGPPacketScanner.scan(exported)
        let sigs = packets.filter { $0.tag == 2 }
        XCTAssertTrue(sigs.allSatisfy { $0.body[$0.body.startIndex + 2] == 1 },
                      "expected every issued signature to declare algo 1 (RSA)")
    }

    private func gpgData(_ home: String, _ args: [String]) throws -> Data {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: try requireGpg())
        proc.arguments = ["--homedir", home, "--batch", "--no-tty"] + args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        proc.standardInput = FileHandle.nullDevice
        try proc.run()
        let d = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return d
    }
}
