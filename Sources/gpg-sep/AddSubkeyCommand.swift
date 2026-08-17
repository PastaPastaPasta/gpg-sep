import Foundation
import CryptoKit
import SEPKit
import OpenPGPKit

/// `gpg-sep add-subkey --to <primary-fpr>` — bind a new enclave subkey under an
/// existing primary already in the user's keyring. The primary may live on a
/// YubiKey/card (RSA) or on disk (ECDSA); its 0x18 binding signature is produced
/// by the running gpg-agent, and — for a signing subkey — a 0x19 back-signature
/// is produced by the enclave subkey itself (RFC 9580 requires it).
enum AddSubkeyCommand {
    static let spec = ArgSpec(
        value: ["to", "role", "expire", "presence", "grace"],
        flags: ["force-software"])

    static let usage = """
    usage: gpg-sep add-subkey --to <primary-fpr> [--role sign|encrypt] [options]
      --to <fpr>              fingerprint of an existing primary in the keyring (required)
      --role sign|encrypt     subkey role (default sign)
      --expire <2y|30d|0>     validity; 0 = no expiration (default 2y)
      --presence <policy>     none|presence|biometry|biometryCurrentSet
      --grace <seconds>       Touch ID reuse window
      --force-software        use a software subkey (TEST/CI; not the enclave)
    """

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }

        let primaryFpr = try args.require("to").uppercased()
        let roleString = args.string("role") ?? "sign"
        let role: KeyRole
        switch roleString {
        case "sign": role = .signing
        case "encrypt": role = .encryption
        default: throw CLIError("invalid --role '\(roleString)' (want sign|encrypt)")
        }
        let expire = try Options.expirySeconds(args.string("expire") ?? "2y")
        let policy = try Options.resolvePolicy(args, config: context.config)
        let forceSoftware = args.has("force-software")
        let creation = Options.now()

        // 1. Fetch the existing primary's public key packet (raw — it may be RSA,
        //    which this module does not model) and its keygrip.
        guard GpgKeyring.hasKey(fpr: primaryFpr) else {
            throw CLIError("primary \(primaryFpr) not found in the gpg keyring")
        }
        let export = Tools.gpgRun(["--export", primaryFpr]).out
        guard !export.isEmpty else { throw CLIError("gpg --export produced nothing for \(primaryFpr)") }
        let rawPackets = try PGPPacketScanner.scan(export)
        guard let primaryRaw = rawPackets.first(where: { $0.tag == 6 }) else {
            throw CLIError("no primary public-key packet in export of \(primaryFpr)")
        }
        let primaryBody = primaryRaw.body
        guard primaryBody.count >= 6 else { throw CLIError("primary key packet too short") }
        let primaryAlgoByte = primaryBody[primaryBody.startIndex + 5]
        let primaryPreimage = v4FingerprintPreimage(publicKeyBody: primaryBody)
        let primaryFingerprint = OpenPGPHash.sha1(primaryPreimage)
        let primaryKeyID = primaryFingerprint.suffix(8)

        guard let primaryGrip = GpgKeyring.primaryKeygrip(fpr: primaryFpr) else {
            throw CLIError("could not determine the keygrip for \(primaryFpr)")
        }

        // 2. Generate the enclave subkey.
        let subkeyRecord: EnclaveKeyRecord
        switch role {
        case .signing:
            subkeyRecord = try context.store.generateSigningKey(
                policy: policy, label: "subkey-sign", creationTime: creation, forceSoftware: forceSoftware)
        case .encryption:
            subkeyRecord = try context.store.generateEncryptionKey(
                policy: policy, label: "subkey-encrypt", creationTime: creation, forceSoftware: forceSoftware)
        }
        let subkey = PGPPublicKeyPacket(
            creationTime: creation, algorithm: algorithm(for: role), point: subkeyRecord.point)

        // The subkey-binding preimage: primary fingerprint preimage || subkey.
        let bindingPreimage = primaryPreimage + subkey.fingerprintPreimage

        // 3. For a signing subkey, the enclave subkey makes a 0x19 back-signature.
        var backSigBody: Data?
        if role == .signing {
            let auth = AuthSession(defaultGraceSeconds: policy.graceSeconds)
            let subSigner = try context.store.signingBackend(
                keygripHex: subkeyRecord.keygripHex,
                context: auth.context(forKeygrip: subkeyRecord.keygripHex, graceSeconds: policy.graceSeconds))
            let backSig = PGPSignatureBuilder(type: .primaryKeyBinding)
            backSig.addHashed(.signatureCreationTime(creation))
            backSig.addHashed(.issuerFingerprint(subkey.fingerprint))
            backSig.addUnhashed(.issuerKeyID(subkey.keyID))
            backSigBody = try backSig.buildBody(over: .raw(bindingPreimage)) { digest, hash in
                try subSigner.sign(digest: digest, hash: hash)
            }
        }

        // 4. Build the 0x18 binding, hashed under the PRIMARY's algorithm, and get
        //    the primary to sign it via the running gpg-agent.
        let binding = PGPSignatureBuilder(
            type: .subkeyBinding, hashAlgorithm: .sha256, signingAlgorithmByte: primaryAlgoByte)
        binding.addHashed(.signatureCreationTime(creation))
        binding.addHashed(.keyFlags(role == .signing ? [.sign] : [.encryptCommunications, .encryptStorage]))
        if expire != 0 { binding.addHashed(.keyExpirationTime(expire)) }
        binding.addHashed(.issuerFingerprint(primaryFingerprint))
        if let backSigBody { binding.addHashed(.embeddedSignature(backSigBody)) }
        binding.addUnhashed(.issuerKeyID(primaryKeyID))

        let digest = binding.digest(over: .raw(bindingPreimage))
        Tools.launchAgent()
        let socket = Tools.agentSocket()
        guard !socket.isEmpty else { throw CLIError("could not determine the gpg-agent socket") }
        let signature = try AgentSigner.sign(socket: socket, keygripHex: primaryGrip, digest: digest)
        let bindingPacket = try binding.finalizePacket(over: .raw(bindingPreimage), mpis: signature.mpis)

        // 5. Emit a merge block: the full exported primary + the new subkey + binding.
        var merged = export
        merged.append(subkey.packetData(subkey: true))
        merged.append(bindingPacket)
        let armored = Armor.armor(merged, type: .publicKey)

        let imp = Tools.gpgRun(["--import"], input: Data(armored.utf8))
        guard imp.code == 0 || imp.err.contains("imported") || imp.err.contains("not changed")
            || imp.err.contains("new subkey") else {
            throw CLIError("gpg --import of the merged subkey failed:\n\(imp.err)")
        }

        // 6. Verify the new binding.
        let check = Tools.gpgRun(["--check-signatures", primaryFpr])
        let lowered = (check.err + check.outString).lowercased()
        let bindingOK = !lowered.contains("bad signature") && !lowered.contains("no valid binding")

        print("Added enclave \(role == .signing ? "signing" : "encryption") subkey under \(primaryFpr)")
        print("  subkey grip : \(subkeyRecord.keygripHex)  (backend=\(subkeyRecord.backend))")
        print("  subkey fpr  : \(subkey.fingerprint.hexUpperString)")
        print("  primary algo: \(algoName(primaryAlgoByte)) (\(primaryAlgoByte))")
        print("  binding     : \(bindingOK ? "Good (gpg --check-signatures)" : "REVIEW: gpg reported an issue")")
        if !bindingOK {
            printErr(check.err)
            throw CLIError("subkey binding did not verify cleanly")
        }
    }

    static func algoName(_ b: UInt8) -> String {
        switch b {
        case 1: return "RSA"
        case 18: return "ECDH"
        case 19: return "ECDSA"
        case 22: return "EdDSA"
        default: return "algo"
        }
    }
}

/// SHA-1 over arbitrary bytes, for v4 fingerprints of keys OpenPGPKit does not
/// model natively (an RSA primary). `Insecure.SHA1` is exactly the hash OpenPGP
/// v4 fingerprints are defined over.
enum OpenPGPHash {
    static func sha1(_ data: Data) -> Data { Data(Insecure.SHA1.hash(data: data)) }
}
