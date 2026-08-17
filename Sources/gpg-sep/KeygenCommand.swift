import Foundation
import SEPKit
import OpenPGPKit

/// `gpg-sep keygen` — create a standalone, fully enclave-born OpenPGP
/// certificate: an ECDSA signing primary (certify+sign), a UID self-certified by
/// the enclave, an optional ECDH encryption subkey, and a pre-generated
/// revocation certificate written to the store.
enum KeygenCommand {
    static let spec = ArgSpec(
        value: ["uid", "expire", "presence", "grace"],
        flags: ["with-encryption-subkey", "export-only", "force-software"])

    static let usage = """
    usage: gpg-sep keygen --uid "Name <email>" [options]
      --uid "Name <email>"        identity for the certificate (required)
      --expire <2y|30d|0>         validity; 0 = no expiration (default 2y)
      --with-encryption-subkey    also create an enclave ECDH encryption subkey
      --presence <policy>         none|presence|biometry|biometryCurrentSet
      --grace <seconds>           Touch ID reuse window
      --export-only               print the armored key; do not import into gpg
      --force-software            use a software key (TEST/CI; not the enclave)
    """

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }

        let uidString = try args.require("uid")
        let expire = try Options.expirySeconds(args.string("expire") ?? "2y")
        let policy = try Options.resolvePolicy(args, config: context.config)
        let forceSoftware = args.has("force-software")
        let withEncryption = args.has("with-encryption-subkey")
        let creation = Options.now()

        let store = context.store
        let auth = AuthSession(defaultGraceSeconds: policy.graceSeconds)

        // 1. Enclave signing primary (ECDSA, certify+sign).
        let primaryRecord = try store.generateSigningKey(
            policy: policy, label: "keygen-primary", creationTime: creation, forceSoftware: forceSoftware)
        let primary = PGPPublicKeyPacket(creationTime: creation, algorithm: .ecdsa, point: primaryRecord.point)
        let uid = PGPUserIDPacket(uidString)
        let primarySigner = try store.signingBackend(
            keygripHex: primaryRecord.keygripHex,
            context: auth.context(forKeygrip: primaryRecord.keygripHex, graceSeconds: policy.graceSeconds))
        func signPrimary(_ digest: Data, _ hash: PGPHashAlgorithm) throws -> (r: Data, s: Data) {
            try primarySigner.sign(digest: digest, hash: hash)
        }

        // 2. Self-certification (0x13).
        let cert = PGPSignatureBuilder(type: .positiveCertification)
        cert.addHashed(.signatureCreationTime(creation))
        cert.addHashed(.keyFlags([.certify, .sign]))
        cert.addHashed(.preferredHashAlgorithms([.sha256, .sha512, .sha384]))
        if expire != 0 { cert.addHashed(.keyExpirationTime(expire)) }
        cert.addHashed(.issuerFingerprint(primary.fingerprint))
        cert.addUnhashed(.issuerKeyID(primary.keyID))
        let certPacket = try cert.build(over: .certification(primary: primary, userID: uid), sign: signPrimary)

        var subkeys: [PGPTransferablePublicKey.BoundSubkey] = []
        var encryptionRecord: EnclaveKeyRecord?

        // 3. Optional ECDH encryption subkey with a 0x18 binding.
        if withEncryption {
            let encRecord = try store.generateEncryptionKey(
                policy: policy, label: "keygen-encrypt", creationTime: creation, forceSoftware: forceSoftware)
            encryptionRecord = encRecord
            let subkey = PGPPublicKeyPacket(creationTime: creation, algorithm: .ecdh, point: encRecord.point)
            let binding = PGPSignatureBuilder(type: .subkeyBinding)
            binding.addHashed(.signatureCreationTime(creation))
            binding.addHashed(.keyFlags([.encryptCommunications, .encryptStorage]))
            if expire != 0 { binding.addHashed(.keyExpirationTime(expire)) }
            binding.addHashed(.issuerFingerprint(primary.fingerprint))
            binding.addUnhashed(.issuerKeyID(primary.keyID))
            let bindingPacket = try binding.build(over: .subkey(primary: primary, subkey: subkey), sign: signPrimary)
            subkeys.append(.init(subkey: subkey, binding: bindingPacket))
        }

        // 4. Pre-generate a revocation certificate (0x20, "key no longer used").
        let revPacket = try buildRevocation(primary: primary, creation: creation, sign: signPrimary)
        let revPath = try writeRevocation(store: store, fingerprint: primary.fingerprint, packet: revPacket)

        // 5. Assemble + import (or just print).
        let tpk = PGPTransferablePublicKey(
            primary: primary,
            userIDs: [.init(userID: uid, certification: certPacket)],
            subkeys: subkeys)
        let armored = tpk.armored()

        if args.has("export-only") {
            print(armored)
        } else {
            let imp = Tools.gpgRun(["--import"], input: Data(armored.utf8))
            guard imp.code == 0 || imp.err.contains("imported") || imp.err.contains("not changed") else {
                throw CLIError("gpg --import failed:\n\(imp.err)")
            }
        }

        // 6. Report.
        print("Created enclave OpenPGP certificate")
        print("  fingerprint : \(primary.fingerprint.hexUpperString)")
        print("  primary grip: \(primaryRecord.keygripHex)  (ECDSA sign+certify, backend=\(primaryRecord.backend))")
        if let encryptionRecord {
            print("  subkey grip : \(encryptionRecord.keygripHex)  (ECDH encrypt, backend=\(encryptionRecord.backend))")
        }
        print("  uid         : \(uidString)")
        print("  expires     : \(expire == 0 ? "never" : "\(expire)s from creation")")
        print("  revcert     : \(revPath)")
        if args.has("export-only") {
            print("  (export-only: not imported into the gpg keyring)")
        } else {
            print("  imported into the gpg keyring")
        }
    }

    /// Build a primary-key revocation signature (0x20) over the primary,
    /// reason code 3 ("key is no longer used").
    static func buildRevocation(
        primary: PGPPublicKeyPacket, creation: UInt32,
        sign: (_ digest: Data, _ hash: PGPHashAlgorithm) throws -> (r: Data, s: Data)
    ) throws -> Data {
        let rev = PGPSignatureBuilder(type: .keyRevocation)
        rev.addHashed(.signatureCreationTime(creation))
        rev.addHashed(.reasonForRevocation(code: 3, reason: "key no longer used"))
        rev.addHashed(.issuerFingerprint(primary.fingerprint))
        rev.addUnhashed(.issuerKeyID(primary.keyID))
        return try rev.build(over: .primaryKey(primary: primary), sign: sign)
    }

    /// Write an armored revocation cert to `<store>/revocations/<fpr>.rev` (0600),
    /// returning its path.
    ///
    /// The armor type is `PGP PUBLIC KEY BLOCK`, matching what GnuPG itself
    /// writes into `openpgp-revocs.d`: gpg refuses a bare revocation signature
    /// wrapped in a `PGP SIGNATURE` block ("no valid OpenPGP data found").
    static func writeRevocation(store: KeyStore, fingerprint: Data, packet: Data) throws -> String {
        let dir = store.root.appendingPathComponent("revocations", isDirectory: true)
        try FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let url = dir.appendingPathComponent("\(fingerprint.hexUpperString).rev", isDirectory: false)
        let body = "This is a revocation certificate for the OpenPGP key with fingerprint\n"
            + "\(fingerprint.hexUpperString), pre-generated by gpg-sep.\n\n"
            + "A revocation certificate is a kind of \"kill switch\": importing and publishing\n"
            + "it permanently declares the key unusable. That cannot be retracted. Because a\n"
            + "Secure Enclave key can never be backed up, keep this file — it is the only way\n"
            + "to retire the key if the machine is lost.\n\n"
            + "Publish it with: gpg-sep revoke \(fingerprint.hexUpperString)\n\n"
            + Armor.armor(packet, type: .publicKey)
        try Data(body.utf8).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        return url.path
    }
}
