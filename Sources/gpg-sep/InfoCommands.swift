import Foundation
import SEPKit
import OpenPGPKit

/// The v4 fingerprint of a record's key (identical whether the key ends up as a
/// primary or a subkey — a v4 fingerprint hashes only the key material).
private func fingerprint(of record: EnclaveKeyRecord) -> Data {
    PGPPublicKeyPacket(
        creationTime: record.creationTime, algorithm: algorithm(for: record.role), point: record.point
    ).fingerprint
}

/// `gpg-sep list` — show enclave keys in the store and whether gpg can see them.
enum ListCommand {
    static let spec = ArgSpec()
    static let usage = "usage: gpg-sep list"

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }

        let records = try context.store.allRecords().sorted { $0.label < $1.label }
        if records.isEmpty { print("No gpg-sep keys in the store (\(context.store.root.path))."); return }

        let visible = GpgKeyring.visibleKeygrips()
        print("gpg-sep keys in \(context.store.root.path):")
        for r in records {
            let fpr = fingerprint(of: r).hexUpperString
            let inGpg = visible.contains(r.keygripHex.uppercased()) ? "yes" : "no"
            print("""
              \(r.label)
                keygrip : \(r.keygripHex)
                fpr     : \(fpr)
                role    : \(r.role.rawValue)
                policy  : presence=\(r.policy.presence.rawValue) grace=\(r.policy.graceSeconds)s
                backend : \(r.backend)
                in gpg  : \(inGpg)
            """)
        }
    }
}

/// `gpg-sep export <fpr|keygrip>` — print the armored public key.
enum ExportCommand {
    static let spec = ArgSpec()
    static let usage = "usage: gpg-sep export <fpr|keygrip>"

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }
        guard let target = args.positionals.first else { throw CLIError("export needs a <fpr|keygrip>") }

        // Prefer gpg's own export (full cert with UIDs/sigs) when it knows the key.
        let viaFpr = Tools.gpgRun(["--armor", "--export", target])
        let armored = viaFpr.outString
        if armored.contains("BEGIN PGP PUBLIC KEY BLOCK") { print(armored); return }

        // Fall back to a keygrip lookup in the store → bare public-key packet.
        if let record = try context.store.record(keygripHex: target) {
            let packet = PGPPublicKeyPacket(
                creationTime: record.creationTime, algorithm: algorithm(for: record.role), point: record.point)
            let tpk = PGPTransferablePublicKey(primary: packet)
            printErr("note: \(target) is only in the enclave store; emitting a bare key packet "
                + "(no UID/self-signature). Use the fingerprint after import for a full certificate.")
            print(tpk.armored())
            return
        }
        throw CLIError("no key found for '\(target)' in gpg or the enclave store")
    }
}

/// `gpg-sep revoke <fpr>` — publish the pre-generated revocation certificate.
enum RevokeCommand {
    static let spec = ArgSpec(flags: ["yes", "print"])
    static let usage = """
    usage: gpg-sep revoke <fpr> [--yes] [--print]
      --yes     skip the confirmation prompt
      --print   also print the revocation certificate for distribution
    """

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }
        guard let fpr = args.positionals.first?.uppercased() else { throw CLIError("revoke needs a <fpr>") }

        let url = context.store.root
            .appendingPathComponent("revocations", isDirectory: true)
            .appendingPathComponent("\(fpr).rev", isDirectory: false)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw CLIError("no pre-generated revocation certificate at \(url.path)")
        }
        let text = try String(contentsOf: url, encoding: .utf8)

        if args.has("print") { print(text) }

        if !args.has("yes") {
            FileHandle.standardOutput.write(Data(
                "Publish (import) the revocation certificate for \(fpr)? This permanently revokes the key. [y/N] ".utf8))
            let answer = readLine(strippingNewline: true)?.lowercased() ?? ""
            guard answer == "y" || answer == "yes" else { print("Aborted."); return }
        }

        let imp = Tools.gpgRun(["--import"], input: Data(text.utf8))
        guard imp.code == 0 || imp.err.lowercased().contains("revocation") else {
            throw CLIError("importing the revocation certificate failed:\n\(imp.err)")
        }
        print("Revocation certificate for \(fpr) imported into the keyring.")
        print("Distribute the updated public key so others learn of the revocation.")
    }
}
