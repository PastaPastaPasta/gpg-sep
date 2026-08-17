import Foundation
import SEPKit

/// `gpg-sep policy` — show or update the default policy (in the config) or a
/// single key's policy (in its store record).
///
/// Important asymmetry, surfaced to the user: `graceSeconds` is applied at
/// *use* time (it configures the `LAContext` reuse window), so changing it takes
/// effect immediately. `presence` is baked into the enclave key's access control
/// at *creation* time and cannot be changed afterwards — updating it on an
/// existing key only changes the record's bookkeeping, not what the Secure
/// Enclave enforces.
enum PolicyCommand {
    static let spec = ArgSpec(value: ["set-grace", "set-presence"])

    static let usage = """
    usage: gpg-sep policy [--set-grace <seconds>] [--set-presence <policy>] [<keygrip>]
      with no <keygrip>: show or update the DEFAULT policy for new keys (config)
      with a <keygrip>:  show or update that key's stored policy
      --set-grace <n>       Touch ID reuse window in seconds (0 = every use)
      --set-presence <p>    none|presence|biometry|biometryCurrentSet
    """

    static func run(_ argv: [String], context: CLIContext) throws {
        let args = try ArgParser.parse(argv, spec: spec)
        if args.has("help") { print(usage); return }

        let newGrace = try args.int("set-grace")
        let newPresence = try args.string("set-presence").map(Options.presence)
        let mutating = newGrace != nil || newPresence != nil

        guard let keygrip = args.positionals.first else {
            try runDefault(context: context, grace: newGrace, presence: newPresence, mutating: mutating)
            return
        }
        try runPerKey(context: context, keygrip: keygrip.uppercased(),
                      grace: newGrace, presence: newPresence, mutating: mutating)
    }

    // MARK: Default policy (config)

    private static func runDefault(context: CLIContext, grace: Int?, presence: PresencePolicy?,
                                   mutating: Bool) throws {
        var config = context.config
        if let grace {
            guard grace >= 0 else { throw CLIError("--set-grace must be >= 0") }
            config.defaultPolicy.graceSeconds = grace
        }
        if let presence { config.defaultPolicy.presence = presence }
        if mutating {
            try config.save(root: context.configRoot)
            print("Updated the default policy for newly generated keys:")
        } else {
            print("Default policy for newly generated keys:")
        }
        print("  presence : \(config.defaultPolicy.presence.rawValue)")
        print("  grace    : \(config.defaultPolicy.graceSeconds)s")
        print("  (config  : \(Config.defaultConfigRoot().appendingPathComponent("config.json").path))")
    }

    // MARK: Per-key policy (store record)

    private static func runPerKey(context: CLIContext, keygrip: String, grace: Int?,
                                  presence: PresencePolicy?, mutating: Bool) throws {
        guard var record = try context.store.record(keygripHex: keygrip) else {
            throw CLIError("no gpg-sep key with keygrip \(keygrip)")
        }
        if let grace {
            guard grace >= 0 else { throw CLIError("--set-grace must be >= 0") }
            record.policy.graceSeconds = grace
        }
        if let presence { record.policy.presence = presence }
        if mutating {
            try writeRecord(record, store: context.store)
            print("Updated the stored policy for \(keygrip):")
        } else {
            print("Policy for \(keygrip):")
        }
        print("  label    : \(record.label)")
        print("  role     : \(record.role.rawValue)")
        print("  backend  : \(record.backend)")
        print("  presence : \(record.policy.presence.rawValue)")
        print("  grace    : \(record.policy.graceSeconds)s")
        if presence != nil, record.backend == BackendKind.secureEnclave {
            printErr("""
            warning: the Secure Enclave binds a key's access control at creation time.
                     Changing --set-presence updates gpg-sep's record only; the enclave
                     still enforces the policy the key was created with. Generate a new
                     key to actually change the presence requirement.
            """)
        }
    }

    /// Persist an updated record. `KeyStore` intentionally exposes no mutation
    /// API (keys are write-once), so policy edits rewrite the public, Codable
    /// record JSON in place with the store's 0600/0700 permissions.
    static func writeRecord(_ record: EnclaveKeyRecord, store: KeyStore) throws {
        let keysDir = store.root.appendingPathComponent("keys", isDirectory: true)
        let url = keysDir.appendingPathComponent("\(record.keygripHex.uppercased()).json", isDirectory: false)
        guard FileManager.default.fileExists(atPath: url.path) else {
            throw CLIError("store record missing at \(url.path)")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(record).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
