import Foundation
import SEPKit
import OpenPGPKit

/// Map a store record's role to its OpenPGP public-key algorithm. `KeyRole` has
/// this mapping too, but it is internal to SEPKit.
func algorithm(for role: KeyRole) -> PGPPublicKeyAlgorithm {
    role == .signing ? .ecdsa : .ecdh
}

/// Process-wide handles the subcommands share: the key store and the loaded
/// config, plus the config root so `policy` can persist changes.
struct CLIContext {
    let store: KeyStore
    var config: Config
    let configRoot: URL?

    static func load() -> CLIContext {
        let store = KeyStore()
        let config = (try? Config.load()) ?? Config()
        return CLIContext(store: store, config: config, configRoot: nil)
    }
}

/// Small parsing helpers over `gpg --with-colons` listings.
enum GpgKeyring {
    /// The primary key's keygrip (uppercase hex) for `fpr`, from
    /// `--with-keygrip --list-keys`. Returns the first `grp:` line (the primary).
    static func primaryKeygrip(fpr: String) -> String? {
        let listing = Tools.gpgRun(["--with-colons", "--with-keygrip", "--list-keys", fpr]).outString
        for line in listing.split(separator: "\n") where line.hasPrefix("grp:") {
            let fields = line.split(separator: ":", omittingEmptySubsequences: false)
            if fields.count > 9 { return String(fields[9]).uppercased() }
        }
        return nil
    }

    /// All keygrips (uppercase) visible in the public keyring.
    static func visibleKeygrips() -> Set<String> {
        let listing = Tools.gpgRun(["--with-colons", "--with-keygrip", "--list-keys"]).outString
        var grips = Set<String>()
        for line in listing.split(separator: "\n") where line.hasPrefix("grp:") {
            let fields = line.split(separator: ":", omittingEmptySubsequences: false)
            if fields.count > 9 { grips.insert(String(fields[9]).uppercased()) }
        }
        return grips
    }

    /// Whether a key with `fpr` exists in the public keyring.
    static func hasKey(fpr: String) -> Bool {
        Tools.gpgRun(["--list-keys", fpr]).code == 0
    }
}
