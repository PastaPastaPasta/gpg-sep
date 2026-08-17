import Foundation

// gpg-sep: the CLI that creates and manages OpenPGP keys born in the Apple
// Secure Enclave. Argument parsing is hand-rolled (see ArgParser.swift) so the
// package has zero external dependencies.

let topLevelUsage = """
gpg-sep — OpenPGP keys born and held in the Apple Secure Enclave

usage: gpg-sep <command> [options]

Key management
  keygen        create a standalone enclave-born certificate (+ revocation cert)
  add-subkey    bind a new enclave subkey under an existing primary
  list          show enclave keys in the store
  export        print a public key in armored form
  revoke        publish a pre-generated revocation certificate
  policy        show or update the default / per-key policy

Deployment
  install       take over the gpg-agent socket via a launchd LaunchAgent
  uninstall     hand the socket back to the stock gpg-agent (idempotent)
  doctor        diagnostics and an end-to-end sign/verify self-test

Run `gpg-sep <command> --help` for a command's options.

Environment
  GPG_SEP_HOME    key store root (default ~/.local/share/gpg-sep)
  GPG_SEP_CONFIG  config root    (default ~/.config/gpg-sep)
  GNUPGHOME       the gpg home the CLI operates on
"""

func runCLI(_ argv: [String]) -> Int32 {
    guard let command = argv.first else {
        print(topLevelUsage)
        return 2
    }
    if command == "--help" || command == "-h" || command == "help" {
        print(topLevelUsage)
        return 0
    }
    if command == "--version" {
        print("gpg-sep 0.1.0")
        return 0
    }

    let rest = Array(argv.dropFirst())
    let context = CLIContext.load()
    do {
        switch command {
        case "keygen":      try KeygenCommand.run(rest, context: context)
        case "add-subkey":  try AddSubkeyCommand.run(rest, context: context)
        case "list":        try ListCommand.run(rest, context: context)
        case "export":      try ExportCommand.run(rest, context: context)
        case "revoke":      try RevokeCommand.run(rest, context: context)
        case "policy":      try PolicyCommand.run(rest, context: context)
        case "install":     try InstallCommand.run(rest, context: context)
        case "uninstall":   try UninstallCommand.run(rest, context: context)
        case "doctor":      try DoctorCommand.run(rest, context: context)
        default:
            printErr("gpg-sep: unknown command '\(command)'\n")
            printErr(topLevelUsage)
            return 2
        }
        return 0
    } catch let e as ExitCode {
        return e.code
    } catch let e as CLIError {
        printErr("gpg-sep: \(e.message)")
        return 1
    } catch {
        printErr("gpg-sep: \(error)")
        return 1
    }
}

exit(runCLI(Array(CommandLine.arguments.dropFirst())))
