import Foundation

/// A tiny, dependency-free argument parser. Each subcommand declares which long
/// options take a value and which are boolean flags; everything else is a
/// positional. `swift-argument-parser` is intentionally absent so the whole tool
/// is auditable from this repo alone.
struct ArgSpec {
    /// Long option names (without `--`) that consume a following value, or use
    /// the `--name=value` form.
    let valueOptions: Set<String>
    /// Long option names (without `--`) that are boolean flags.
    let flagOptions: Set<String>

    init(value: Set<String> = [], flags: Set<String> = []) {
        // `help` is always accepted as a flag.
        self.valueOptions = value
        self.flagOptions = flags.union(["help"])
    }
}

/// The result of parsing one subcommand's arguments.
struct ParsedArgs {
    var options: [String: String] = [:]
    var flags: Set<String> = []
    var positionals: [String] = []

    func string(_ name: String) -> String? { options[name] }
    func has(_ flag: String) -> Bool { flags.contains(flag) }

    /// A required value option; throws a `CLIError` with a clear message if absent.
    func require(_ name: String) throws -> String {
        guard let v = options[name] else {
            throw CLIError("missing required option --\(name)")
        }
        return v
    }

    /// An integer value option, validated.
    func int(_ name: String) throws -> Int? {
        guard let raw = options[name] else { return nil }
        guard let v = Int(raw) else { throw CLIError("--\(name) expects an integer, got '\(raw)'") }
        return v
    }
}

enum ArgParser {
    /// Parse `args` (the tokens *after* the subcommand name) against `spec`.
    /// Rejects unknown `--options`. A bare `--` stops option parsing; remaining
    /// tokens are positionals.
    static func parse(_ args: [String], spec: ArgSpec) throws -> ParsedArgs {
        var result = ParsedArgs()
        var i = 0
        var optionsEnded = false
        while i < args.count {
            let tok = args[i]
            if optionsEnded || !tok.hasPrefix("--") {
                result.positionals.append(tok)
                i += 1
                continue
            }
            if tok == "--" {
                optionsEnded = true
                i += 1
                continue
            }
            let stripped = String(tok.dropFirst(2))
            // `--name=value` form.
            if let eq = stripped.firstIndex(of: "=") {
                let name = String(stripped[stripped.startIndex..<eq])
                let value = String(stripped[stripped.index(after: eq)...])
                guard spec.valueOptions.contains(name) else {
                    throw CLIError("unknown or non-value option --\(name)")
                }
                result.options[name] = value
                i += 1
                continue
            }
            if spec.flagOptions.contains(stripped) {
                result.flags.insert(stripped)
                i += 1
                continue
            }
            if spec.valueOptions.contains(stripped) {
                guard i + 1 < args.count else {
                    throw CLIError("option --\(stripped) requires a value")
                }
                result.options[stripped] = args[i + 1]
                i += 2
                continue
            }
            throw CLIError("unknown option --\(stripped)")
        }
        return result
    }
}

/// A user-facing CLI error. Printed to stderr; the process exits non-zero.
struct CLIError: Error, CustomStringConvertible {
    let message: String
    init(_ message: String) { self.message = message }
    var description: String { message }
}
