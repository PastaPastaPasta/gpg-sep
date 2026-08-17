import Foundation
import SEPKit

/// Shared option parsing: durations, presence policies, and building the key
/// policy from `--presence`/`--grace` on top of the configured defaults.
enum Options {
    /// Parse an expiry like `2y`, `18m`, `12w`, `30d`, `48h`, `3600` (bare =
    /// seconds) into a number of seconds. `0` means "no expiration".
    /// Months are 30 days, years 365 days (matching gpg's coarse arithmetic).
    static func expirySeconds(_ raw: String) throws -> UInt32 {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { throw CLIError("empty --expire value") }
        let unit = trimmed.last!
        let multipliers: [Character: UInt64] = [
            "s": 1, "h": 3600, "d": 86400, "w": 604800, "m": 2592000, "y": 31536000,
        ]
        if let mult = multipliers[unit] {
            let numberPart = String(trimmed.dropLast())
            guard let n = UInt64(numberPart) else {
                throw CLIError("malformed --expire value '\(raw)'")
            }
            let seconds = n * mult
            guard seconds <= UInt64(UInt32.max) else { throw CLIError("--expire too large") }
            return UInt32(seconds)
        }
        guard let n = UInt64(trimmed) else { throw CLIError("malformed --expire value '\(raw)'") }
        guard n <= UInt64(UInt32.max) else { throw CLIError("--expire too large") }
        return UInt32(n)
    }

    static func presence(_ raw: String) throws -> PresencePolicy {
        guard let p = PresencePolicy(rawValue: raw) else {
            throw CLIError("invalid --presence '\(raw)' (want none|presence|biometry|biometryCurrentSet)")
        }
        return p
    }

    /// Resolve the effective key policy from CLI flags over the config default.
    static func resolvePolicy(_ args: ParsedArgs, config: Config) throws -> KeyPolicy {
        var policy = config.defaultPolicy
        if let p = args.string("presence") { policy.presence = try presence(p) }
        if let g = try args.int("grace") { policy.graceSeconds = g }
        return policy
    }

    /// Current wall-clock as a v4 creation-time octet count.
    static func now() -> UInt32 { UInt32(Date().timeIntervalSince1970) }
}
