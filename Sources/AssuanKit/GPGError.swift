import Foundation

/// gpg-error numeric codes and the source/code packing used on the Assuan wire.
///
/// A libgpg-error error number is a 32-bit value: bits 24..30 are the *source*
/// (7 bits) and bits 0..23 are the *code* (24 bits); bit 31 is reserved and
/// always zero in practice. So the wire number is `(source << 24) | code`.
///
/// Verified against the live Homebrew gpg-agent 2.5.20 on this machine: an
/// unknown command yields the ERR line `ERR 67109139 Unknown IPC command <GPG
/// Agent>`, and `gpg-error 67109139` decodes that to
/// `(4, 275) = (GPG_ERR_SOURCE_GPGAGENT, GPG_ERR_ASS_UNKNOWN_CMD)`.
/// All numeric constants below were cross-checked with the `gpg-error` tool.
public enum GPGErrorSource {
    /// GPG_ERR_SOURCE_UNKNOWN — used when the emitter did not tag a source.
    public static let unknown: UInt32 = 0
    /// GPG_ERR_SOURCE_GPGAGENT — what gpg-agent stamps on its own errors.
    public static let gpgAgent: UInt32 = 4
}

/// Common libgpg-error codes (the low 24 bits), verified with the `gpg-error`
/// CLI on this host. These are the *bare* codes; combine with a source via
/// ``gpgError(_:source:)`` to get the number that goes on the wire.
public enum GPGError: UInt32 {
    case noError = 0
    case general = 1
    case badSignature = 8
    case noPubkey = 9
    /// GPG_ERR_NO_SECKEY = 17
    case noSeckey = 17
    /// GPG_ERR_INV_VALUE = 55
    case invValue = 55
    /// GPG_ERR_NO_AGENT = 77 — no backend gpg-agent is reachable.
    case noAgent = 77
    /// GPG_ERR_NOT_IMPLEMENTED = 69
    case notImplemented = 69
    /// GPG_ERR_INV_SEXP = 83
    case invSexp = 83
    /// GPG_ERR_UNSUPPORTED_ALGORITHM = 84
    case unsupportedAlgorithm = 84
    /// GPG_ERR_NO_PIN_ENTRY = 85
    case noPinEntry = 85
    /// GPG_ERR_CANCELED = 99
    case canceled = 99
    /// GPG_ERR_UNKNOWN_COMMAND = 175 (a generic "unknown command")
    case unknownCommand = 175
    /// GPG_ERR_ASS_INCOMPLETE_LINE = 262 — Assuan layer: line with no newline.
    case assIncompleteLine = 262
    /// GPG_ERR_ASS_UNKNOWN_CMD = 275 — what gpg-agent emits for a bad verb.
    case assUnknownCmd = 275

    /// The wire number for this code stamped with the given source.
    public func number(source: UInt32 = GPGErrorSource.gpgAgent) -> UInt32 {
        gpgError(rawValue, source: source)
    }
}

/// Pack a bare 24-bit code and a 7-bit source into the 32-bit wire number.
///
/// `source` defaults to GPG_ERR_SOURCE_GPGAGENT (4) because this library's
/// server side impersonates gpg-agent.
public func gpgError(_ code: UInt32, source: UInt32 = GPGErrorSource.gpgAgent) -> UInt32 {
    ((source & 0x7F) << 24) | (code & 0x00FF_FFFF)
}

/// Split a wire error number back into (source, code).
public func gpgErrorComponents(_ number: UInt32) -> (source: UInt32, code: UInt32) {
    ((number >> 24) & 0x7F, number & 0x00FF_FFFF)
}

/// A parsed `ERR` response, carrying the raw wire number plus its decomposition.
public struct AssuanError: Error, Equatable {
    public let number: UInt32
    public let text: String?
    public var source: UInt32 { gpgErrorComponents(number).source }
    public var code: UInt32 { gpgErrorComponents(number).code }

    public init(number: UInt32, text: String? = nil) {
        self.number = number
        self.text = text
    }

    public init(code: GPGError, source: UInt32 = GPGErrorSource.gpgAgent, text: String? = nil) {
        self.number = code.number(source: source)
        self.text = text
    }
}
