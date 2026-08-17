import Foundation

/// Assuan percent (and percent-plus) escaping, byte-exact.
///
/// Two related but distinct escapings live on the Assuan wire:
///
/// * **Percent** (`D` data lines): only `%`, CR and LF are escaped as `%XX`.
///   Every other byte — including high/binary bytes such as an S-expression's
///   raw MPI bytes — travels literally. Verified against live gpg-agent 2.5.20:
///   a `HAVEKEY --list` reply carries raw 20-byte keygrips inline with `%0A`
///   and `%0D` standing in for the 0x0A / 0x0D bytes and nothing else escaped.
///
/// * **Percent-plus** (command arguments): additionally a space is written as
///   `+`, so a literal `+` must itself be escaped (`%2B`). Decoding maps `+`
///   back to a space. We also `%XX`-escape control and high bytes on encode so
///   that command lines stay 7-bit clean, but decoding accepts any `%XX`.
///
/// Getting either wrong corrupts binary S-expressions, so both directions are
/// exercised by round-trip tests including `%`, CR, LF, `+`, space and >0x7F.
public enum AssuanEscaping {
    private static let hexDigits = Array("0123456789ABCDEF".utf8)

    private static func appendHex(_ byte: UInt8, to out: inout [UInt8]) {
        out.append(0x25) // '%'
        out.append(hexDigits[Int(byte >> 4)])
        out.append(hexDigits[Int(byte & 0x0F)])
    }

    /// Decode a hex nibble, or nil if not a hex digit.
    private static func nibble(_ b: UInt8) -> UInt8? {
        switch b {
        case 0x30...0x39: return b - 0x30          // 0-9
        case 0x41...0x46: return b - 0x41 + 10      // A-F
        case 0x61...0x66: return b - 0x61 + 10      // a-f
        default: return nil
        }
    }

    // MARK: Percent (D-line data)

    /// Encode data for a `D` line: escape only `%`, CR and LF.
    public static func percentEncode(_ data: Data) -> Data {
        var out = [UInt8]()
        out.reserveCapacity(data.count)
        for b in data {
            switch b {
            case 0x25, 0x0D, 0x0A: appendHex(b, to: &out) // % CR LF
            default: out.append(b)
            }
        }
        return Data(out)
    }

    // MARK: Percent-plus (command arguments)

    /// Encode data for a command argument: `%`, CR, LF, control and high bytes
    /// become `%XX`, a literal `+` becomes `%2B`, and a space becomes `+`.
    public static func percentPlusEncode(_ data: Data) -> Data {
        var out = [UInt8]()
        out.reserveCapacity(data.count)
        for b in data {
            switch b {
            case 0x20: out.append(0x2B)                    // space -> '+'
            case 0x2B, 0x25: appendHex(b, to: &out)        // '+' '%' -> %XX
            default:
                if b < 0x21 || b > 0x7E { appendHex(b, to: &out) }
                else { out.append(b) }
            }
        }
        return Data(out)
    }

    // MARK: Decoding

    /// Decode a `D`-line body: `%XX` -> byte, everything else literal.
    /// A malformed trailing `%` (or non-hex after `%`) is passed through
    /// literally rather than throwing — the wire is never trusted to crash us.
    public static func percentDecode(_ data: Data) -> Data {
        decode(data, plus: false)
    }

    /// Decode a command argument: as ``percentDecode(_:)`` but `+` -> space.
    public static func percentPlusDecode(_ data: Data) -> Data {
        decode(data, plus: true)
    }

    private static func decode(_ data: Data, plus: Bool) -> Data {
        let bytes = [UInt8](data)
        var out = [UInt8]()
        out.reserveCapacity(bytes.count)
        var i = 0
        while i < bytes.count {
            let b = bytes[i]
            if b == 0x25 { // '%'
                if i + 2 < bytes.count,
                   let hi = nibble(bytes[i + 1]), let lo = nibble(bytes[i + 2]) {
                    out.append((hi << 4) | lo)
                    i += 3
                    continue
                }
                // Not a valid escape: keep the '%' literal.
                out.append(b)
                i += 1
            } else if plus && b == 0x2B { // '+'
                out.append(0x20)
                i += 1
            } else {
                out.append(b)
                i += 1
            }
        }
        return Data(out)
    }

    // MARK: String conveniences

    public static func percentPlusEncode(_ string: String) -> String {
        String(decoding: percentPlusEncode(Data(string.utf8)), as: UTF8.self)
    }

    public static func percentPlusDecodeToString(_ string: String) -> String {
        String(decoding: percentPlusDecode(Data(string.utf8)), as: UTF8.self)
    }
}
