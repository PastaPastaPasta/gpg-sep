import Foundation

/// The line-length numbers libassuan actually uses, and the data-line writer
/// that reproduces its wrapping byte for byte.
///
/// The Assuan manual says "the implementation is line based with a maximum line
/// size of 1000 octets" and that "lines longer than 1000 bytes should be
/// treated as a communication error". libassuan implements that with a single
/// constant, `ASSUAN_LINELENGTH = 1002 /* 1000 + [CR,]LF */`, and a reader that
/// gives up if no LF appears within those 1002 octets. So the largest line a
/// libassuan peer will ever accept is 1001 octets of content plus the LF.
public enum AssuanLimits {
    /// `ASSUAN_LINELENGTH` — the whole line including its terminator.
    public static let lineBufferSize = 1002

    /// Largest line content, terminator excluded, that a libassuan peer accepts.
    public static let maxLineContent = lineBufferSize - 1 // 1001

    /// The nominal per-line limit from the manual. Commands and control lines
    /// this library emits stay at or under it.
    public static let nominalMaxLine = 1000

    /// libassuan's data-line fill limit, `LINELENGTH - 2 - 2` (998).
    ///
    /// `_assuan_cookie_write_data` keeps appending escaped octets while the
    /// line — counting the two-octet `"D "` prefix — is shorter than this,
    /// which reserves room for one three-octet escape plus the terminator.
    /// A line therefore tops out at 1000 octets of content.
    public static let dataFillLimit = lineBufferSize - 4 // 998

    /// The greeting libassuan sends when the server sets no custom hello line.
    public static let defaultGreeting = "Pleased to meet you"

    /// What a libassuan server answers `BYE` with.
    public static let closingConnectionText = "closing connection"
}

extension AssuanEscaping {
    /// Split `data` into complete `D` line bodies — `"D "` prefix included,
    /// terminator excluded — wrapped exactly where libassuan wraps them.
    ///
    /// Reproducing the wrap point matters because gpg tools are perfectly happy
    /// to compare captured protocol traces, and because a proxy that re-chunks
    /// differently from the agent it fronts is immediately distinguishable.
    /// Empty input yields no lines at all, which is what `assuan_send_data`
    /// does with a zero-length buffer.
    public static func dataLineBodies(_ data: Data) -> [Data] {
        var lines: [Data] = []
        var line = Data()
        for byte in data {
            if line.isEmpty { line.append(contentsOf: [0x44, 0x20]) } // "D "
            switch byte {
            case 0x25: line.append(contentsOf: Array("%25".utf8))
            case 0x0D: line.append(contentsOf: Array("%0D".utf8))
            case 0x0A: line.append(contentsOf: Array("%0A".utf8))
            default: line.append(byte)
            }
            // libassuan tests the length after appending, so a line may
            // overshoot the limit by two octets when the final octet was one
            // that had to be escaped.
            if line.count >= AssuanLimits.dataFillLimit {
                lines.append(line)
                line = Data()
            }
        }
        if !line.isEmpty { lines.append(line) }
        return lines
    }
}
