import Foundation

/// A single parsed Assuan protocol line.
///
/// The same enum models both directions. `parseResponse` reads what a server
/// (gpg-agent, or our proxy's backend) sends; `parseCommand` reads what a
/// client sends. The two differ only in how the leading token is interpreted —
/// e.g. `END` is a *command* from a client but never a server response.
public enum AssuanLine: Equatable {
    /// `OK [text]`
    case ok(String?)
    /// `ERR <code> [text]`
    case err(code: UInt32, text: String?)
    /// `S <keyword> <args>`
    case status(keyword: String, args: String)
    /// `D <percent-escaped-data>` — payload already unescaped to raw bytes.
    case data(Data)
    /// `INQUIRE <keyword> [args]`
    case inquire(keyword: String, args: String)
    /// `# comment`
    case comment(String)
    /// Any client command: `<VERB> [rest]`. `END`, `BYE`, `RESET`, `CAN`,
    /// `NOP`, `OPTION …`, `SETHASH …` all land here.
    case command(verb: String, rest: String)
}

public struct AssuanParseError: Error, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
}

extension AssuanLine {
    /// Serialize back to raw wire bytes **without** the trailing newline.
    /// The line writer appends `\n`.
    public func serialize() -> Data {
        switch self {
        case .ok(let text):
            return Data(("OK" + (text.map { " " + $0 } ?? "")).utf8)
        case .err(let code, let text):
            return Data(("ERR \(code)" + (text.map { " " + $0 } ?? "")).utf8)
        case .status(let keyword, let args):
            let a = args.isEmpty ? "" : " " + args
            return Data(("S \(keyword)\(a)").utf8)
        case .data(let payload):
            var out = Data("D ".utf8)
            out.append(AssuanEscaping.percentEncode(payload))
            return out
        case .inquire(let keyword, let args):
            let a = args.isEmpty ? "" : " " + args
            return Data(("INQUIRE \(keyword)\(a)").utf8)
        case .comment(let text):
            // libassuan writes "# " before the text; `parseX` strips that same
            // single space back off, so the round trip is exact.
            return Data(("# " + text).utf8)
        case .command(let verb, let rest):
            let r = rest.isEmpty ? "" : " " + rest
            return Data(("\(verb)\(r)").utf8)
        }
    }

    // MARK: Parsing

    /// Parse a server→client response line (raw bytes, no trailing newline).
    public static func parseResponse<C: Collection>(_ raw: C) throws -> AssuanLine
    where C.Element == UInt8 {
        let bytes = Array(raw)
        if bytes.first == 0x23 { // '#'
            return .comment(commentText(bytes))
        }
        let (token, restStart) = firstToken(bytes)
        switch token {
        case "OK":
            return .ok(restString(bytes, from: restStart, orNilIfEmpty: true))
        case "ERR":
            return try parseErr(bytes, from: restStart)
        case "S":
            let (kw, kwRest) = firstToken(Array(bytes[restStart...]))
            guard !kw.isEmpty else { throw AssuanParseError("status line without keyword") }
            let args = restString(Array(bytes[restStart...]), from: kwRest, orNilIfEmpty: false) ?? ""
            return .status(keyword: kw, args: args)
        case "INQUIRE":
            let (kw, kwRest) = firstToken(Array(bytes[restStart...]))
            guard !kw.isEmpty else { throw AssuanParseError("INQUIRE without keyword") }
            let args = restString(Array(bytes[restStart...]), from: kwRest, orNilIfEmpty: false) ?? ""
            return .inquire(keyword: kw, args: args)
        case "D":
            return .data(dataPayload(bytes, from: restStart))
        case "":
            throw AssuanParseError("empty response line")
        default:
            throw AssuanParseError("unrecognized response token '\(token)'")
        }
    }

    /// Parse a client→server command line (raw bytes, no trailing newline).
    public static func parseCommand<C: Collection>(_ raw: C) throws -> AssuanLine
    where C.Element == UInt8 {
        let bytes = Array(raw)
        // A leading '#' comment, or an empty line, is a comment/no-op per Assuan.
        if bytes.first == 0x23 { // '#'
            return .comment(commentText(bytes))
        }
        let (token, restStart) = firstToken(bytes)
        switch token {
        case "":
            // Blank line: Assuan treats it as a comment/no-op.
            return .comment("")
        case "D":
            // Inline data line from a client (INQUIRE reply, or PKSIGN sexp).
            return .data(dataPayload(bytes, from: restStart))
        default:
            // Everything else — including END, BYE, RESET, CAN, NOP, OPTION,
            // SETHASH, PKSIGN … — is a command. Verb is normalized to
            // uppercase since Assuan verbs are case-insensitive.
            let rest = restString(bytes, from: restStart, orNilIfEmpty: false) ?? ""
            return .command(verb: token.uppercased(), rest: rest)
        }
    }

    // MARK: Helpers

    private static func parseErr(_ bytes: [UInt8], from start: Int) throws -> AssuanLine {
        let (codeTok, afterCode) = firstToken(Array(bytes[start...]))
        guard let code = UInt32(codeTok) else {
            throw AssuanParseError("ERR without numeric code: '\(codeTok)'")
        }
        let text = restString(Array(bytes[start...]), from: afterCode, orNilIfEmpty: true)
        return .err(code: code, text: text)
    }

    /// The `D` payload is everything after the *single* space following `D`,
    /// percent-decoded. If there is no space (bare `D`), the payload is empty.
    private static func dataPayload(_ bytes: [UInt8], from restStart: Int) -> Data {
        guard restStart <= bytes.count else { return Data() }
        let slice = Data(bytes[restStart...])
        return AssuanEscaping.percentDecode(slice)
    }

    /// Split off the first whitespace-delimited token. Returns the token as a
    /// String and the index at which the remainder begins (after exactly one
    /// separating space). For `D`, `restStart` points right after `D `.
    private static func firstToken(_ bytes: [UInt8]) -> (String, Int) {
        var i = 0
        // Leading spaces are not expected but tolerated.
        while i < bytes.count, bytes[i] == 0x20 { i += 1 }
        let tokStart = i
        while i < bytes.count, bytes[i] != 0x20 { i += 1 }
        let token = String(decoding: bytes[tokStart..<i], as: UTF8.self)
        // Consume exactly one separating space so the payload keeps any extra.
        let restStart = i < bytes.count ? i + 1 : bytes.count
        return (token, restStart)
    }

    /// The text of a `#` comment: everything after the `#`, minus the single
    /// space `serialize()` puts there, so `# hi` round-trips to `"hi"`.
    private static func commentText(_ bytes: [UInt8]) -> String {
        var start = 1
        if start < bytes.count, bytes[start] == 0x20 { start += 1 }
        return String(decoding: bytes[start...], as: UTF8.self)
    }

    private static func restString(_ bytes: [UInt8], from start: Int, orNilIfEmpty: Bool) -> String? {
        guard start < bytes.count else { return orNilIfEmpty ? nil : "" }
        let s = String(decoding: bytes[start...], as: UTF8.self)
        if orNilIfEmpty && s.isEmpty { return nil }
        return s
    }
}
