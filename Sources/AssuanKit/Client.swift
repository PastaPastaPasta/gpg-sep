import Foundation

/// The collected outcome of a single `transact` exchange.
public struct AssuanResult {
    /// All `D` data lines concatenated and unescaped.
    public var data: Data = Data()
    /// Every `S` status line, keyword + (raw) args, in order.
    public var statuses: [(keyword: String, args: String)] = []
    /// Text after a terminal `OK`, if any.
    public var okText: String? = nil
    /// Populated instead of `okText` when the command ended in `ERR`.
    public var error: AssuanError? = nil

    public var isOK: Bool { error == nil }

    /// The unescaped data decoded as UTF-8 (for textual replies like versions).
    public var text: String { String(decoding: data, as: UTF8.self) }
}

/// An Assuan client speaking to a server (real gpg-agent, or our proxy backend).
public final class AssuanClient {
    public let connection: AssuanConnection
    public private(set) var greeting: String?

    public init(connection: AssuanConnection) {
        self.connection = connection
    }

    /// Connect to a Unix socket and read the initial greeting.
    public static func connect(toSocket path: String) throws -> AssuanClient {
        let conn = try AssuanConnection.connect(toUnixSocket: path)
        let client = AssuanClient(connection: conn)
        try client.readGreeting()
        return client
    }

    /// Read the server's opening line, which must be `OK …`.
    @discardableResult
    public func readGreeting() throws -> String? {
        guard let line = try connection.readResponseLine() else {
            throw AssuanIOError("connection closed before greeting")
        }
        guard case .ok(let text) = line else {
            throw AssuanParseError("expected OK greeting, got \(line)")
        }
        greeting = text
        return text
    }

    /// Standard opening handshake: `RESET` then each provided `OPTION` line.
    /// Pass options as full argument strings, e.g. `"ttyname=/dev/ttys000"`.
    public func handshake(options: [String] = []) throws {
        _ = try transact("RESET")
        for opt in options {
            let r = try transact("OPTION \(opt)")
            if let e = r.error { throw e }
        }
    }

    /// Send one command and collect the response up to the terminal OK/ERR.
    ///
    /// Server-initiated `INQUIRE` lines are answered by `dataInquiryHandler`,
    /// whose returned `Data` is sent back as chunked `D` lines followed by
    /// `END`. If a handler is not supplied, the inquiry is cancelled (`CAN`).
    public func transact(
        _ command: String,
        dataInquiryHandler: ((_ keyword: String, _ args: String) throws -> Data)? = nil
    ) throws -> AssuanResult {
        try connection.writeLineBytes(Data(command.utf8))
        var result = AssuanResult()
        while true {
            guard let line = try connection.readResponseLine() else {
                throw AssuanIOError("connection closed mid-transaction")
            }
            switch line {
            case .data(let d):
                result.data.append(d)
            case .status(let kw, let args):
                result.statuses.append((kw, args))
            case .comment:
                continue
            case .inquire(let kw, let args):
                if let handler = dataInquiryHandler {
                    let payload = try handler(kw, args)
                    try sendInquiryReply(payload)
                } else {
                    try connection.write(.command(verb: "CAN", rest: ""))
                }
            case .ok(let text):
                result.okText = text
                return result
            case .err(let code, let text):
                result.error = AssuanError(number: code, text: text)
                return result
            case .command:
                throw AssuanParseError("server sent a command line: \(line)")
            }
        }
    }

    /// Send `data` as chunked `D` lines then `END` — the client side of an
    /// INQUIRE reply, or of feeding inline data to a command.
    public func sendInquiryReply(_ data: Data) throws {
        try Self.sendData(data, on: connection)
        try connection.write(.command(verb: "END", rest: ""))
    }

    /// Write `data` as one or more `D` lines, percent-escaped and wrapped
    /// exactly where libassuan wraps them.
    static func sendData(_ data: Data, on conn: AssuanConnection) throws {
        for body in AssuanEscaping.dataLineBodies(data) {
            try conn.writeLineBytes(body)
        }
    }

    // MARK: - Raw proxy passthrough

    /// Relay one already-parsed client command verbatim to `backend`, streaming
    /// every backend response line back through `clientOut` until the terminal
    /// `OK`/`ERR`.
    ///
    /// INQUIRE handling: when the backend asks a question, `inquireFromClient`
    /// is invoked with the `.inquire(...)` line. It must perform the client-side
    /// round trip (relay the INQUIRE to the real client, read the client's
    /// `D…`/`END`) and return the collected answer as a single `.data(payload)`
    /// line — which this method re-chunks into `D` lines + `END` for the
    /// backend. To decline, it may instead return `.command(verb: "CAN", …)`,
    /// which is forwarded as `CAN`. This keeps binary S-expressions intact
    /// across the proxy in both directions.
    public func forwardRaw(
        commandLine: String,
        to backend: AssuanConnection,
        clientOut: (AssuanLine) throws -> Void,
        inquireFromClient: (AssuanLine) throws -> AssuanLine
    ) throws {
        try backend.writeLineBytes(Data(commandLine.utf8))
        while true {
            guard let line = try backend.readResponseLine() else {
                throw AssuanIOError("backend closed mid-forward")
            }
            switch line {
            case .inquire:
                let reply = try inquireFromClient(line)
                switch reply {
                case .data(let payload):
                    try Self.sendData(payload, on: backend)
                    try backend.write(.command(verb: "END", rest: ""))
                case .command(let verb, let rest):
                    // Typically CAN to abort the inquiry.
                    try backend.write(.command(verb: verb, rest: rest))
                default:
                    throw AssuanParseError("inquireFromClient returned unsupported \(reply)")
                }
            case .ok, .err:
                try clientOut(line)
                return
            default:
                // D / S / comment: stream straight through to the client.
                try clientOut(line)
            }
        }
    }
}
