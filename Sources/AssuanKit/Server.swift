import Foundation

/// What a command handler decided to do with a command.
public enum AssuanDisposition {
    /// The handler fully answered (it already wrote OK/ERR/data via the IO).
    case handled
    /// The server should relay this command verbatim to the backend.
    case forward
}

/// A per-connection command dispatcher. Return `.handled` after writing a
/// terminal response through `io`, or `.forward` to have the server relay the
/// command to its backend connection.
public protocol AssuanCommandHandler: AnyObject {
    func handle(verb: String, rest: String, io: AssuanServerIO) throws -> AssuanDisposition
}

/// The response/inquiry surface handed to a command handler. All writes go to
/// the client connection; `sendInquire` also reads the client's reply.
public final class AssuanServerIO {
    private let conn: AssuanConnection

    init(connection: AssuanConnection) {
        self.conn = connection
    }

    /// Send `data` as chunked, percent-escaped `D` lines.
    public func sendData(_ data: Data) throws {
        try AssuanClient.sendData(data, on: conn)
    }

    /// Send `S <keyword> <args>`.
    public func sendStatus(keyword: String, args: String) throws {
        try conn.write(.status(keyword: keyword, args: args))
    }

    /// Terminate the command with `OK [text]`.
    public func sendOK(_ text: String? = nil) throws {
        try conn.write(.ok(text))
    }

    /// Terminate the command with `ERR <number> [text]`. `code` is the full
    /// 32-bit wire number; use ``AssuanKit/gpgError(_:source:)`` to build one.
    public func sendError(code: UInt32, text: String? = nil) throws {
        try conn.write(.err(code: code, text: text))
    }

    /// Convenience: terminate with a known ``GPGError`` stamped as gpg-agent.
    public func sendError(_ code: GPGError, source: UInt32 = GPGErrorSource.gpgAgent, text: String? = nil) throws {
        try conn.write(.err(code: code.number(source: source), text: text ?? code.rawValue.description))
    }

    public func sendError(_ error: AssuanError) throws {
        try conn.write(.err(code: error.number, text: error.text))
    }

    /// Ask the client a question: send `INQUIRE <keyword> <args>`, then read the
    /// client's `D…`/`END` reply and return the aggregated, unescaped bytes.
    /// A client `CAN` raises a cancelled error; `END` with no data returns empty.
    public func sendInquire(keyword: String, args: String = "") throws -> Data {
        try conn.write(.inquire(keyword: keyword, args: args))
        var collected = Data()
        while true {
            guard let line = try conn.readCommandLine() else {
                throw AssuanIOError("client closed during INQUIRE reply")
            }
            switch line {
            case .data(let d):
                collected.append(d)
            case .command(let verb, _):
                switch verb {
                case "END": return collected
                case "CAN": throw AssuanError(code: .canceled, text: "client cancelled inquiry")
                default: throw AssuanParseError("unexpected \(verb) during INQUIRE reply")
                }
            case .comment:
                continue
            default:
                throw AssuanParseError("unexpected line during INQUIRE reply: \(line)")
            }
        }
    }

    /// Raw access to the next incoming client line, for handlers that need it.
    public func readLine() throws -> AssuanLine? {
        try conn.readCommandLine()
    }
}

/// Drives one client connection: greeting, read loop, dispatch, and — for
/// `.forward` dispositions — a transparent bidirectional relay to the backend
/// (including INQUIRE round-trips back to the client).
public final class AssuanServer {
    private let client: AssuanConnection
    private let handler: AssuanCommandHandler
    private let backend: AssuanConnection?
    private let io: AssuanServerIO
    public var greeting: String

    public init(
        client: AssuanConnection,
        handler: AssuanCommandHandler,
        backend: AssuanConnection? = nil,
        greeting: String = AssuanLimits.defaultGreeting
    ) {
        self.client = client
        self.handler = handler
        self.backend = backend
        self.greeting = greeting
        self.io = AssuanServerIO(connection: client)
    }

    /// Send the opening `OK` greeting and process commands until BYE/EOF.
    ///
    /// The greeting matches libassuan's `assuan_accept` byte for byte:
    /// `OK <greeting>, process <pid>`, where the PID is the *server's* own
    /// (`pid_t apid = getpid ()` in `assuan-listen.c`) — not the client's,
    /// despite what the comment in gnupg's IO monitor suggests. Verified
    /// against gpg-agent 2.5.20, whose greeting reports the agent's PID.
    public func run() throws {
        try client.write(.ok("\(greeting), process \(getpid())"))
        while true {
            let raw: [UInt8]?
            do {
                raw = try client.readRawLine()
            } catch let e as AssuanIOError where e.recoverable {
                // An overlength but fully-consumed line: the stream is resynced,
                // so answer ERR and keep serving instead of dropping the client.
                try io.sendError(.assIncompleteLine, text: "line too long")
                continue
            }
            guard let raw else { return } // clean EOF
            let line: AssuanLine
            do {
                line = try AssuanLine.parseCommand(raw)
            } catch {
                try io.sendError(.assUnknownCmd, text: "unparseable line")
                continue
            }
            switch line {
            case .comment:
                continue
            case .command(let verb, let rest):
                if verb == "BYE" {
                    try io.sendOK("closing connection")
                    return
                }
                try dispatch(verb: verb, rest: rest, raw: raw)
            case .data:
                // A data line outside an INQUIRE reply is a protocol slip.
                try io.sendError(.assIncompleteLine, text: "unexpected data line")
            default:
                // Clients never send OK/ERR/S/INQUIRE; ignore defensively.
                continue
            }
        }
    }

    private func dispatch(verb: String, rest: String, raw: [UInt8]) throws {
        let disposition: AssuanDisposition
        do {
            disposition = try handler.handle(verb: verb, rest: rest, io: io)
        } catch let e as AssuanError {
            try io.sendError(e)
            return
        } catch {
            try io.sendError(.general, text: "\(error)")
            return
        }
        switch disposition {
        case .handled:
            return
        case .forward:
            guard let backend else {
                try io.sendError(.noAgent, text: "no backend gpg-agent to forward to")
                return
            }
            do {
                try relay(commandLine: raw, to: backend)
            } catch let e as AssuanIOError {
                // The backend died mid-relay. Emit a clean ERR to terminate this
                // command rather than letting a bare EOF desync the client. The
                // client connection stays open so enclave keygrips keep working.
                try? io.sendError(.noAgent, text: "backend relay failed: \(e.message)")
            }
        }
    }

    /// Forward `commandLine` verbatim to the backend and stream every response
    /// back to the client, relaying backend INQUIREs to the client and the
    /// client's `D…`/`END` answer back to the backend — streaming, no buffering.
    private func relay(commandLine: [UInt8], to backend: AssuanConnection) throws {
        try backend.writeLineBytes(Data(commandLine))
        while true {
            guard let line = try backend.readResponseLine() else {
                throw AssuanIOError("backend closed mid-relay")
            }
            switch line {
            case .inquire:
                try client.write(line) // relay the question to the real client
                try pumpInquiryReply(from: client, to: backend)
            case .ok, .err:
                try client.write(line)
                return
            default:
                try client.write(line) // D / S / comment straight through
            }
        }
    }

    /// Copy the client's INQUIRE reply (`D…` lines then `END`) to the backend,
    /// verbatim, preserving exact escaped bytes.
    private func pumpInquiryReply(from client: AssuanConnection, to backend: AssuanConnection) throws {
        while true {
            guard let raw = try client.readRawLine() else {
                throw AssuanIOError("client closed during INQUIRE reply")
            }
            // Forward the raw bytes unchanged so escaping is byte-identical.
            try backend.writeLineBytes(Data(raw))
            let line = try AssuanLine.parseCommand(raw)
            if case .command(let verb, _) = line, verb == "END" || verb == "CAN" {
                return
            }
        }
    }
}
