import Darwin
import Foundation
import XCTest
@testable import AssuanKit

/// Interop against the real thing, in both directions:
///
/// * ``AssuanClient`` drives a private gpg-agent — the same conversation the
///   proxy will have with the agent it fronts.
/// * The real libassuan client, `gpg-connect-agent`, drives ``AssuanServer`` —
///   which is how gpg will talk to the proxy.
///
/// Everything happens in an ephemeral `GNUPGHOME` under `/tmp` (short, because
/// `sun_path` is 104 octets) and the agent is killed afterwards. The user's
/// `~/.gnupg` and running agent are never touched.
final class GPGInteropTests: XCTestCase {

    // MARK: Tool discovery

    private static func toolPath(_ name: String) -> String? {
        let candidates = ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)", "/usr/bin/\(name)"]
        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }
        // Fall back to PATH for unusual installs (MacPorts, nix, CI images).
        let which = Process()
        which.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        which.arguments = ["which", name]
        let pipe = Pipe()
        which.standardOutput = pipe
        which.standardError = FileHandle.nullDevice
        guard (try? which.run()) != nil else { return nil }
        which.waitUntilExit()
        let out = String(
            decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self
        ).trimmingCharacters(in: .whitespacesAndNewlines)
        return out.isEmpty ? nil : out
    }

    @discardableResult
    private func run(_ tool: String, _ arguments: [String], input: String? = nil) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let output = Pipe()
        process.standardOutput = output
        process.standardError = output
        if let input {
            let stdin = Pipe()
            process.standardInput = stdin
            try process.run()
            stdin.fileHandleForWriting.write(Data(input.utf8))
            try? stdin.fileHandleForWriting.close()
        } else {
            process.standardInput = FileHandle.nullDevice
            try process.run()
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: A private agent

    /// A gpg-agent running in a throwaway home directory.
    private final class AgentFixture {
        let home: String
        let gpgconf: String
        var socketPath: String { home + "/S.gpg-agent" }

        init(agent: String, gpgconf: String) throws {
            self.gpgconf = gpgconf
            // Keep the path short: GNUPGHOME + "/S.gpg-agent" has to fit in
            // sun_path, and $TMPDIR on macOS is nowhere near short enough.
            home = "/tmp/ag" + String(UInt32.random(in: 0..<0xFFFF_FFFF), radix: 16)
            try FileManager.default.createDirectory(
                atPath: home, withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700])

            let process = Process()
            process.executableURL = URL(fileURLWithPath: agent)
            process.arguments = ["--homedir", home, "--daemon", "--allow-loopback-pinentry"]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try process.run()
            process.waitUntilExit()

            // The daemon forks; wait for the socket to show up.
            let deadline = Date().addingTimeInterval(10)
            while Date() < deadline {
                var st = stat()
                if lstat(socketPath, &st) == 0, (st.st_mode & S_IFMT) == S_IFSOCK { return }
                usleep(50_000)
            }
            throw AssuanIOError("gpg-agent socket never appeared at \(socketPath)")
        }

        func shutdown() {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: gpgconf)
            process.arguments = ["--homedir", home, "--kill", "all"]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            try? process.run()
            process.waitUntilExit()
            try? FileManager.default.removeItem(atPath: home)
        }
    }

    private func withAgent(_ body: (AgentFixture) throws -> Void) throws {
        guard let agent = Self.toolPath("gpg-agent"), let gpgconf = Self.toolPath("gpgconf") else {
            throw XCTSkip("gpg-agent is not installed")
        }
        let fixture = try AgentFixture(agent: agent, gpgconf: gpgconf)
        defer { fixture.shutdown() }
        try body(fixture)
    }

    // MARK: Client against a real gpg-agent

    func testGreetingFromRealAgent() throws {
        try withAgent { agent in
            let client = try AssuanClient.connect(toSocket: agent.socketPath)
            defer { client.connection.close() }
            let greeting = try XCTUnwrap(client.greeting)
            // `assuan_accept` builds this from the *server's* getpid(), so the
            // number is the agent's PID, not ours.
            XCTAssertTrue(greeting.hasPrefix("Pleased to meet you, process "), greeting)
            let pid = greeting.dropFirst("Pleased to meet you, process ".count)
            XCTAssertNotNil(Int(pid), "greeting should end in a PID; got: \(greeting)")
            XCTAssertNotEqual(Int(pid), Int(getpid()), "that PID is the agent's, not ours")
        }
    }

    func testNopAndGetinfoVersion() throws {
        try withAgent { agent in
            let client = try AssuanClient.connect(toSocket: agent.socketPath)
            defer { client.connection.close() }

            XCTAssertTrue(try client.transact("NOP").isOK)

            let version = try client.transact("GETINFO version")
            XCTAssertTrue(version.isOK)
            XCTAssertTrue(version.text.hasPrefix("2."), "unexpected version: \(version.text)")
        }
    }

    func testUnknownCommandYieldsTheDocumentedErrorNumber() throws {
        try withAgent { agent in
            let client = try AssuanClient.connect(toSocket: agent.socketPath)
            defer { client.connection.close() }

            let result = try client.transact("THIS-IS-NOT-A-COMMAND")
            let error = try XCTUnwrap(result.error)
            XCTAssertEqual(error.code, GPGError.assUnknownCmd.rawValue)
            XCTAssertEqual(error.source, GPGErrorSource.gpgAgent)
            XCTAssertEqual(error.number, 67_109_139)
            XCTAssertEqual(error.text, "Unknown IPC command <GPG Agent>")
        }
    }

    func testHelpProducesCommentLines() throws {
        try withAgent { agent in
            let client = try AssuanClient.connect(toSocket: agent.socketPath)
            defer { client.connection.close() }
            // HELP answers with a long run of `#` comment lines and then OK;
            // a client that mis-parses comments would hang or throw here.
            XCTAssertTrue(try client.transact("HELP").isOK)
            XCTAssertTrue(try client.transact("NOP").isOK)
        }
    }

    func testByeGetsTheStandardClosingLine() throws {
        try withAgent { agent in
            let client = try AssuanClient.connect(toSocket: agent.socketPath)
            defer { client.connection.close() }
            XCTAssertEqual(try client.transact("BYE").okText, "closing connection")
        }
    }

    /// The full generate / read / sign round trip, which is exactly the traffic
    /// the proxy has to survive: an `INQUIRE` answered with a canonical
    /// S-expression, and binary S-expressions coming back on `D` lines.
    func testGenkeyReadkeyAndPksignRoundTrip() throws {
        try withAgent { agent in
            let client = try AssuanClient.connect(toSocket: agent.socketPath)
            defer { client.connection.close() }

            XCTAssertTrue(try client.transact("OPTION pinentry-mode=loopback").isOK)

            // GENKEY inquires KEYPARAM; we answer with an S-expression built by
            // our own serializer, which proves libgcrypt accepts our bytes.
            let keyparam = SExpression.list([
                .atom("genkey"),
                .list([.atom("ecc"), .list([.atom("curve"), .atom("nistp256")])]),
            ])
            var inquiredKeyword: String?
            let genkey = try client.transact("GENKEY --no-protection") { keyword, _ in
                inquiredKeyword = keyword
                return keyparam.serialize()
            }
            XCTAssertEqual(inquiredKeyword, "KEYPARAM")
            XCTAssertTrue(genkey.isOK, "GENKEY failed: \(String(describing: genkey.error))")

            // The reply is a canonical public-key S-expression from libgcrypt.
            let publicKey = try SExpression.parse(genkey.data)
            XCTAssertEqual(publicKey.items?.first?.atomString, "public-key")
            let ecc = try XCTUnwrap(publicKey.find("ecc"))
            XCTAssertEqual(ecc.value("curve").map { String(decoding: $0, as: UTF8.self) },
                           "NIST P-256")
            let q = try XCTUnwrap(ecc.value("q"))
            XCTAssertEqual(q.count, 65)
            XCTAssertEqual(q.first, 0x04)

            // Re-serializing must reproduce libgcrypt's octets exactly.
            XCTAssertEqual(publicKey.serialize(), genkey.data)

            let keygrip = try XCTUnwrap(genkey.statuses.first { $0.keyword == "KEYGRIP" }?.args)
            XCTAssertEqual(keygrip.count, 40)

            // READKEY must give back the identical S-expression.
            let readkey = try client.transact("READKEY \(keygrip)")
            XCTAssertTrue(readkey.isOK)
            XCTAssertEqual(readkey.data, genkey.data)

            // And a signature, which is where the r/s MPI shape matters.
            XCTAssertTrue(try client.transact("SIGKEY \(keygrip)").isOK)
            let digest = String(repeating: "ab", count: 32) // 32-byte SHA-256 digest
            XCTAssertTrue(try client.transact("SETHASH --hash=sha256 \(digest)").isOK)

            let signature = try client.transact("PKSIGN")
            XCTAssertTrue(signature.isOK, "PKSIGN failed: \(String(describing: signature.error))")
            let sexp = try SExpression.parse(signature.data)
            XCTAssertEqual(sexp.serialize(), signature.data)
            let rs = try XCTUnwrap(sexp.ecdsaSignatureRS())
            XCTAssertFalse(rs.r.isEmpty)
            XCTAssertFalse(rs.s.isEmpty)
            XCTAssertLessThanOrEqual(rs.r.count, 33)
            XCTAssertLessThanOrEqual(rs.s.count, 33)
        }
    }

    func testKeyinfoListStatusLines() throws {
        try withAgent { agent in
            let client = try AssuanClient.connect(toSocket: agent.socketPath)
            defer { client.connection.close() }
            // An empty store answers OK with no status lines at all; the point
            // is that the transaction terminates cleanly either way.
            let result = try client.transact("KEYINFO --list")
            XCTAssertTrue(result.isOK)
        }
    }

    // MARK: A real libassuan client against our server

    /// `gpg-connect-agent --raw-socket` is libassuan's own client. If it can
    /// drive our server, our wire format is right.
    func testGPGConnectAgentDrivesOurServer() throws {
        guard let connectAgent = Self.toolPath("gpg-connect-agent") else {
            throw XCTSkip("gpg-connect-agent is not installed")
        }
        let path = try TemporarySocketPath()
        defer { path.cleanup() }

        let listener = try AssuanListener(path: path.socket)
        defer { listener.closeAndUnlink() }

        let payload = Data([0x25, 0x0A, 0x0D, 0x00, 0x7F]) // the escaping edge cases
        let serving = Thread {
            try? listener.serveForever { conn in
                let server = AssuanServer(client: conn, handler: RawEchoHandler(payload: payload))
                try? server.run()
            }
        }
        serving.start()

        let script = """
        NOP
        /echo ---
        GETINFO version
        /echo ---
        BINARY
        /echo ---
        NOSUCHCOMMAND
        /echo ---
        BYE
        """
        let output = try run(connectAgent, ["--raw-socket", path.socket], input: script + "\n")

        // libassuan's client accepted our greeting, our OK, our D lines and our
        // ERR — anything malformed makes gpg-connect-agent bail out early.
        XCTAssertTrue(output.contains("1.2.3-gpgsep"), "GETINFO reply missing:\n\(output)")
        XCTAssertTrue(output.contains("ERR 67109139"), "ERR line missing:\n\(output)")
        XCTAssertTrue(output.contains("Unknown IPC command"), "ERR text missing:\n\(output)")
        // gpg-connect-agent renders binary D-line payloads with C escapes.
        XCTAssertTrue(output.contains("D %25"), "escaped payload missing:\n\(output)")
    }

    func testGPGConnectAgentFollowsOurSocketRedirectionFile() throws {
        guard let connectAgent = Self.toolPath("gpg-connect-agent") else {
            throw XCTSkip("gpg-connect-agent is not installed")
        }
        let path = try TemporarySocketPath()
        defer { path.cleanup() }

        let realSocket = path.directory + "/real"
        let advertised = path.directory + "/S.gpg-agent"

        let listener = try AssuanListener(path: realSocket)
        defer { listener.closeAndUnlink() }
        try AssuanSocketRedirection.write(at: advertised, socketPath: realSocket)

        let serving = Thread {
            try? listener.serveForever { conn in
                let server = AssuanServer(client: conn, handler: RawEchoHandler(payload: Data()))
                try? server.run()
            }
        }
        serving.start()

        // libassuan resolves the %Assuan% file itself, so this proves our
        // writer produces a file it accepts.
        let output = try run(connectAgent, ["--raw-socket", advertised],
                             input: "GETINFO version\nBYE\n")
        XCTAssertTrue(output.contains("1.2.3-gpgsep"), "redirection was not followed:\n\(output)")
    }

    func testWeFollowARedirectionFileWrittenForARealAgent() throws {
        try withAgent { agent in
            // Point a redirection file at the live agent's socket and connect
            // through it, the way gpg does when $GNUPGHOME is too long.
            let redirect = agent.home + "/R"
            try AssuanSocketRedirection.write(at: redirect, socketPath: agent.socketPath)

            let conn = try AssuanConnection.connectFollowingRedirection(to: redirect)
            let client = AssuanClient(connection: conn)
            defer { conn.close() }
            try client.readGreeting()
            XCTAssertTrue(client.greeting?.contains("Pleased to meet you") == true)
            XCTAssertTrue(try client.transact("NOP").isOK)
        }
    }
}

/// Answers `GETINFO version`, echoes a fixed binary payload for `BINARY`, and
/// rejects anything else with gpg-agent's own error number.
private final class RawEchoHandler: AssuanCommandHandler {
    let payload: Data
    init(payload: Data) { self.payload = payload }

    func handle(verb: String, rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        switch verb {
        case "NOP", "RESET", "OPTION":
            try io.sendOK()
        case "GETINFO":
            try io.sendData(Data("1.2.3-gpgsep".utf8))
            try io.sendOK()
        case "BINARY":
            try io.sendStatus(keyword: "PAYLOAD", args: "\(payload.count)")
            try io.sendData(payload)
            try io.sendOK()
        default:
            try io.sendError(
                code: GPGError.assUnknownCmd.number(source: GPGErrorSource.gpgAgent),
                text: "Unknown IPC command <GPG Agent>")
        }
        return .handled
    }
}
