import Darwin
import XCTest
@testable import AssuanKit

/// A handler driven by a closure, so each test can define its own tiny server.
private final class ClosureHandler: AssuanCommandHandler {
    let body: (String, String, AssuanServerIO) throws -> AssuanDisposition
    init(_ body: @escaping (String, String, AssuanServerIO) throws -> AssuanDisposition) {
        self.body = body
    }
    func handle(verb: String, rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        try body(verb, rest, io)
    }
}

/// ``AssuanClient`` talking to ``AssuanServer`` over a `socketpair`, plus the
/// listener and the proxy relay path.
final class LoopbackTests: XCTestCase {

    /// Wire a server to a client over a socket pair and run the server on its
    /// own thread. Returns the client; the server thread ends at BYE or EOF.
    private func makeClient(
        greeting: String = AssuanLimits.defaultGreeting,
        backend: AssuanConnection? = nil,
        handler: @escaping (String, String, AssuanServerIO) throws -> AssuanDisposition
    ) throws -> AssuanClient {
        let (serverSide, clientSide) = try AssuanConnection.makePair()
        let server = AssuanServer(
            client: serverSide,
            handler: ClosureHandler(handler),
            backend: backend,
            greeting: greeting)
        let thread = Thread { try? server.run() }
        thread.start()
        let client = AssuanClient(connection: clientSide)
        try client.readGreeting()
        return client
    }

    // MARK: Greeting and basic verbs

    func testGreetingIsSentBeforeAnyCommand() throws {
        let client = try makeClient { _, _, io in try io.sendOK(); return .handled }
        // libassuan's exact hello line, optionally followed by ", process N"
        // when the kernel exposes the peer's PID.
        XCTAssertTrue(
            client.greeting?.hasPrefix(AssuanLimits.defaultGreeting) == true,
            "unexpected greeting: \(client.greeting ?? "nil")")
        client.connection.close()
    }

    func testOKAndERR() throws {
        let client = try makeClient { verb, _, io in
            if verb == "GOOD" { try io.sendOK("fine") } else { try io.sendError(.notImplemented, text: "nope") }
            return .handled
        }
        defer { client.connection.close() }

        let good = try client.transact("GOOD")
        XCTAssertTrue(good.isOK)
        XCTAssertEqual(good.okText, "fine")

        let bad = try client.transact("OTHER")
        XCTAssertFalse(bad.isOK)
        XCTAssertEqual(bad.error?.code, GPGError.notImplemented.rawValue)
        XCTAssertEqual(bad.error?.source, GPGErrorSource.gpgAgent)
    }

    func testByeIsAnsweredAndClosesTheConnection() throws {
        let client = try makeClient { _, _, io in try io.sendOK(); return .handled }
        defer { client.connection.close() }
        let result = try client.transact("BYE")
        XCTAssertEqual(result.okText, AssuanLimits.closingConnectionText)
    }

    func testUnparseableCommandDoesNotKillTheConnection() throws {
        let client = try makeClient { _, _, io in try io.sendOK("still here"); return .handled }
        defer { client.connection.close() }
        // A stray comment is ignored outright, and the next command still works.
        try client.connection.writeLineBytes(Data("# just a comment".utf8))
        XCTAssertEqual(try client.transact("NOP").okText, "still here")
    }

    func testDataLineOutsideAnInquiryIsRejectedButSurvivable() throws {
        let client = try makeClient { _, _, io in try io.sendOK(); return .handled }
        defer { client.connection.close() }
        try client.connection.writeLineBytes(Data("D stray".utf8))
        guard let line = try client.connection.readResponseLine(),
              case .err = line else {
            return XCTFail("expected an ERR for a data line outside an inquiry")
        }
        XCTAssertTrue(try client.transact("NOP").isOK)
    }

    // MARK: Data

    func testStatusAndDataAreCollectedInOrder() throws {
        let client = try makeClient { _, _, io in
            try io.sendStatus(keyword: "INQUIRE_MAXLEN", args: "1024")
            try io.sendData(Data("hello ".utf8))
            try io.sendStatus(keyword: "KEYGRIP", args: "ABCD")
            try io.sendData(Data("world".utf8))
            try io.sendOK()
            return .handled
        }
        defer { client.connection.close() }

        let result = try client.transact("X")
        XCTAssertEqual(result.text, "hello world")
        XCTAssertEqual(result.statuses.map(\.keyword), ["INQUIRE_MAXLEN", "KEYGRIP"])
        XCTAssertEqual(result.statuses.first?.args, "1024")
    }

    func testLargeBinaryPayloadSurvivesChunkingAndEscaping() throws {
        // 64 KiB of every octet value, which forces many D lines and exercises
        // %25/%0D/%0A on line boundaries.
        var payload = Data()
        for i in 0..<65_536 { payload.append(UInt8(i % 256)) }

        let client = try makeClient { _, _, io in
            try io.sendData(payload)
            try io.sendOK()
            return .handled
        }
        defer { client.connection.close() }

        let result = try client.transact("BIG")
        XCTAssertEqual(result.data, payload)
    }

    func testCanonicalSExpressionSurvivesTheWire() throws {
        var q = Data([0x04])
        // Include the three special octets so escaping is exercised inside a
        // length-prefixed atom, where a mis-escape would shift every offset.
        q.append(Data([0x25, 0x0A, 0x0D]))
        q.append(Data(repeating: 0xFE, count: 61))
        let sexp = SExpression.eccPublicKey(curve: "NIST P-256", q: q)

        let client = try makeClient { _, _, io in
            try io.sendData(sexp.serialize())
            try io.sendOK()
            return .handled
        }
        defer { client.connection.close() }

        let result = try client.transact("READKEY")
        XCTAssertEqual(result.data, sexp.serialize())
        XCTAssertEqual(try SExpression.parse(result.data), sexp)
    }

    // MARK: INQUIRE

    func testInquireRoundTrip() throws {
        let received = UncheckedBox<Data>(Data())
        let client = try makeClient { verb, _, io in
            guard verb == "GENKEY" else { try io.sendOK(); return .handled }
            try io.sendStatus(keyword: "INQUIRE_MAXLEN", args: "1024")
            let answer = try io.sendInquire(keyword: "KEYPARAM")
            received.value = answer
            try io.sendData(Data("done".utf8))
            try io.sendOK()
            return .handled
        }
        defer { client.connection.close() }

        let keyparam = Data("(6:genkey(3:ecc(5:curve10:NIST P-256)))".utf8)
        let result = try client.transact("GENKEY --no-protection") { keyword, _ in
            XCTAssertEqual(keyword, "KEYPARAM")
            return keyparam
        }
        XCTAssertTrue(result.isOK)
        XCTAssertEqual(result.text, "done")
        XCTAssertEqual(received.value, keyparam)
    }

    func testInquireWithMultiLineAnswer() throws {
        var big = Data()
        for i in 0..<10_000 { big.append(UInt8((i * 3) % 256)) }
        let received = UncheckedBox<Data>(Data())

        let client = try makeClient { _, _, io in
            received.value = try io.sendInquire(keyword: "CIPHERTEXT")
            try io.sendOK()
            return .handled
        }
        defer { client.connection.close() }

        XCTAssertTrue(try client.transact("PKDECRYPT") { _, _ in big }.isOK)
        XCTAssertEqual(received.value, big)
    }

    func testUnhandledInquiryIsCancelled() throws {
        let cancelled = UncheckedBox<Bool>(false)
        let client = try makeClient { _, _, io in
            do {
                _ = try io.sendInquire(keyword: "PASSPHRASE")
                try io.sendOK()
            } catch let error as AssuanError {
                cancelled.value = error.code == GPGError.canceled.rawValue
                try io.sendError(error)
            }
            return .handled
        }
        defer { client.connection.close() }

        // No inquiry handler supplied: the client answers CAN.
        let result = try client.transact("PKDECRYPT")
        XCTAssertFalse(result.isOK)
        XCTAssertTrue(cancelled.value)
    }

    // MARK: Line limits

    func testOverlongInboundLineIsRejected() throws {
        let (a, b) = try AssuanConnection.makePair()
        defer { a.close(); b.close() }
        // Bypass the outbound guard to simulate a non-conforming peer.
        var raw = [UInt8](Data("OK ".utf8))
        raw.append(contentsOf: Array(repeating: UInt8(ascii: "x"),
                                     count: AssuanLimits.maxLineContent))
        raw.append(0x0A)
        try a.writeRawForTesting(raw)
        XCTAssertThrowsError(try b.readRawLine())
    }

    func testLineOfExactlyTheBufferLimitIsAccepted() throws {
        let (a, b) = try AssuanConnection.makePair()
        defer { a.close(); b.close() }
        // 1001 octets of content plus LF is exactly ASSUAN_LINELENGTH, the
        // largest a libassuan peer will read.
        let content = [UInt8](repeating: UInt8(ascii: "x"), count: AssuanLimits.maxLineContent)
        try a.writeRawForTesting(content + [0x0A])
        XCTAssertEqual(try b.readRawLine(), content)
    }

    func testOutboundOverlongLineIsRefused() throws {
        let (a, b) = try AssuanConnection.makePair()
        defer { a.close(); b.close() }
        let tooLong = Data(repeating: UInt8(ascii: "x"), count: AssuanLimits.maxLineContent + 1)
        XCTAssertThrowsError(try a.writeLineBytes(tooLong))
    }

    func testOutboundLineWithEmbeddedNewlineIsRefused() throws {
        let (a, b) = try AssuanConnection.makePair()
        defer { a.close(); b.close() }
        XCTAssertThrowsError(try a.writeLineBytes(Data("OK a\nERR 1".utf8)))
    }

    func testCRLFTerminatorIsAccepted() throws {
        let (a, b) = try AssuanConnection.makePair()
        defer { a.close(); b.close() }
        try a.writeRawForTesting(Array("OK hi\r\n".utf8))
        XCTAssertEqual(try b.readResponseLine(), .ok("hi"))
    }

    func testSplitWritesAreReassembled() throws {
        let (a, b) = try AssuanConnection.makePair()
        defer { a.close(); b.close() }
        try a.writeRawForTesting(Array("OK par".utf8))
        try a.writeRawForTesting(Array("tial\nS X 1\n".utf8))
        XCTAssertEqual(try b.readResponseLine(), .ok("partial"))
        XCTAssertEqual(try b.readResponseLine(), .status(keyword: "X", args: "1"))
    }

    func testCleanEOFReturnsNil() throws {
        let (a, b) = try AssuanConnection.makePair()
        defer { b.close() }
        a.close()
        XCTAssertNil(try b.readRawLine())
    }

    // MARK: Listener

    func testListenerAcceptsAndServesAClient() throws {
        let path = try TemporarySocketPath()
        defer { path.cleanup() }

        let listener = try AssuanListener(path: path.socket)
        defer { listener.closeAndUnlink() }

        let accept = Thread {
            guard let conn = try? listener.accept() else { return }
            let server = AssuanServer(
                client: conn,
                handler: ClosureHandler { verb, _, io in
                    try io.sendData(Data(verb.utf8))
                    try io.sendOK()
                    return .handled
                })
            try? server.run()
        }
        accept.start()

        let client = try AssuanClient.connect(toSocket: path.socket)
        defer { client.connection.close() }
        // Over a real socket the peer PID is available, so the greeting carries
        // it exactly as libassuan's does.
        XCTAssertEqual(
            client.greeting, "\(AssuanLimits.defaultGreeting), process \(getpid())",
            "the greeting must match libassuan's assuan_accept byte for byte")
        XCTAssertEqual(try client.transact("PING").text, "PING")
    }

    func testListenerReportsPeerCredentials() throws {
        let path = try TemporarySocketPath()
        defer { path.cleanup() }
        let listener = try AssuanListener(path: path.socket)
        defer { listener.closeAndUnlink() }

        let box = UncheckedBox<(uid_t?, pid_t?)>((nil, nil))
        let done = DispatchSemaphore(value: 0)
        let accept = Thread {
            if let conn = try? listener.accept() {
                box.value = (conn.peerUserID, conn.peerProcessID)
                conn.close()
            }
            done.signal()
        }
        accept.start()

        let conn = try AssuanConnection.connect(toUnixSocket: path.socket)
        XCTAssertEqual(done.wait(timeout: .now() + 5), .success)
        conn.close()
        XCTAssertEqual(box.value.0, getuid())
        XCTAssertEqual(box.value.1, getpid())
    }

    func testListenerRefusesAnOverlongPath() {
        let long = "/tmp/" + String(repeating: "a", count: AssuanListener.maxPathLength)
        XCTAssertThrowsError(try AssuanListener(path: long))
    }

    func testListenerReplacesAStaleSocketButNotARegularFile() throws {
        let path = try TemporarySocketPath()
        defer { path.cleanup() }

        let first = try AssuanListener(path: path.socket)
        // Rebinding the same path succeeds because the stale socket is removed.
        let second = try AssuanListener(path: path.socket)
        second.closeAndUnlink()
        first.closeAndUnlink()

        // A regular file is never unlinked, so binding over one must fail.
        FileManager.default.createFile(atPath: path.socket, contents: Data("not a socket".utf8))
        XCTAssertThrowsError(try AssuanListener(path: path.socket))
        XCTAssertEqual(
            try String(contentsOfFile: path.socket, encoding: .utf8), "not a socket",
            "a regular file at the socket path must be left untouched")
    }

    /// M1: with `refuseLiveSocket`, a socket that still has a live listener is
    /// never clobbered; a stale inode (no listener) is still replaced.
    func testRefuseLiveSocketProtectsALiveListenerButReplacesAStaleOne() throws {
        let path = try TemporarySocketPath()
        defer { path.cleanup() }

        // Live listener: a second bind with refuseLiveSocket must be refused.
        let live = try AssuanListener(path: path.socket)
        XCTAssertThrowsError(try AssuanListener(path: path.socket, refuseLiveSocket: true),
                             "a live socket must not be clobbered when refuseLiveSocket is set")
        live.closeAndUnlink()

        // Stale inode (bound, no listener): a probe connect() is refused, so it is
        // treated as stale and replaced.
        makeStaleSocket(at: path.socket)
        let replacement = try AssuanListener(path: path.socket, refuseLiveSocket: true)
        replacement.closeAndUnlink()
    }

    /// Create a stale AF_UNIX socket inode: bound so the file exists, but with no
    /// listener, so a probe `connect()` is refused and the path counts as stale.
    private func makeStaleSocket(at socketPath: String) {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return }
        var addr = try! AssuanListener.makeAddress(path: socketPath)
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        _ = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(s, $0, len) }
        }
        _ = Darwin.close(s) // inode remains; nothing is listening
    }

    // MARK: - M2: errors surface as ERR, the connection is not dropped

    func testOverlongCommandLineGetsERRAndConnectionStaysUsable() throws {
        let client = try makeClient { _, _, io in try io.sendOK("still here"); return .handled }
        defer { client.connection.close() }
        // 2000 bytes, well over ASSUAN_LINELENGTH, sent raw to bypass the guard.
        var raw = Array("NOP ".utf8)
        raw += Array(repeating: UInt8(ascii: "x"), count: 2000)
        raw.append(0x0A)
        try client.connection.writeRawForTesting(raw)
        guard let line = try client.connection.readResponseLine(), case .err = line else {
            return XCTFail("an overlong line must produce an ERR, not a dropped connection")
        }
        XCTAssertEqual(try client.transact("NOP").okText, "still here",
                       "the connection must resync and keep serving after the ERR")
    }

    func testBackendDeathMidRelayYieldsERRNotBareEOF() throws {
        let (backendServerSide, backendClientSide) = try AssuanConnection.makePair()
        let backendThread = Thread {
            // Greet, read the one relayed command, then die without answering.
            try? backendServerSide.write(.ok(AssuanLimits.defaultGreeting))
            _ = try? backendServerSide.readRawLine()
            backendServerSide.close()
        }
        backendThread.start()
        // Consume the backend greeting, as the real proxy does on connect.
        _ = try backendClientSide.readResponseLine()

        let client = try makeClient(backend: backendClientSide) { _, _, _ in .forward }
        defer { client.connection.close() }
        let result = try client.transact("READKEY ABCD")
        XCTAssertNotNil(result.error,
                        "a backend that dies mid-relay must surface as ERR, not a hang or bare EOF")
    }

    // MARK: Proxy relay

    func testForwardRelaysCommandsAndDataToABackend() throws {
        // backendServer <-> backendClient is the "real agent"; the proxy sits
        // between the test client and backendClient.
        let (backendServerSide, backendClientSide) = try AssuanConnection.makePair()
        let backendThread = Thread {
            let server = AssuanServer(
                client: backendServerSide,
                handler: ClosureHandler { verb, rest, io in
                    try io.sendStatus(keyword: "FROM", args: "backend")
                    try io.sendData(Data("\(verb)|\(rest)".utf8))
                    try io.sendOK("backend ok")
                    return .handled
                })
            try? server.run()
        }
        backendThread.start()
        // The proxy must consume the backend's greeting before relaying, or the
        // first relayed command would read it as that command's response.
        guard case .ok(let hello)? = try backendClientSide.readResponseLine(),
              hello?.hasPrefix(AssuanLimits.defaultGreeting) == true else {
            return XCTFail("backend did not greet")
        }

        let client = try makeClient(backend: backendClientSide) { verb, _, io in
            if verb == "LOCAL" { try io.sendOK("handled locally"); return .handled }
            return .forward
        }
        defer { client.connection.close() }

        XCTAssertEqual(try client.transact("LOCAL").okText, "handled locally")

        let relayed = try client.transact("READKEY ABCD")
        XCTAssertEqual(relayed.okText, "backend ok")
        XCTAssertEqual(relayed.text, "READKEY|ABCD")
        XCTAssertEqual(relayed.statuses.first?.keyword, "FROM")
    }

    func testForwardRelaysInquiriesBackToTheClient() throws {
        let seen = UncheckedBox<Data>(Data())
        let (backendServerSide, backendClientSide) = try AssuanConnection.makePair()
        let backendThread = Thread {
            let server = AssuanServer(
                client: backendServerSide,
                handler: ClosureHandler { _, _, io in
                    seen.value = try io.sendInquire(keyword: "CIPHERTEXT")
                    try io.sendData(Data("plaintext".utf8))
                    try io.sendOK()
                    return .handled
                })
            try? server.run()
        }
        backendThread.start()
        guard case .ok(let hello)? = try backendClientSide.readResponseLine(),
              hello?.hasPrefix(AssuanLimits.defaultGreeting) == true else {
            return XCTFail("backend did not greet")
        }

        let client = try makeClient(backend: backendClientSide) { _, _, _ in .forward }
        defer { client.connection.close() }

        // A payload with the special octets proves the relay forwards the raw
        // escaped bytes rather than re-encoding them.
        let ciphertext = Data([0x25, 0x0A, 0x0D, 0x00, 0xFF]) + Data(repeating: 0x41, count: 3000)
        let result = try client.transact("PKDECRYPT") { keyword, _ in
            XCTAssertEqual(keyword, "CIPHERTEXT")
            return ciphertext
        }
        XCTAssertTrue(result.isOK)
        XCTAssertEqual(result.text, "plaintext")
        XCTAssertEqual(seen.value, ciphertext)
    }
}

// MARK: - Test helpers

/// A mutable box usable from a test's background thread.
final class UncheckedBox<T>: @unchecked Sendable {
    var value: T
    init(_ value: T) { self.value = value }
}

/// A short-lived directory under `/tmp`, kept short because
/// `sockaddr_un.sun_path` is only 104 octets and `$TMPDIR` alone can eat 60.
struct TemporarySocketPath {
    let directory: String
    var socket: String { directory + "/S" }

    init() throws {
        directory = "/tmp/ak" + String(UInt32.random(in: 0..<0xFFFF_FFFF), radix: 16)
        try FileManager.default.createDirectory(
            atPath: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
    }

    func cleanup() {
        try? FileManager.default.removeItem(atPath: directory)
    }
}

extension AssuanConnection {
    /// Write bytes with no line framing or validation, so tests can simulate a
    /// peer that does not follow the rules.
    func writeRawForTesting(_ bytes: [UInt8]) throws {
        var offset = 0
        try bytes.withUnsafeBytes { buf in
            while offset < bytes.count {
                let n = send(fd, buf.baseAddress! + offset, bytes.count - offset, 0)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw AssuanIOError("send failed", errno: errno)
                }
                offset += n
            }
        }
    }
}
