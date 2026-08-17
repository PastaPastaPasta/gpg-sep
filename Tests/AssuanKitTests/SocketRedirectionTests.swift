import Darwin
import Foundation
import XCTest
@testable import AssuanKit

/// GnuPG's `%Assuan%` socket redirection files, whose exact byte layout is
/// fixed by `eval_redirection` in libassuan's `assuan-socket.c`.
final class SocketRedirectionTests: XCTestCase {

    private var directory = ""

    override func setUpWithError() throws {
        directory = "/tmp/rd" + String(UInt32.random(in: 0..<0xFFFF_FFFF), radix: 16)
        try FileManager.default.createDirectory(
            atPath: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: directory)
    }

    private func write(_ contents: Data, to name: String) throws -> String {
        let path = directory + "/" + name
        try contents.write(to: URL(fileURLWithPath: path))
        return path
    }

    // MARK: Writing

    func testWrittenFileHasTheExactByteLayout() throws {
        let path = directory + "/S.gpg-agent"
        try AssuanSocketRedirection.write(at: path, socketPath: "/tmp/x/S")
        let contents = try Data(contentsOf: URL(fileURLWithPath: path))
        XCTAssertEqual(contents, Data("%Assuan%\nsocket=/tmp/x/S\n".utf8))
    }

    func testWrittenFileIsPrivate() throws {
        let path = directory + "/S.gpg-agent"
        try AssuanSocketRedirection.write(at: path, socketPath: "/tmp/x/S")
        let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? NSNumber
        XCTAssertEqual(mode?.int16Value, 0o600)
    }

    func testWritingReplacesAnExistingSocket() throws {
        let path = directory + "/S.gpg-agent"
        let listener = try AssuanListener(path: path)
        listener.closeAndUnlink()
        // Re-create a socket at the path, then overwrite it with a redirection.
        let live = try AssuanListener(path: path)
        try AssuanSocketRedirection.write(at: path, socketPath: "/tmp/x/S")
        live.closeAndUnlink()
        XCTAssertEqual(try AssuanSocketRedirection.target(ofFileAt: path), "/tmp/x/S")
    }

    func testRoundTrip() throws {
        let path = directory + "/S.gpg-agent"
        try AssuanSocketRedirection.write(at: path, socketPath: "/private/tmp/abc/S.gpg-agent")
        XCTAssertEqual(
            try AssuanSocketRedirection.target(ofFileAt: path), "/private/tmp/abc/S.gpg-agent")
        XCTAssertEqual(
            try AssuanSocketRedirection.resolve(path), "/private/tmp/abc/S.gpg-agent")
    }

    func testRefusesToWriteANameWithANewline() {
        XCTAssertThrowsError(
            try AssuanSocketRedirection.write(at: directory + "/x", socketPath: "/tmp/a\nb"))
    }

    func testRefusesToWriteAnOverlongFile() {
        let huge = "/tmp/" + String(repeating: "z", count: 600)
        XCTAssertThrowsError(
            try AssuanSocketRedirection.write(at: directory + "/x", socketPath: huge))
    }

    // MARK: Reading

    func testPlainSocketIsNotARedirection() throws {
        let path = directory + "/S"
        let listener = try AssuanListener(path: path)
        defer { listener.closeAndUnlink() }
        XCTAssertNil(try AssuanSocketRedirection.target(ofFileAt: path))
        XCTAssertEqual(try AssuanSocketRedirection.resolve(path), path)
    }

    func testMissingPathIsNotARedirection() throws {
        XCTAssertNil(try AssuanSocketRedirection.target(ofFileAt: directory + "/nope"))
    }

    func testFileWithoutTheMagicIsNotARedirection() throws {
        let path = try write(Data("just a file\n".utf8), to: "plain")
        XCTAssertNil(try AssuanSocketRedirection.target(ofFileAt: path))
    }

    func testRejectsMissingTrailingLF() throws {
        let path = try write(Data("%Assuan%\nsocket=/tmp/x".utf8), to: "nolf")
        XCTAssertThrowsError(try AssuanSocketRedirection.target(ofFileAt: path))
    }

    func testRejectsEmptySocketName() throws {
        let path = try write(Data("%Assuan%\nsocket=\n".utf8), to: "empty")
        XCTAssertThrowsError(try AssuanSocketRedirection.target(ofFileAt: path))
    }

    func testRejectsExtraLines() throws {
        let path = try write(Data("%Assuan%\nsocket=/tmp/x\nextra\n".utf8), to: "extra")
        XCTAssertThrowsError(try AssuanSocketRedirection.target(ofFileAt: path))
    }

    func testRejectsATargetTooLongForSunPath() throws {
        let name = "/tmp/" + String(repeating: "q", count: 200)
        let path = try write(Data("%Assuan%\nsocket=\(name)\n".utf8), to: "long")
        XCTAssertThrowsError(try AssuanSocketRedirection.target(ofFileAt: path))
    }

    func testExpandsEnvironmentVariables() throws {
        setenv("ASSUANKIT_TEST_DIR", "/tmp/expanded", 1)
        defer { unsetenv("ASSUANKIT_TEST_DIR") }
        let path = try write(
            Data("%Assuan%\nsocket=${ASSUANKIT_TEST_DIR}/S.gpg-agent\n".utf8), to: "env")
        XCTAssertEqual(
            try AssuanSocketRedirection.target(ofFileAt: path), "/tmp/expanded/S.gpg-agent")
    }

    func testUnsetVariableExpandsToNothing() throws {
        unsetenv("ASSUANKIT_TEST_UNSET")
        let path = try write(
            Data("%Assuan%\nsocket=/tmp${ASSUANKIT_TEST_UNSET}/S\n".utf8), to: "unset")
        XCTAssertEqual(try AssuanSocketRedirection.target(ofFileAt: path), "/tmp/S")
    }

    func testRejectsUnterminatedVariableReference() throws {
        let path = try write(Data("%Assuan%\nsocket=/tmp/${OOPS\n".utf8), to: "bad")
        XCTAssertThrowsError(try AssuanSocketRedirection.target(ofFileAt: path))
    }

    // MARK: Connecting through one

    func testClientFollowsARedirectionToARealServer() throws {
        let realSocket = directory + "/real"
        let advertised = directory + "/S.gpg-agent"

        let listener = try AssuanListener(path: realSocket)
        defer { listener.closeAndUnlink() }
        try AssuanSocketRedirection.write(at: advertised, socketPath: realSocket)

        let serving = Thread {
            try? listener.serveForever { conn in
                let server = AssuanServer(client: conn, handler: OKHandler())
                try? server.run()
            }
        }
        serving.start()

        let conn = try AssuanConnection.connectFollowingRedirection(to: advertised)
        defer { conn.close() }
        let client = AssuanClient(connection: conn)
        try client.readGreeting()
        XCTAssertTrue(try client.transact("NOP").isOK)
    }
}

private final class OKHandler: AssuanCommandHandler {
    func handle(verb: String, rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        try io.sendOK()
        return .handled
    }
}
