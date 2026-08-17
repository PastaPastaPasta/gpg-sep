import XCTest
@testable import AssuanKit

/// Parsing and serializing the Assuan line grammar in both directions.
final class LineTests: XCTestCase {

    private func response(_ text: String) throws -> AssuanLine {
        try AssuanLine.parseResponse(Array(text.utf8))
    }

    private func command(_ text: String) throws -> AssuanLine {
        try AssuanLine.parseCommand(Array(text.utf8))
    }

    // MARK: Responses

    func testParsesBareOK() throws {
        XCTAssertEqual(try response("OK"), .ok(nil))
    }

    func testParsesOKWithText() throws {
        XCTAssertEqual(try response("OK closing connection"), .ok("closing connection"))
    }

    func testParsesTheRealGreeting() throws {
        // Verbatim from gpg-agent 2.5.20.
        XCTAssertEqual(
            try response("OK Pleased to meet you, process 66200"),
            .ok("Pleased to meet you, process 66200"))
    }

    func testParsesTheRealUnknownCommandError() throws {
        // Verbatim from gpg-agent 2.5.20 for an unrecognised verb.
        let line = try response("ERR 67109139 Unknown IPC command <GPG Agent>")
        XCTAssertEqual(line, .err(code: 67_109_139, text: "Unknown IPC command <GPG Agent>"))
    }

    func testErrorNumberDecomposesIntoSourceAndCode() {
        // 67109139 == (GPG_ERR_SOURCE_GPGAGENT << 24) | GPG_ERR_ASS_UNKNOWN_CMD
        let error = AssuanError(number: 67_109_139)
        XCTAssertEqual(error.source, GPGErrorSource.gpgAgent)
        XCTAssertEqual(error.code, 275)
        XCTAssertEqual(GPGError.assUnknownCmd.number(source: GPGErrorSource.gpgAgent), 67_109_139)
    }

    func testErrorNumberPacking() {
        XCTAssertEqual(gpgError(275, source: 4), 67_109_139)
        XCTAssertEqual(gpgError(99, source: 4), 67_108_963)
        // A source-less code is just the code, as libgpg-error defines it.
        XCTAssertEqual(gpgError(1, source: GPGErrorSource.unknown), 1)
        let parts = gpgErrorComponents(16_777_404)
        XCTAssertEqual(parts.source, 1) // GPG_ERR_SOURCE_GCRYPT
        XCTAssertEqual(parts.code, 188)
    }

    func testParsesErrWithoutText() throws {
        XCTAssertEqual(try response("ERR 1"), .err(code: 1, text: nil))
    }

    func testRejectsErrWithoutNumericCode() {
        XCTAssertThrowsError(try response("ERR oops"))
    }

    func testParsesStatusLine() throws {
        XCTAssertEqual(
            try response("S KEYINFO 1583217963C374BFBDAEAD409A749F1869C2C441 D - - - C - - -"),
            .status(keyword: "KEYINFO",
                    args: "1583217963C374BFBDAEAD409A749F1869C2C441 D - - - C - - -"))
    }

    func testParsesStatusLineWithoutArgs() throws {
        XCTAssertEqual(try response("S KEYGRIP"), .status(keyword: "KEYGRIP", args: ""))
    }

    func testParsesInquire() throws {
        XCTAssertEqual(try response("INQUIRE KEYPARAM"), .inquire(keyword: "KEYPARAM", args: ""))
        XCTAssertEqual(try response("INQUIRE CONFIRM 1"), .inquire(keyword: "CONFIRM", args: "1"))
    }

    func testParsesDataLineAndUnescapes() throws {
        XCTAssertEqual(try response("D a%25b%0Ac"), .data(Data("a%b\nc".utf8)))
    }

    func testParsesComment() throws {
        XCTAssertEqual(try response("# NOP"), .comment("NOP"))
    }

    func testRejectsUnknownResponseKeyword() {
        XCTAssertThrowsError(try response("WAT something"))
        XCTAssertThrowsError(try response(""))
    }

    // MARK: Commands

    func testParsesCommandAndUppercasesVerb() throws {
        XCTAssertEqual(
            try command("sethash --hash=sha256 ABCD"),
            .command(verb: "SETHASH", rest: "--hash=sha256 ABCD"))
    }

    func testParsesBareCommand() throws {
        XCTAssertEqual(try command("BYE"), .command(verb: "BYE", rest: ""))
        XCTAssertEqual(try command("END"), .command(verb: "END", rest: ""))
        XCTAssertEqual(try command("CAN"), .command(verb: "CAN", rest: ""))
    }

    func testParsesClientDataLine() throws {
        XCTAssertEqual(try command("D (3:foo)"), .data(Data("(3:foo)".utf8)))
    }

    func testBlankLineIsAComment() throws {
        XCTAssertEqual(try command(""), .comment(""))
    }

    func testCommentLineFromClient() throws {
        XCTAssertEqual(try command("# hello"), .comment("hello"))
    }

    // MARK: Serialization

    func testSerializationRoundTripsResponses() throws {
        let lines: [AssuanLine] = [
            .ok(nil),
            .ok("Pleased to meet you, process 1"),
            .err(code: 67_109_139, text: "Unknown IPC command <GPG Agent>"),
            .err(code: 1, text: nil),
            .status(keyword: "INQUIRE_MAXLEN", args: "1024"),
            .status(keyword: "KEYGRIP", args: ""),
            .inquire(keyword: "KEYPARAM", args: ""),
            .inquire(keyword: "CONFIRM", args: "1"),
            .comment("NOP"),
            .data(Data([0x00, 0x25, 0x0A, 0x0D, 0xFF])),
        ]
        for line in lines {
            XCTAssertEqual(try AssuanLine.parseResponse(line.serialize()), line, "\(line)")
        }
    }

    func testSerializationRoundTripsCommands() throws {
        let lines: [AssuanLine] = [
            .command(verb: "BYE", rest: ""),
            .command(verb: "SETHASH", rest: "--hash=sha256 AB"),
            .comment("x"),
            .data(Data("(7:sig-val)".utf8)),
        ]
        for line in lines {
            XCTAssertEqual(try AssuanLine.parseCommand(line.serialize()), line, "\(line)")
        }
    }

    func testSerializedDataLineMatchesTheWireFormat() {
        let line = AssuanLine.data(Data([0x25, 0x0D, 0x0A]))
        XCTAssertEqual(line.serialize(), Data("D %25%0D%0A".utf8))
    }

    func testSerializedErrMatchesTheAgentsExactBytes() {
        let line = AssuanLine.err(code: 67_109_139, text: "Unknown IPC command <GPG Agent>")
        XCTAssertEqual(line.serialize(), Data("ERR 67109139 Unknown IPC command <GPG Agent>".utf8))
    }

    // MARK: Payload edges

    func testDataLineWithNoPayload() throws {
        XCTAssertEqual(try response("D "), .data(Data()))
        XCTAssertEqual(try response("D"), .data(Data()))
    }

    func testExtraSpacesAfterDGoIntoThePayload() throws {
        // Exactly one space separates `D` from its payload; anything further is
        // data, since a payload may legitimately begin with a space.
        XCTAssertEqual(try response("D  x"), .data(Data(" x".utf8)))
    }
}
