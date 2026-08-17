import XCTest
@testable import AssuanKit

/// Percent / percent-plus escaping, and the `D`-line wrapping that has to match
/// libassuan octet for octet.
final class EscapingTests: XCTestCase {

    // MARK: Percent (D lines)

    func testPercentEncodeEscapesOnlyPercentCRLF() {
        let raw = Data([0x25, 0x0D, 0x0A])
        XCTAssertEqual(AssuanEscaping.percentEncode(raw), Data("%25%0D%0A".utf8))
    }

    func testPercentEncodeLeavesEveryOtherOctetAlone() {
        // Binary S-expression payloads carry NUL, high bytes and '+' verbatim;
        // escaping any of them would corrupt a key or a signature.
        var raw = Data()
        for byte in UInt8.min...UInt8.max where byte != 0x25 && byte != 0x0D && byte != 0x0A {
            raw.append(byte)
        }
        XCTAssertEqual(AssuanEscaping.percentEncode(raw), raw)
    }

    func testPercentUsesUppercaseHex() {
        // The manual: "only uppercase letters should be used in the escape".
        let encoded = AssuanEscaping.percentEncode(Data([0x0D]))
        XCTAssertEqual(String(decoding: encoded, as: UTF8.self), "%0D")
    }

    func testPercentRoundTripsEveryOctet() {
        let raw = Data(UInt8.min...UInt8.max)
        XCTAssertEqual(AssuanEscaping.percentDecode(AssuanEscaping.percentEncode(raw)), raw)
    }

    func testPercentDecodeAcceptsLowercaseHex() {
        // libassuan's xtoi_2 is case insensitive, so we accept what it accepts.
        XCTAssertEqual(AssuanEscaping.percentDecode(Data("%0a%0d%25".utf8)), Data([0x0A, 0x0D, 0x25]))
    }

    func testPercentDecodeKeepsMalformedEscapeLiteral() {
        // A truncated or non-hex escape must not throw or swallow input: the
        // wire is never trusted to knock the proxy over.
        XCTAssertEqual(AssuanEscaping.percentDecode(Data("a%".utf8)), Data("a%".utf8))
        XCTAssertEqual(AssuanEscaping.percentDecode(Data("a%z9b".utf8)), Data("a%z9b".utf8))
        XCTAssertEqual(AssuanEscaping.percentDecode(Data("%4".utf8)), Data("%4".utf8))
    }

    func testPercentDecodeMatchesLiveAgentBytes() throws {
        // Captured verbatim from gpg-agent 2.5.20's READKEY reply for a freshly
        // generated NIST P-256 key: 0x25 and 0x0A appear as %25 / %0A while
        // 0x04, 0x80 and 0x0B travel raw.
        var onTheWire = Data("(1:q6:".utf8)
        onTheWire.append(0x04)
        onTheWire.append(contentsOf: Array("%25".utf8))
        onTheWire.append(0x80)
        onTheWire.append(contentsOf: Array("%0A".utf8))
        onTheWire.append(0x0B)
        onTheWire.append(contentsOf: Array(")".utf8))

        let decoded = AssuanEscaping.percentDecode(onTheWire)
        XCTAssertEqual(decoded, Data([0x28, 0x31, 0x3A, 0x71, 0x36, 0x3A,
                                      0x04, 0x25, 0x80, 0x0A, 0x0B, 0x29]))
    }

    // MARK: Percent-plus (command arguments)

    func testPercentPlusEncodesSpaceAsPlus() {
        XCTAssertEqual(AssuanEscaping.percentPlusEncode("a b"), "a+b")
    }

    func testPercentPlusEscapesLiteralPlus() {
        XCTAssertEqual(AssuanEscaping.percentPlusEncode("a+b"), "a%2Bb")
    }

    func testPercentPlusRoundTripsEveryOctet() {
        let raw = Data(UInt8.min...UInt8.max)
        let encoded = AssuanEscaping.percentPlusEncode(raw)
        XCTAssertEqual(AssuanEscaping.percentPlusDecode(encoded), raw)
    }

    func testPercentPlusEncodingStays7BitAndLineSafe() {
        let encoded = AssuanEscaping.percentPlusEncode(Data(UInt8.min...UInt8.max))
        for byte in encoded {
            XCTAssertTrue(byte > 0x20 && byte < 0x7F, "0x\(String(byte, radix: 16)) is not line-safe")
        }
    }

    func testPercentPlusDecodeOfAgentStyleDescription() {
        // SETKEYDESC takes a percent-plus escaped string; this is the shape
        // gpg sends for a signing prompt.
        let wire = "Please+enter+the+passphrase%0Afor+key+%22test%22"
        XCTAssertEqual(
            AssuanEscaping.percentPlusDecodeToString(wire),
            "Please enter the passphrase\nfor key \"test\"")
    }

    // MARK: D-line wrapping

    func testDataLineBodiesEmptyInputProducesNoLines() {
        // assuan_send_data with a zero-length buffer emits nothing at all.
        XCTAssertEqual(AssuanEscaping.dataLineBodies(Data()), [])
    }

    func testShortPayloadIsOneLine() {
        let bodies = AssuanEscaping.dataLineBodies(Data("hello".utf8))
        XCTAssertEqual(bodies, [Data("D hello".utf8)])
    }

    func testDataLinesWrapAtLibassuanFillLimit() {
        // _assuan_cookie_write_data appends while the line (including "D ") is
        // shorter than LINELENGTH-2-2 == 998, so with no escaping the first
        // line is exactly 998 octets: "D " plus 996 payload octets.
        let payload = Data(repeating: UInt8(ascii: "x"), count: 2000)
        let bodies = AssuanEscaping.dataLineBodies(payload)
        XCTAssertEqual(bodies[0].count, AssuanLimits.dataFillLimit)
        XCTAssertEqual(bodies[1].count, AssuanLimits.dataFillLimit)
        XCTAssertEqual(bodies.count, 3)
        XCTAssertEqual(bodies[2].count, 2 + (2000 - 2 * 996))
    }

    func testDataLinesNeverExceedTheLineBuffer() {
        // All-escaped input is the worst case: every octet costs three. The
        // overshoot is bounded at two octets, so a line tops out at 1000 — well
        // inside what a libassuan peer will read back.
        let payload = Data(repeating: 0x0A, count: 5000)
        for body in AssuanEscaping.dataLineBodies(payload) {
            XCTAssertLessThanOrEqual(body.count, AssuanLimits.nominalMaxLine)
            XCTAssertLessThanOrEqual(body.count, AssuanLimits.maxLineContent)
        }
    }

    func testWrappedDataLinesReassembleToTheOriginal() {
        var payload = Data()
        for i in 0..<7000 { payload.append(UInt8(i % 256)) }
        var rebuilt = Data()
        for body in AssuanEscaping.dataLineBodies(payload) {
            XCTAssertEqual(body.prefix(2), Data("D ".utf8))
            rebuilt.append(AssuanEscaping.percentDecode(body.dropFirst(2)))
        }
        XCTAssertEqual(rebuilt, payload)
    }

    func testDataLinesCarryBinaryUnescapedApartFromTheThreeSpecials() {
        let payload = Data([0x00, 0x01, 0x25, 0xFF, 0x0D, 0x0A, 0x2B, 0x20])
        let bodies = AssuanEscaping.dataLineBodies(payload)
        XCTAssertEqual(bodies.count, 1)
        XCTAssertEqual(bodies[0], Data([0x44, 0x20, 0x00, 0x01]) + Data("%25".utf8)
                       + Data([0xFF]) + Data("%0D%0A".utf8) + Data([0x2B, 0x20]))
    }
}
