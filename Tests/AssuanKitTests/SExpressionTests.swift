import XCTest
@testable import AssuanKit

/// Canonical S-expressions, checked against real libgcrypt output.
final class SExpressionTests: XCTestCase {

    /// A `(public-key(ecc(curve NIST P-256)(q …)))` exactly as gpg-agent 2.5.20
    /// returned it from `READKEY` for a freshly generated key — the raw octets
    /// after `D`-line unescaping. The `q` point deliberately contains 0x25 and
    /// 0x0A, the two octets that have to survive percent escaping.
    private var liveAgentPublicKey: Data {
        var q = Data([0x04])
        q.append(contentsOf: [0x80, 0x0F, 0x25, 0xB9, 0x6A, 0x3C, 0x86, 0x98,
                              0xD0, 0xF6, 0x04, 0x15, 0x51, 0x56, 0x07, 0x21,
                              0x3B, 0x80, 0x52, 0x08, 0x68, 0xE3, 0x41, 0x95,
                              0xD9, 0x17, 0x8F, 0x0A, 0x85, 0x29, 0xCE, 0xA2])
        q.append(contentsOf: [0x19, 0xA3, 0x16, 0x9E, 0x8B, 0x97, 0xB1, 0xD1,
                              0xCA, 0xFC, 0x59, 0x94, 0xEE, 0x1E, 0x0B, 0xD3,
                              0xA9, 0x0B, 0x7E, 0x58, 0xDE, 0x42, 0x26, 0x68,
                              0x47, 0x6E, 0x5F, 0x04, 0xB2, 0x23, 0xE8, 0x9C])
        var out = Data("(10:public-key(3:ecc(5:curve10:NIST P-256)(1:q65:".utf8)
        out.append(q)
        out.append(contentsOf: Array(")))".utf8))
        return out
    }

    // MARK: Serialization

    func testSerializesSimpleList() {
        let sexp = SExpression.list([.atom("foo"), .atom("bar")])
        XCTAssertEqual(sexp.serialize(), Data("(3:foo3:bar)".utf8))
    }

    func testSerializesEmptyListAndEmptyAtom() {
        XCTAssertEqual(SExpression.list([]).serialize(), Data("()".utf8))
        XCTAssertEqual(SExpression.atom(Data()).serialize(), Data("0:".utf8))
    }

    func testSerializesNestedStructure() {
        let sexp = SExpression.list([
            .atom("sig-val"),
            .list([.atom("ecdsa"),
                   .list([.atom("r"), .atom(Data([0x01, 0x02]))]),
                   .list([.atom("s"), .atom(Data([0x03]))])]),
        ])
        XCTAssertEqual(
            sexp.serialize(),
            Data("(7:sig-val(5:ecdsa(1:r2:".utf8) + Data([0x01, 0x02])
                + Data(")(1:s1:".utf8) + Data([0x03]) + Data(")))".utf8))
    }

    func testAtomsCarryArbitraryBinaryIncludingParensAndDigits() {
        // Length prefixing is what makes canonical form unambiguous: an atom
        // holding "(3:x)" must not confuse the parser.
        let sexp = SExpression.list([.atom("k"), .atom(Data("(3:x)".utf8))])
        XCTAssertEqual(try SExpression.parse(sexp.serialize()), sexp)
    }

    // MARK: Parsing

    func testParsesSimpleList() throws {
        XCTAssertEqual(
            try SExpression.parse(Data("(3:foo3:bar)".utf8)),
            .list([.atom("foo"), .atom("bar")]))
    }

    func testRoundTripsLiveAgentPublicKey() throws {
        let parsed = try SExpression.parse(liveAgentPublicKey)
        XCTAssertEqual(parsed.serialize(), liveAgentPublicKey,
                       "re-serialization must be byte-identical to libgcrypt's output")
        XCTAssertEqual(parsed.items?.first?.atomString, "public-key")
        let ecc = try XCTUnwrap(parsed.find("ecc"))
        XCTAssertEqual(ecc.value("curve").map { String(decoding: $0, as: UTF8.self) },
                       "NIST P-256")
        let q = try XCTUnwrap(ecc.value("q"))
        XCTAssertEqual(q.count, 65)
        XCTAssertEqual(q.first, 0x04, "uncompressed point prefix")
    }

    func testParsesLiveAgentSignature() throws {
        // From gpg-agent 2.5.20's PKSIGN reply.
        var wire = Data("(7:sig-val(5:ecdsa(1:r32:".utf8)
        let r = Data((0..<32).map { UInt8(($0 * 7 + 1) % 256) })
        let s = Data((0..<32).map { UInt8(($0 * 11 + 3) % 256) })
        wire.append(r)
        wire.append(contentsOf: Array(")(1:s32:".utf8))
        wire.append(s)
        wire.append(contentsOf: Array(")))".utf8))

        let parsed = try SExpression.parse(wire)
        let rs = try XCTUnwrap(parsed.ecdsaSignatureRS())
        XCTAssertEqual(rs.r, r)
        XCTAssertEqual(rs.s, s)
        XCTAssertEqual(parsed.serialize(), wire)
    }

    func testToleratesTheTrailingNULLibgcryptAppends() throws {
        // gcry_sexp_sprint NUL-terminates its buffer and gpg-agent sometimes
        // sends that octet along.
        var wire = Data("(3:foo)".utf8)
        wire.append(0x00)
        XCTAssertEqual(try SExpression.parse(wire), .list([.atom("foo")]))
    }

    func testRejectsTrailingGarbage() {
        XCTAssertThrowsError(try SExpression.parse(Data("(3:foo)xx".utf8)))
    }

    func testRejectsTruncatedAtom() {
        XCTAssertThrowsError(try SExpression.parse(Data("(9:foo)".utf8)))
    }

    func testRejectsUnterminatedList() {
        XCTAssertThrowsError(try SExpression.parse(Data("(3:foo".utf8)))
    }

    func testRejectsMissingColon() {
        XCTAssertThrowsError(try SExpression.parse(Data("(3foo)".utf8)))
    }

    func testRejectsLeadingZeroLength() {
        // Canonical form has exactly one spelling per length; "03:foo" is the
        // sort of thing a re-encoder must never accept and then reproduce.
        XCTAssertThrowsError(try SExpression.parse(Data("(03:foo)".utf8)))
        XCTAssertEqual(try SExpression.parse(Data("(0:)".utf8)), .list([.atom(Data())]))
    }

    func testRejectsDisplayHints() {
        // Rivest's advanced form allows [hint]data; libgcrypt's canonical
        // output never does, so silently accepting one would let a peer smuggle
        // a shape we cannot faithfully re-emit.
        XCTAssertThrowsError(try SExpression.parse(Data("([3:foo]3:bar)".utf8)))
    }

    func testRejectsRunawayNesting() {
        let deep = Data(String(repeating: "(", count: 5000).utf8)
        XCTAssertThrowsError(try SExpression.parse(deep))
    }

    func testRejectsAbsurdAtomLength() {
        XCTAssertThrowsError(try SExpression.parse(Data("99999999999999999999999:x".utf8)))
    }

    // MARK: Lookup

    func testFindAndValue() throws {
        let sexp = try SExpression.parse(Data("(3:key(3:ecc(5:curve5:P-256)(1:q2:ab)))".utf8))
        let ecc = try XCTUnwrap(sexp.find("ecc"))
        XCTAssertEqual(ecc.value("curve"), Data("P-256".utf8))
        XCTAssertEqual(ecc.value("q"), Data("ab".utf8))
        XCTAssertNil(ecc.value("missing"))
        XCTAssertNil(sexp.find("nope"))
    }

    // MARK: gcrypt MPI encoding

    func testMPIStripsLeadingZeros() {
        XCTAssertEqual(SExpression.gcryptMPI(Data([0x00, 0x00, 0x01, 0x02])), Data([0x01, 0x02]))
    }

    func testMPIPadsWhenTopBitIsSet() {
        // libgcrypt's STD format is signed, so a value whose leading octet has
        // the high bit set gains a 0x00 prefix. Getting this wrong yields a
        // signature gpg rejects.
        XCTAssertEqual(SExpression.gcryptMPI(Data([0x80, 0x01])), Data([0x00, 0x80, 0x01]))
        XCTAssertEqual(SExpression.gcryptMPI(Data([0x7F, 0x01])), Data([0x7F, 0x01]))
    }

    func testMPIOfAllZerosIsASingleZero() {
        XCTAssertEqual(SExpression.gcryptMPI(Data([0x00, 0x00])), Data([0x00]))
        XCTAssertEqual(SExpression.gcryptMPI(Data()), Data([0x00]))
    }

    func testEcdsaSigValShape() throws {
        let sexp = SExpression.ecdsaSigVal(r: Data([0x00, 0x80]), s: Data([0x01]))
        XCTAssertEqual(
            sexp.serialize(),
            Data("(7:sig-val(5:ecdsa(1:r2:".utf8) + Data([0x00, 0x80])
                + Data(")(1:s1:".utf8) + Data([0x01]) + Data(")))".utf8))
        let rs = try XCTUnwrap(sexp.ecdsaSignatureRS())
        XCTAssertEqual(rs.r, Data([0x00, 0x80]))
    }

    func testEccPublicKeyShapeMatchesTheAgents() throws {
        var q = Data([0x04])
        q.append(Data(repeating: 0xAA, count: 64))
        let sexp = SExpression.eccPublicKey(curve: "NIST P-256", q: q)
        let expected = Data("(10:public-key(3:ecc(5:curve10:NIST P-256)(1:q65:".utf8)
            + q + Data(")))".utf8)
        XCTAssertEqual(sexp.serialize(), expected)
        // An uncompressed point starts 0x04, whose top bit is clear, so the MPI
        // rule must leave it untouched.
        XCTAssertEqual(try XCTUnwrap(sexp.find("ecc").flatMap { $0.value("q") }), q)
    }
}
