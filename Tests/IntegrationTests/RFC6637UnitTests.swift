import XCTest
@testable import GPGSepDaemonCore

/// Hardware-free checks of the RFC 6637 primitives, so a decrypt failure can be
/// localised to the crypto vs. the Assuan plumbing.
final class RFC6637UnitTests: XCTestCase {

    /// RFC 3394 §4.1 test vector: 128-bit KEK, 128-bit key.
    func testAESKeyUnwrapKnownVector() throws {
        let kek = Data(hexString: "000102030405060708090A0B0C0D0E0F")!
        let wrapped = Data(hexString: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")!
        let expected = Data(hexString: "00112233445566778899AABBCCDDEEFF")!
        let unwrapped = try RFC6637.aesKeyUnwrap(kek: kek, wrapped: wrapped)
        XCTAssertEqual(unwrapped, expected)
    }

    /// RFC 3394 §4.6: 256-bit KEK, 256-bit key.
    func testAESKeyUnwrap256Vector() throws {
        let kek = Data(hexString: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")!
        let wrapped = Data(hexString: """
        28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21
        """.replacingOccurrences(of: "\n", with: ""))!
        let expected = Data(hexString: "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")!
        let unwrapped = try RFC6637.aesKeyUnwrap(kek: kek, wrapped: wrapped)
        XCTAssertEqual(unwrapped, expected)
    }

    /// The single-step KDF reduces to one SHA-256 block for a 16-byte KEK.
    func testSingleStepKDFMatchesSHA256Prefix() throws {
        let z = Data(repeating: 0x11, count: 32)
        let info = Data("param".utf8)
        let kek = try RFC6637.singleStepKDF(hashAlgo: 8, z: z, otherInfo: info, length: 16)
        XCTAssertEqual(kek.count, 16)
        // Recompute the expected leftmost 16 bytes of SHA256(0x00000001 || z || info).
        var input = Data([0x00, 0x00, 0x00, 0x01])
        input.append(z)
        input.append(info)
        let full = try RFC6637.digest(hashAlgo: 8, input)
        XCTAssertEqual(kek, full.prefix(16))
    }
}
