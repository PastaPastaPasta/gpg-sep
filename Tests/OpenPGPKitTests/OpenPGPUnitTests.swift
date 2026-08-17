import XCTest
import CryptoKit
@testable import OpenPGPKit

/// Golden reference point + values taken from a real gpg 2.5.20 nistp256 ECDSA
/// key (see interop tests for the live re-derivation).
private let refX = Data(hex: "b5820c8b1000401dc867331ccee6ed7caf7a573d38e60709b207523c658bb91c")
private let refY = Data(hex: "447ced33fe800664193f1be40b6f2201c659e542c5bf9ccb4e369c05df0be947")
private let refCreation: UInt32 = 1786991580
private let refFingerprint = "117AB0EFA559C231DE498CE59D64866248F27D9B"
private let refKeygrip = "A30297C9D1960C2380C6F22B7A3905B9DEFC8266"

final class OpenPGPUnitTests: XCTestCase {

    func testKeygripMatchesGpgGolden() {
        let point = ECPoint(x: refX, y: refY)
        XCTAssertEqual(Keygrip.p256(point: point).hexUpper, refKeygrip)
    }

    func testFingerprintAndKeyIDMatchGpgGolden() {
        let pkt = PGPPublicKeyPacket(creationTime: refCreation, algorithm: .ecdsa, point: ECPoint(x: refX, y: refY))
        XCTAssertEqual(pkt.fingerprint.hexUpper, refFingerprint)
        XCTAssertEqual(pkt.keyID.hexUpper, String(refFingerprint.suffix(16)))
    }

    func testEcdsaKeyBodyGoldenBytes() {
        // Reproduces the exact body bytes gpg exported for the reference key.
        let pkt = PGPPublicKeyPacket(creationTime: refCreation, algorithm: .ecdsa, point: ECPoint(x: refX, y: refY))
        let expected = "046a8353dc13082a8648ce3d0301070203" + "04" + refX.hexLower + refY.hexLower
        XCTAssertEqual(pkt.bodyData().hexLower, expected)
        // Old-format tag-6 header: 0x98, length 0x52 (82).
        XCTAssertEqual(pkt.packetData(subkey: false).prefix(2).hexLower, "9852")
    }

    func testEcdhKdfParametersBytes() {
        let pkt = PGPPublicKeyPacket(creationTime: refCreation, algorithm: .ecdh, point: ECPoint(x: refX, y: refY))
        // Body must end with the KDF field 03 01 08 07 (len, reserved, SHA-256, AES-128).
        XCTAssertEqual(pkt.bodyData().suffix(4).hexLower, "03010807")
        // Subkey header uses tag 14 -> 0xB8.
        XCTAssertEqual(pkt.packetData(subkey: true).first, 0xB8)
    }

    func testMPIEncodeStripsLeadingZeros() {
        // 0x000A -> bit length 4, one body byte 0x0A.
        XCTAssertEqual(MPI.encode(Data([0x00, 0x0A])).hexLower, "00040a")
        // 0x01FF -> 9 bits.
        XCTAssertEqual(MPI.encode(Data([0x01, 0xFF])).hexLower, "000901ff")
        // zero.
        XCTAssertEqual(MPI.encode(Data([0x00, 0x00])).hexLower, "0000")
    }

    func testMPIRoundTrip() throws {
        let value = Data(hex: "00ab34ef")
        let enc = MPI.encode(value)
        let (dec, next) = try MPI.decode(enc, at: 0)
        XCTAssertEqual(dec.hexLower, "ab34ef")
        XCTAssertEqual(next, enc.count)
    }

    func testPointMPIIs515Bits() {
        let point = ECPoint(x: refX, y: refY)
        // 0x0203 = 515 bits for a 65-byte uncompressed point with 0x04 prefix.
        XCTAssertEqual(point.pointMPI.prefix(3).hexLower, "020304")
        XCTAssertEqual(point.pointMPI.count, 2 + 65)
    }

    func testDERToRawRS() throws {
        // Sign something with CryptoKit and confirm DER->raw round-trips.
        let key = P256.Signing.PrivateKey()
        let sig = try key.signature(for: Data("hello".utf8))
        let (r, s) = try ecdsaDERToRawRS(sig.derRepresentation)
        // CryptoKit's rawRepresentation is r||s, each padded to 32 bytes.
        let raw = sig.rawRepresentation
        let expR = raw.prefix(32)
        let expS = raw.suffix(32)
        XCTAssertEqual(try leftPad(r, to: 32).hexLower, Data(expR).hexLower)
        XCTAssertEqual(try leftPad(s, to: 32).hexLower, Data(expS).hexLower)
    }

    func testDERToRawRSRejectsGarbage() {
        XCTAssertThrowsError(try ecdsaDERToRawRS(Data([0x31, 0x00])))
    }

    func testArmorRoundTripAndCRC() throws {
        let payload = Data((0..<200).map { UInt8($0 & 0xFF) })
        let armored = Armor.armor(payload, type: .publicKey)
        XCTAssertTrue(armored.hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        XCTAssertTrue(armored.contains("\n=")) // CRC line
        let back = try Armor.dearmor(armored)
        XCTAssertEqual(back, payload)
    }

    func testArmorCRCKnownVector() {
        // CRC-24 of empty input is the init value 0xB704CE.
        XCTAssertEqual(Armor.crc24(Data()), 0xB704CE)
    }

    func testSubpacketLengthEncoding() {
        // A 1-byte body subpacket => length octet = 2 (type + body).
        let sp = PGPSubpacket.keyFlags([.sign, .certify])
        let enc = sp.encoded()
        XCTAssertEqual(enc.first, 0x02)      // length
        XCTAssertEqual(enc[enc.startIndex + 1], 27) // type
        XCTAssertEqual(enc.last, 0x03)       // sign|certify
    }

    func testIssuerFingerprintSubpacket() {
        let fpr = Data(hex: refFingerprint)
        let sp = PGPSubpacket.issuerFingerprint(fpr)
        let enc = sp.encoded()
        // length 22 (1 type + 1 version + 20 fpr), type 33, version 4.
        XCTAssertEqual(enc.first, 22)
        XCTAssertEqual(enc[enc.startIndex + 1], 33)
        XCTAssertEqual(enc[enc.startIndex + 2], 0x04)
    }
}

// MARK: - Hex helpers

extension Data {
    init(hex: String) {
        var d = Data()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            d.append(UInt8(hex[idx..<next], radix: 16)!)
            idx = next
        }
        self = d
    }
    var hexLower: String { map { String(format: "%02x", $0) }.joined() }
    var hexUpper: String { map { String(format: "%02X", $0) }.joined() }
}
