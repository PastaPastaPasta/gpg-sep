import Foundation
import CryptoKit

/// An uncompressed P-256 public point. Each coordinate is exactly 32 bytes,
/// big-endian.
public struct ECPoint: Equatable {
    public let x: Data
    public let y: Data

    public init(x: Data, y: Data) {
        self.x = x
        self.y = y
    }

    /// Validating initializer that enforces the 32-byte P-256 field size.
    public init(validatingX x: Data, y: Data) throws {
        guard x.count == 32 else { throw OpenPGPError.invalidCoordinateLength(expected: 32, got: x.count) }
        guard y.count == 32 else { throw OpenPGPError.invalidCoordinateLength(expected: 32, got: y.count) }
        self.x = x
        self.y = y
    }

    /// SEC1 uncompressed encoding: `0x04 || X || Y` (65 bytes).
    public var uncompressed: Data {
        var d = Data([0x04])
        d.append(x)
        d.append(y)
        return d
    }

    /// The point as a single OpenPGP MPI wrapping the 65-byte uncompressed form.
    /// For P-256 the wrapped value is 515 bits (0x0203).
    public var pointMPI: Data {
        MPI.encode(uncompressed)
    }
}

/// Public-key algorithm identifiers used by this module (RFC 9580 §9.1).
public enum PGPPublicKeyAlgorithm: UInt8 {
    case ecdsa = 19
    case ecdh = 18
}

/// Curve OID constants (RFC 6637 §11 / RFC 9580).
public enum PGPCurve {
    /// NIST P-256 object identifier bytes (1.2.840.10045.3.1.7).
    public static let nistP256OID = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
}

/// Old-format packet header helpers (RFC 9580 §4.2).
enum PacketHeader {
    /// Emit an old-format packet header for the given tag (0..15) and body
    /// length, choosing the smallest length-type field that fits.
    static func oldFormat(tag: UInt8, bodyLength: Int) -> Data {
        precondition(tag < 16, "old-format headers only encode tags 0..15")
        if bodyLength < 0x100 {
            return Data([0x80 | (tag << 2) | 0x00, UInt8(bodyLength)])
        } else if bodyLength < 0x10000 {
            return Data([0x80 | (tag << 2) | 0x01,
                         UInt8((bodyLength >> 8) & 0xFF),
                         UInt8(bodyLength & 0xFF)])
        } else {
            return Data([0x80 | (tag << 2) | 0x02,
                         UInt8((bodyLength >> 24) & 0xFF),
                         UInt8((bodyLength >> 16) & 0xFF),
                         UInt8((bodyLength >> 8) & 0xFF),
                         UInt8(bodyLength & 0xFF)])
        }
    }
}

/// The v4 fingerprint preimage `0x99 || len2(body) || body` (RFC 9580 §5.5.4)
/// for an arbitrary public-key packet body — including RSA and other algorithms
/// this module does not otherwise model. `SHA-1` over this yields the 20-byte
/// fingerprint; the same bytes bind the key inside subkey-binding signatures.
public func v4FingerprintPreimage(publicKeyBody body: Data) -> Data {
    var d = Data([0x99, UInt8((body.count >> 8) & 0xFF), UInt8(body.count & 0xFF)])
    d.append(body)
    return d
}

/// A v4 public-key or public-subkey packet (tag 6 / tag 14) for a nistp256
/// ECDSA or ECDH key.
public struct PGPPublicKeyPacket: Equatable {
    public let creationTime: UInt32
    public let algorithm: PGPPublicKeyAlgorithm
    public let point: ECPoint

    public init(creationTime: UInt32, algorithm: PGPPublicKeyAlgorithm, point: ECPoint) {
        self.creationTime = creationTime
        self.algorithm = algorithm
        self.point = point
    }

    /// The packet body (everything after the tag/length header): version,
    /// creation time, algorithm, curve OID, point MPI, and — for ECDH — the
    /// KDF parameter field.
    public func bodyData() -> Data {
        var d = Data()
        d.append(0x04) // version 4
        d.append(UInt8((creationTime >> 24) & 0xFF))
        d.append(UInt8((creationTime >> 16) & 0xFF))
        d.append(UInt8((creationTime >> 8) & 0xFF))
        d.append(UInt8(creationTime & 0xFF))
        d.append(algorithm.rawValue)
        // Curve OID: one length octet then the OID bytes.
        d.append(UInt8(PGPCurve.nistP256OID.count))
        d.append(PGPCurve.nistP256OID)
        // Public point as a single MPI (0x04 || X || Y).
        d.append(point.pointMPI)
        if algorithm == .ecdh {
            // RFC 6637 §9 KDF params: len(0x03), reserved(0x01),
            // KDF hash id (SHA-256 = 8), KEK cipher id (AES-128 = 7).
            // Verified byte-exact against gpg 2.5.20's default nistp256 ECDH key.
            d.append(contentsOf: [0x03, 0x01, 0x08, 0x07])
        }
        return d
    }

    /// The complete packet including its old-format header. `subkey` selects
    /// tag 14 (public subkey) instead of tag 6 (public primary key).
    public func packetData(subkey: Bool) -> Data {
        let body = bodyData()
        let tag: UInt8 = subkey ? 14 : 6
        var d = PacketHeader.oldFormat(tag: tag, bodyLength: body.count)
        d.append(body)
        return d
    }

    /// The data hashed to form a fingerprint and to bind this key in
    /// signatures: `0x99 || len2(body) || body` (RFC 9580 §5.5.4).
    public var fingerprintPreimage: Data {
        v4FingerprintPreimage(publicKeyBody: bodyData())
    }

    /// 20-byte v4 fingerprint: SHA-1 over the fingerprint preimage.
    public var fingerprint: Data {
        Data(Insecure.SHA1.hash(data: fingerprintPreimage))
    }

    /// Low 8 bytes of the fingerprint.
    public var keyID: Data {
        fingerprint.suffix(8)
    }

    /// 20-byte libgcrypt keygrip for this public point.
    public var keygrip: Data {
        Keygrip.p256(point: point)
    }
}

/// A user ID packet (tag 13). The identity string is stored as UTF-8.
public struct PGPUserIDPacket {
    public let userID: String

    public init(_ userID: String) {
        self.userID = userID
    }

    public func bodyData() -> Data {
        Data(userID.utf8)
    }

    public func packetData() -> Data {
        let body = bodyData()
        var d = PacketHeader.oldFormat(tag: 13, bodyLength: body.count)
        d.append(body)
        return d
    }

    /// The certification preimage chunk: `0xB4 || len4(uid) || uid`
    /// (RFC 9580 §5.2.4).
    public var certificationPreimage: Data {
        let body = bodyData()
        var d = Data([0xB4,
                      UInt8((body.count >> 24) & 0xFF),
                      UInt8((body.count >> 16) & 0xFF),
                      UInt8((body.count >> 8) & 0xFF),
                      UInt8(body.count & 0xFF)])
        d.append(body)
        return d
    }
}
