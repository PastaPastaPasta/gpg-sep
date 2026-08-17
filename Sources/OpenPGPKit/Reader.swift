import Foundation

/// A parsed OpenPGP packet (partial coverage: the packet kinds this module
/// writes).
public enum PGPPacket {
    case publicKey(PGPPublicKeyPacket, subkey: Bool)
    case userID(String)
    case signature(ParsedSignature)
    case unknown(tag: UInt8, body: Data)
}

/// Structural view of a v4 signature packet.
public struct ParsedSignature {
    public let type: UInt8
    public let publicKeyAlgorithm: UInt8
    public let hashAlgorithm: UInt8
    public let hashedSubpacketBytes: Data
    public let unhashedSubpacketBytes: Data
    public let quickCheck: Data // leading 2 octets of the digest
    public let mpis: [Data]     // r, s for ECDSA
}

/// A raw, uninterpreted packet: its tag plus the body bytes and the full
/// on-wire packet bytes (header + body). Lets callers handle packet kinds this
/// module does not model — notably an RSA (algo 1) primary key packet whose body
/// layout differs from the ECDSA/ECDH keys the typed reader understands.
public struct PGPRawPacket {
    public let tag: UInt8
    public let body: Data
    public let packet: Data
}

/// Walk a packet stream returning every packet's tag and raw bytes without
/// interpreting the bodies. Handles both old- and new-format headers.
public enum PGPPacketScanner {
    public static func scan(_ data: Data) throws -> [PGPRawPacket] {
        var packets: [PGPRawPacket] = []
        var i = data.startIndex
        while i < data.endIndex {
            let packetStart = i
            let ctb = data[i]
            guard ctb & 0x80 != 0 else { throw OpenPGPError.malformedPacket("bad CTB \(ctb)") }
            var tag: UInt8
            var length: Int
            i = data.index(after: i)
            if ctb & 0x40 != 0 {
                tag = ctb & 0x3F
                (length, i) = try PGPReader.scanNewLength(data, i)
            } else {
                tag = (ctb >> 2) & 0x0F
                let lenType = ctb & 0x03
                (length, i) = try PGPReader.scanOldLength(data, i, lenType: lenType)
            }
            guard data.distance(from: i, to: data.endIndex) >= length else { throw OpenPGPError.truncated }
            let body = data.subdata(in: i..<data.index(i, offsetBy: length))
            i = data.index(i, offsetBy: length)
            let packet = data.subdata(in: packetStart..<i)
            packets.append(PGPRawPacket(tag: tag, body: body, packet: packet))
        }
        return packets
    }
}

/// Minimal packet reader covering the packet kinds this module emits. Handles
/// both old- and new-format headers.
public enum PGPReader {
    static func scanOldLength(_ data: Data, _ i: Data.Index, lenType: UInt8) throws -> (Int, Data.Index) {
        try readOldLength(data, i, lenType: lenType)
    }
    static func scanNewLength(_ data: Data, _ i: Data.Index) throws -> (Int, Data.Index) {
        try readNewLength(data, i)
    }

    public static func parse(_ data: Data) throws -> [PGPPacket] {
        var packets: [PGPPacket] = []
        var i = data.startIndex
        while i < data.endIndex {
            let ctb = data[i]
            guard ctb & 0x80 != 0 else { throw OpenPGPError.malformedPacket("bad CTB \(ctb)") }
            var tag: UInt8
            var length: Int
            i = data.index(after: i)
            if ctb & 0x40 != 0 {
                // New-format header.
                tag = ctb & 0x3F
                (length, i) = try readNewLength(data, i)
            } else {
                // Old-format header.
                tag = (ctb >> 2) & 0x0F
                let lenType = ctb & 0x03
                (length, i) = try readOldLength(data, i, lenType: lenType)
            }
            guard data.distance(from: i, to: data.endIndex) >= length else { throw OpenPGPError.truncated }
            let body = data.subdata(in: i..<data.index(i, offsetBy: length))
            i = data.index(i, offsetBy: length)
            packets.append(try decode(tag: tag, body: body))
        }
        return packets
    }

    private static func readOldLength(_ data: Data, _ i: Data.Index, lenType: UInt8) throws -> (Int, Data.Index) {
        var idx = i
        func byte() throws -> Int {
            guard idx < data.endIndex else { throw OpenPGPError.truncated }
            let v = Int(data[idx]); idx = data.index(after: idx); return v
        }
        switch lenType {
        case 0: return (try byte(), idx)
        case 1: let a = try byte(); let b = try byte(); return ((a << 8) | b, idx)
        case 2:
            let a = try byte(), b = try byte(), c = try byte(), d = try byte()
            return ((a << 24) | (b << 16) | (c << 8) | d, idx)
        default: throw OpenPGPError.malformedPacket("indeterminate length unsupported")
        }
    }

    private static func readNewLength(_ data: Data, _ i: Data.Index) throws -> (Int, Data.Index) {
        var idx = i
        func byte() throws -> Int {
            guard idx < data.endIndex else { throw OpenPGPError.truncated }
            let v = Int(data[idx]); idx = data.index(after: idx); return v
        }
        let first = try byte()
        if first < 192 { return (first, idx) }
        if first < 224 { let b = try byte(); return (((first - 192) << 8) + b + 192, idx) }
        if first == 255 {
            let a = try byte(), b = try byte(), c = try byte(), d = try byte()
            return ((a << 24) | (b << 16) | (c << 8) | d, idx)
        }
        throw OpenPGPError.malformedPacket("partial body lengths unsupported")
    }

    private static func decode(tag: UInt8, body: Data) throws -> PGPPacket {
        switch tag {
        case 6, 14:
            return .publicKey(try parsePublicKey(body), subkey: tag == 14)
        case 13:
            return .userID(String(decoding: body, as: UTF8.self))
        case 2:
            return .signature(try parseSignature(body))
        default:
            return .unknown(tag: tag, body: body)
        }
    }

    private static func parsePublicKey(_ body: Data) throws -> PGPPublicKeyPacket {
        var i = 0
        func u8() throws -> UInt8 {
            guard i < body.count else { throw OpenPGPError.truncated }
            let v = body[body.startIndex + i]; i += 1; return v
        }
        guard try u8() == 4 else { throw OpenPGPError.malformedPacket("expected v4 key") }
        let ct = (UInt32(try u8()) << 24) | (UInt32(try u8()) << 16) | (UInt32(try u8()) << 8) | UInt32(try u8())
        let algoByte = try u8()
        guard let algo = PGPPublicKeyAlgorithm(rawValue: algoByte) else {
            throw OpenPGPError.unsupportedAlgorithm(algoByte)
        }
        let oidLen = Int(try u8())
        guard i + oidLen <= body.count else { throw OpenPGPError.truncated }
        i += oidLen // curve OID (nistp256 assumed; validated by round-trip tests)
        let (pointVal, next) = try MPI.decode(body, at: i)
        i = next
        guard pointVal.first == 0x04, pointVal.count == 65 else {
            throw OpenPGPError.malformedPacket("expected uncompressed P-256 point")
        }
        let x = pointVal.subdata(in: (pointVal.startIndex + 1)..<(pointVal.startIndex + 33))
        let y = pointVal.subdata(in: (pointVal.startIndex + 33)..<(pointVal.startIndex + 65))
        return PGPPublicKeyPacket(creationTime: ct, algorithm: algo, point: ECPoint(x: x, y: y))
    }

    private static func parseSignature(_ body: Data) throws -> ParsedSignature {
        var i = body.startIndex
        func u8() throws -> UInt8 {
            guard i < body.endIndex else { throw OpenPGPError.truncated }
            let v = body[i]; i = body.index(after: i); return v
        }
        func u16() throws -> Int { (Int(try u8()) << 8) | Int(try u8()) }
        guard try u8() == 4 else { throw OpenPGPError.malformedPacket("expected v4 signature") }
        let type = try u8()
        let pk = try u8()
        let hash = try u8()
        let hashedLen = try u16()
        guard body.distance(from: i, to: body.endIndex) >= hashedLen else { throw OpenPGPError.truncated }
        let hashed = body.subdata(in: i..<body.index(i, offsetBy: hashedLen))
        i = body.index(i, offsetBy: hashedLen)
        let unhashedLen = try u16()
        guard body.distance(from: i, to: body.endIndex) >= unhashedLen else { throw OpenPGPError.truncated }
        let unhashed = body.subdata(in: i..<body.index(i, offsetBy: unhashedLen))
        i = body.index(i, offsetBy: unhashedLen)
        let quick = body.subdata(in: i..<body.index(i, offsetBy: 2))
        i = body.index(i, offsetBy: 2)
        var mpis: [Data] = []
        var off = body.distance(from: body.startIndex, to: i)
        while off < body.count {
            let (v, next) = try MPI.decode(body, at: off)
            mpis.append(v)
            off = next
        }
        return ParsedSignature(type: type, publicKeyAlgorithm: pk, hashAlgorithm: hash,
                               hashedSubpacketBytes: hashed, unhashedSubpacketBytes: unhashed,
                               quickCheck: quick, mpis: mpis)
    }
}
