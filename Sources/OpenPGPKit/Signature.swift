import Foundation
import CryptoKit

/// Hash-algorithm identifiers (RFC 9580 §9.5). Only the SHA-2 sizes the Secure
/// Enclave can service over a precomputed digest are modeled.
public enum PGPHashAlgorithm: UInt8 {
    case sha256 = 8
    case sha384 = 9
    case sha512 = 10

    /// Digest length in bytes.
    public var digestLength: Int {
        switch self {
        case .sha256: return 32
        case .sha384: return 48
        case .sha512: return 64
        }
    }

    func digest(_ data: Data) -> Data {
        switch self {
        case .sha256: return Data(SHA256.hash(data: data))
        case .sha384: return Data(SHA384.hash(data: data))
        case .sha512: return Data(SHA512.hash(data: data))
        }
    }
}

/// v4 signature type octets (RFC 9580 §5.2.1).
public enum PGPSignatureType: UInt8 {
    case binaryDocument = 0x00
    case textDocument = 0x01
    case positiveCertification = 0x13
    case subkeyBinding = 0x18
    case primaryKeyBinding = 0x19
    case keyRevocation = 0x20
    case subkeyRevocation = 0x28
}

/// Key-usage flags for subpacket type 27 (RFC 9580 §5.2.3.29).
public struct KeyFlags: OptionSet {
    public let rawValue: UInt8
    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let certify = KeyFlags(rawValue: 0x01)
    public static let sign = KeyFlags(rawValue: 0x02)
    public static let encryptCommunications = KeyFlags(rawValue: 0x04)
    public static let encryptStorage = KeyFlags(rawValue: 0x08)
    public static let authenticate = KeyFlags(rawValue: 0x20)
}

/// A single signature subpacket. `type` is the subpacket type octet; `body` is
/// everything after the type octet.
public struct PGPSubpacket {
    public let type: UInt8
    public let body: Data

    public init(type: UInt8, body: Data) {
        self.type = type
        self.body = body
    }

    /// Encoded form: length header (covering type + body) then type then body.
    public func encoded() -> Data {
        let length = body.count + 1 // include the type octet
        var out = Data()
        // Subpacket length uses the RFC 9580 §5.2.3.1 scheme.
        if length < 192 {
            out.append(UInt8(length))
        } else if length < 8384 {
            let v = length - 192
            out.append(UInt8((v >> 8) + 192))
            out.append(UInt8(v & 0xFF))
        } else {
            out.append(0xFF)
            out.append(UInt8((length >> 24) & 0xFF))
            out.append(UInt8((length >> 16) & 0xFF))
            out.append(UInt8((length >> 8) & 0xFF))
            out.append(UInt8(length & 0xFF))
        }
        out.append(type)
        out.append(body)
        return out
    }

    // MARK: Convenience constructors

    public static func signatureCreationTime(_ t: UInt32) -> PGPSubpacket {
        PGPSubpacket(type: 2, body: be32(t))
    }
    public static func keyExpirationTime(_ seconds: UInt32) -> PGPSubpacket {
        PGPSubpacket(type: 9, body: be32(seconds))
    }
    public static func preferredHashAlgorithms(_ algos: [PGPHashAlgorithm]) -> PGPSubpacket {
        PGPSubpacket(type: 21, body: Data(algos.map { $0.rawValue }))
    }
    public static func keyFlags(_ flags: KeyFlags) -> PGPSubpacket {
        PGPSubpacket(type: 27, body: Data([flags.rawValue]))
    }
    public static func issuerKeyID(_ keyID: Data) -> PGPSubpacket {
        PGPSubpacket(type: 16, body: keyID)
    }
    /// Issuer fingerprint (type 33): key-version octet (4) then the 20-byte fpr.
    public static func issuerFingerprint(_ fingerprint: Data) -> PGPSubpacket {
        PGPSubpacket(type: 33, body: Data([0x04]) + fingerprint)
    }
    /// Embedded signature (type 32) carrying a back-signature packet body.
    public static func embeddedSignature(_ signaturePacketBody: Data) -> PGPSubpacket {
        PGPSubpacket(type: 32, body: signaturePacketBody)
    }
    /// Reason for revocation (type 29): reason code then UTF-8 comment.
    public static func reasonForRevocation(code: UInt8, reason: String) -> PGPSubpacket {
        PGPSubpacket(type: 29, body: Data([code]) + Data(reason.utf8))
    }

    private static func be32(_ v: UInt32) -> Data {
        Data([UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)])
    }
}

/// What a signature covers. Determines the key/UID material hashed before the
/// signature's own fields (RFC 9580 §5.2.4).
public enum PGPSignatureTarget {
    /// Certification of a UID by the primary key (0x10–0x13).
    case certification(primary: PGPPublicKeyPacket, userID: PGPUserIDPacket)
    /// Subkey binding (0x18/0x19) or subkey revocation (0x28): primary + subkey.
    case subkey(primary: PGPPublicKeyPacket, subkey: PGPPublicKeyPacket)
    /// Direct-key signature or primary-key revocation (0x20): primary only.
    case primaryKey(primary: PGPPublicKeyPacket)
    /// Document signature (0x00/0x01): the literal data being signed.
    case document(Data)
    /// Precomputed target material — the exact bytes hashed before the
    /// signature's own fields. Escape hatch for binding a subkey under a primary
    /// this module does not model (e.g. an RSA YubiKey primary): the caller
    /// supplies `<primary fingerprint preimage> || subkey.fingerprintPreimage`.
    case raw(Data)

    /// The bytes hashed before the signature's own trailer.
    var preimage: Data {
        switch self {
        case let .certification(primary, uid):
            return primary.fingerprintPreimage + uid.certificationPreimage
        case let .subkey(primary, subkey):
            return primary.fingerprintPreimage + subkey.fingerprintPreimage
        case let .primaryKey(primary):
            return primary.fingerprintPreimage
        case let .document(data):
            return data
        case let .raw(data):
            return data
        }
    }
}

/// Builds a v4 signature packet. The private-key operation is inverted: this
/// type produces the digest to sign, and the caller supplies raw `(r, s)` from
/// an external signer (the Secure Enclave), keeping private keys out of process.
public final class PGPSignatureBuilder {
    public let type: PGPSignatureType
    public let hashAlgorithm: PGPHashAlgorithm
    public let publicKeyAlgorithm: PGPPublicKeyAlgorithm
    /// Raw algorithm octet of the *issuing* key as it appears in the signature's
    /// hashed prefix (RFC 9580 §5.2.3): 19 for ECDSA, 18 for ECDH, 1 for RSA.
    /// This is the authoritative value used when hashing and finalizing, and it
    /// must match the key that actually produces the signature. For the
    /// ECDSA/ECDH initializer it equals `publicKeyAlgorithm.rawValue`.
    public let signingAlgorithmByte: UInt8
    public private(set) var hashedSubpackets: [PGPSubpacket] = []
    public private(set) var unhashedSubpackets: [PGPSubpacket] = []

    /// - Parameters:
    ///   - type: signature class octet.
    ///   - hashAlgorithm: digest algorithm for both the OpenPGP hash and the
    ///     external ECDSA operation.
    ///   - signingKeyAlgorithm: algorithm of the *issuing* key (19 for ECDSA).
    public init(type: PGPSignatureType,
                hashAlgorithm: PGPHashAlgorithm = .sha256,
                signingKeyAlgorithm: PGPPublicKeyAlgorithm = .ecdsa) {
        self.type = type
        self.hashAlgorithm = hashAlgorithm
        self.publicKeyAlgorithm = signingKeyAlgorithm
        self.signingAlgorithmByte = signingKeyAlgorithm.rawValue
    }

    /// Initializer for issuing keys whose algorithm has no dedicated
    /// `PGPPublicKeyAlgorithm` case in this minimal module — notably RSA (1) for
    /// a YubiKey primary binding a Secure-Enclave subkey. `publicKeyAlgorithm` is
    /// reported as `.ecdsa` and is NOT consulted on this path; only
    /// `signingAlgorithmByte` is authoritative. Finalize with
    /// ``finalizePacket(over:mpis:)`` (RSA → a single `s` MPI).
    public init(type: PGPSignatureType,
                hashAlgorithm: PGPHashAlgorithm,
                signingAlgorithmByte: UInt8) {
        self.type = type
        self.hashAlgorithm = hashAlgorithm
        self.publicKeyAlgorithm = .ecdsa
        self.signingAlgorithmByte = signingAlgorithmByte
    }

    @discardableResult
    public func addHashed(_ sp: PGPSubpacket) -> PGPSignatureBuilder {
        hashedSubpackets.append(sp); return self
    }
    @discardableResult
    public func addUnhashed(_ sp: PGPSubpacket) -> PGPSignatureBuilder {
        unhashedSubpackets.append(sp); return self
    }

    /// The fixed prefix of the signature body that is itself hashed: version,
    /// type, pk-algo, hash-algo, then the hashed-subpacket area.
    private func hashedSignatureData() -> Data {
        var d = Data([0x04, type.rawValue, signingAlgorithmByte, hashAlgorithm.rawValue])
        var sub = Data()
        for sp in hashedSubpackets { sub.append(sp.encoded()) }
        d.append(UInt8((sub.count >> 8) & 0xFF))
        d.append(UInt8(sub.count & 0xFF))
        d.append(sub)
        return d
    }

    /// The full to-be-hashed byte string: target material, the hashed signature
    /// data, then the v4 trailer (0x04, 0xFF, 4-octet length of the hashed
    /// signature data).
    public func toBeHashed(over target: PGPSignatureTarget) -> Data {
        let sigData = hashedSignatureData()
        var d = target.preimage
        d.append(sigData)
        d.append(contentsOf: [0x04, 0xFF,
                              UInt8((sigData.count >> 24) & 0xFF),
                              UInt8((sigData.count >> 16) & 0xFF),
                              UInt8((sigData.count >> 8) & 0xFF),
                              UInt8(sigData.count & 0xFF)])
        return d
    }

    /// The digest an external signer must sign for this signature.
    public func digest(over target: PGPSignatureTarget) -> Data {
        hashAlgorithm.digest(toBeHashed(over: target))
    }

    /// Assemble the signature packet body from raw `(r, s)` values. `r`/`s` are
    /// big-endian; they are re-encoded as OpenPGP MPIs. The 2-octet quick-check
    /// field is the leading two octets of the digest.
    public func finalizeBody(over target: PGPSignatureTarget, r: Data, s: Data) throws -> Data {
        guard !r.isEmpty, r.count <= 32, !s.isEmpty, s.count <= 32 else {
            throw OpenPGPError.invalidSignatureInteger
        }
        // ECDSA signature: two MPIs, r then s.
        return try finalizeBody(over: target, mpis: [r, s])
    }

    /// Assemble the full signature packet (tag 2, old-format header).
    public func finalizePacket(over target: PGPSignatureTarget, r: Data, s: Data) throws -> Data {
        let body = try finalizeBody(over: target, r: r, s: s)
        var d = PacketHeader.oldFormat(tag: 2, bodyLength: body.count)
        d.append(body)
        return d
    }

    /// Assemble the signature packet body from an arbitrary list of big-endian
    /// integers, each re-encoded as an OpenPGP MPI in order. ECDSA passes
    /// `[r, s]`; RSA passes `[s]`. The 2-octet quick-check field is the leading
    /// two octets of the digest.
    public func finalizeBody(over target: PGPSignatureTarget, mpis: [Data]) throws -> Data {
        guard !mpis.isEmpty, mpis.allSatisfy({ !$0.isEmpty }) else {
            throw OpenPGPError.invalidSignatureInteger
        }
        let sigData = hashedSignatureData()
        let digest = hashAlgorithm.digest(toBeHashed(over: target))

        var body = sigData
        var unhashed = Data()
        for sp in unhashedSubpackets { unhashed.append(sp.encoded()) }
        body.append(UInt8((unhashed.count >> 8) & 0xFF))
        body.append(UInt8(unhashed.count & 0xFF))
        body.append(unhashed)
        // Left 16 bits of the digest.
        body.append(digest.prefix(2))
        for value in mpis { body.append(MPI.encode(value)) }
        return body
    }

    /// Assemble the full signature packet (tag 2) from arbitrary MPIs.
    public func finalizePacket(over target: PGPSignatureTarget, mpis: [Data]) throws -> Data {
        let body = try finalizeBody(over: target, mpis: mpis)
        var d = PacketHeader.oldFormat(tag: 2, bodyLength: body.count)
        d.append(body)
        return d
    }

    /// Convenience: compute the digest, invoke the external signer, and return
    /// the full signature packet.
    public func build(
        over target: PGPSignatureTarget,
        sign: (_ digest: Data, _ hashAlgo: PGPHashAlgorithm) throws -> (r: Data, s: Data)
    ) throws -> Data {
        let d = digest(over: target)
        let (r, s) = try sign(d, hashAlgorithm)
        return try finalizePacket(over: target, r: r, s: s)
    }

    /// Convenience returning only the signature packet *body* (for embedding as
    /// a subpacket-32 back-signature).
    public func buildBody(
        over target: PGPSignatureTarget,
        sign: (_ digest: Data, _ hashAlgo: PGPHashAlgorithm) throws -> (r: Data, s: Data)
    ) throws -> Data {
        let d = digest(over: target)
        let (r, s) = try sign(d, hashAlgorithm)
        return try finalizeBody(over: target, r: r, s: s)
    }
}
