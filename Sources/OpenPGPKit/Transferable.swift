import Foundation

/// Assembles a complete "transferable public key" (RFC 9580 §10.1): the primary
/// key packet, its user IDs and self-certifications, then each subkey with its
/// binding signature.
public struct PGPTransferablePublicKey {
    public let primary: PGPPublicKeyPacket

    /// A user ID together with the certification signature packet over it.
    public struct CertifiedUserID {
        public let userID: PGPUserIDPacket
        public let certification: Data // full signature packet (tag 2)
        public init(userID: PGPUserIDPacket, certification: Data) {
            self.userID = userID
            self.certification = certification
        }
    }

    /// A subkey together with its binding signature packet.
    public struct BoundSubkey {
        public let subkey: PGPPublicKeyPacket
        public let binding: Data // full signature packet (tag 2)
        public init(subkey: PGPPublicKeyPacket, binding: Data) {
            self.subkey = subkey
            self.binding = binding
        }
    }

    public var userIDs: [CertifiedUserID]
    public var subkeys: [BoundSubkey]

    public init(primary: PGPPublicKeyPacket,
                userIDs: [CertifiedUserID] = [],
                subkeys: [BoundSubkey] = []) {
        self.primary = primary
        self.userIDs = userIDs
        self.subkeys = subkeys
    }

    /// Raw binary packet stream in canonical transferable order.
    public func serialized() -> Data {
        var d = primary.packetData(subkey: false)
        for u in userIDs {
            d.append(u.userID.packetData())
            d.append(u.certification)
        }
        for s in subkeys {
            d.append(s.subkey.packetData(subkey: true))
            d.append(s.binding)
        }
        return d
    }

    /// ASCII-armored public key block.
    public func armored() -> String {
        Armor.armor(serialized(), type: .publicKey)
    }
}

/// Armor a standalone signature packet as a `PGP SIGNATURE` block (e.g. a
/// detached document signature or a revocation certificate).
public func armoredSignature(_ signaturePacket: Data) -> String {
    Armor.armor(signaturePacket, type: .signature)
}
