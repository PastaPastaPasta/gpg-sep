import Foundation

/// ASCII-armor encoding (RFC 9580 §6) with CRC-24 checksum.
public enum Armor {
    public enum BlockType {
        case publicKey
        case signature

        var header: String {
            switch self {
            case .publicKey: return "-----BEGIN PGP PUBLIC KEY BLOCK-----"
            case .signature: return "-----BEGIN PGP SIGNATURE-----"
            }
        }
        var footer: String {
            switch self {
            case .publicKey: return "-----END PGP PUBLIC KEY BLOCK-----"
            case .signature: return "-----END PGP SIGNATURE-----"
            }
        }
    }

    /// CRC-24 as specified by RFC 9580 §6.1 (init 0xB704CE, poly 0x1864CFB).
    public static func crc24(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xB704CE
        for byte in data {
            crc ^= UInt32(byte) << 16
            for _ in 0..<8 {
                crc <<= 1
                if crc & 0x1000000 != 0 { crc ^= 0x1864CFB }
            }
        }
        return crc & 0xFFFFFF
    }

    /// Armor `data` into the textual block form (LF line endings, 64 base64
    /// chars per line, `=`-prefixed CRC line).
    public static func armor(_ data: Data, type: BlockType) -> String {
        let b64 = data.base64EncodedString()
        var lines: [String] = []
        var idx = b64.startIndex
        while idx < b64.endIndex {
            let end = b64.index(idx, offsetBy: 64, limitedBy: b64.endIndex) ?? b64.endIndex
            lines.append(String(b64[idx..<end]))
            idx = end
        }
        let crc = crc24(data)
        let crcBytes = Data([UInt8((crc >> 16) & 0xFF), UInt8((crc >> 8) & 0xFF), UInt8(crc & 0xFF)])
        let crcLine = "=" + crcBytes.base64EncodedString()

        var out = type.header + "\n\n"
        out += lines.joined(separator: "\n")
        if !lines.isEmpty { out += "\n" }
        out += crcLine + "\n"
        out += type.footer + "\n"
        return out
    }

    /// Parse an armored block back to its binary payload, validating the CRC.
    public static func dearmor(_ text: String) throws -> Data {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard let beginIdx = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN PGP") }),
              let endIdx = lines.firstIndex(where: { $0.hasPrefix("-----END PGP") }),
              beginIdx < endIdx else {
            throw OpenPGPError.invalidArmor("missing framing")
        }
        var payloadLines: [String] = []
        var crcLine: String? = nil
        var seenBlank = false
        for line in lines[(beginIdx + 1)..<endIdx] {
            if !seenBlank {
                // Skip armor headers and the mandatory blank separator line.
                if line.isEmpty { seenBlank = true; continue }
                if line.contains(":") { continue }
                seenBlank = true
            }
            if line.hasPrefix("=") { crcLine = line; continue }
            if line.isEmpty { continue }
            payloadLines.append(line)
        }
        guard let payload = Data(base64Encoded: payloadLines.joined()) else {
            throw OpenPGPError.invalidArmor("bad base64")
        }
        if let crcLine, let crcData = Data(base64Encoded: String(crcLine.dropFirst())), crcData.count == 3 {
            let expected = (UInt32(crcData[crcData.startIndex]) << 16)
                | (UInt32(crcData[crcData.startIndex + 1]) << 8)
                | UInt32(crcData[crcData.startIndex + 2])
            guard crc24(payload) == expected else { throw OpenPGPError.invalidArmor("CRC mismatch") }
        }
        return payload
    }
}
