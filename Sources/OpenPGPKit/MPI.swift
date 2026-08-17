import Foundation

/// OpenPGP multiprecision integer (MPI) coding (RFC 9580 §3.2).
///
/// Wire form: a 2-octet big-endian *bit* count, followed by the minimal
/// big-endian byte representation of the value (no leading zero bytes).
public enum MPI {
    /// Encode a big-endian, unsigned integer as an MPI.
    /// Leading zero bytes are stripped; the bit length is measured from the
    /// most-significant set bit of the first non-zero byte.
    public static func encode(_ value: Data) -> Data {
        // Strip leading zero bytes to reach the minimal representation.
        var bytes = [UInt8](value)
        var i = 0
        while i < bytes.count && bytes[i] == 0 { i += 1 }
        bytes.removeFirst(i)

        if bytes.isEmpty {
            // Value zero: zero bits, no body.
            return Data([0x00, 0x00])
        }

        // Bit length = total bits minus the leading zero bits of the top byte
        // (UInt8.leadingZeroBitCount is already measured within 8 bits).
        let bitLength = bytes.count * 8 - bytes[0].leadingZeroBitCount

        var out = Data()
        out.append(UInt8((bitLength >> 8) & 0xFF))
        out.append(UInt8(bitLength & 0xFF))
        out.append(contentsOf: bytes)
        return out
    }

    /// Decode one MPI from `data` starting at `offset`.
    /// Returns the value bytes (minimal, no leading zeros) and the offset just
    /// past the MPI.
    public static func decode(_ data: Data, at offset: Int) throws -> (value: Data, next: Int) {
        guard offset + 2 <= data.count else { throw OpenPGPError.truncated }
        let bitLength = (Int(data[data.startIndex + offset]) << 8) | Int(data[data.startIndex + offset + 1])
        let byteLength = (bitLength + 7) / 8
        let start = offset + 2
        guard start + byteLength <= data.count else { throw OpenPGPError.truncated }
        let value = data.subdata(in: (data.startIndex + start)..<(data.startIndex + start + byteLength))
        return (value, start + byteLength)
    }
}
