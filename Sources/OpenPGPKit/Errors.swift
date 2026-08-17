import Foundation

/// Errors raised while serializing or parsing OpenPGP material.
public enum OpenPGPError: Error, Equatable {
    /// An EC coordinate was not exactly 32 bytes (P-256 field size).
    case invalidCoordinateLength(expected: Int, got: Int)
    /// A signature integer (r or s) was empty or longer than 32 bytes.
    case invalidSignatureInteger
    /// Packet or MPI data ended before the declared length.
    case truncated
    /// A packet body was malformed (bad tag, version, or field layout).
    case malformedPacket(String)
    /// Unsupported public-key algorithm for this minimal implementation.
    case unsupportedAlgorithm(UInt8)
    /// A DER-encoded ECDSA signature could not be parsed.
    case invalidDER(String)
    /// ASCII-armor framing or CRC did not validate.
    case invalidArmor(String)
}
