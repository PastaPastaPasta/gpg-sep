import Foundation

/// Convert a DER-encoded ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }`
/// (as produced by CryptoKit / Security.framework / the Secure Enclave) into
/// raw big-endian `(r, s)` integers.
///
/// The returned integers are minimal (DER INTEGERs, so any single leading zero
/// sign byte is stripped). Callers that need fixed-width 32-byte forms should
/// left-pad; OpenPGP MPI encoding re-derives the exact bit length regardless.
public func ecdsaDERToRawRS(_ der: Data) throws -> (r: Data, s: Data) {
    let bytes = [UInt8](der)
    var i = 0
    func need(_ n: Int) throws {
        guard i + n <= bytes.count else { throw OpenPGPError.invalidDER("unexpected end") }
    }
    try need(1)
    guard bytes[i] == 0x30 else { throw OpenPGPError.invalidDER("expected SEQUENCE") }
    i += 1
    // Sequence length (short or long form).
    try need(1)
    var seqLen = Int(bytes[i]); i += 1
    if seqLen & 0x80 != 0 {
        let n = seqLen & 0x7F
        guard n >= 1 && n <= 2 else { throw OpenPGPError.invalidDER("bad length form") }
        try need(n)
        seqLen = 0
        for _ in 0..<n { seqLen = (seqLen << 8) | Int(bytes[i]); i += 1 }
    }
    guard i + seqLen == bytes.count else { throw OpenPGPError.invalidDER("length mismatch") }

    func readInt() throws -> Data {
        try need(1)
        guard bytes[i] == 0x02 else { throw OpenPGPError.invalidDER("expected INTEGER") }
        i += 1
        try need(1)
        let len = Int(bytes[i]); i += 1
        guard len > 0 else { throw OpenPGPError.invalidDER("empty INTEGER") }
        try need(len)
        var v = Array(bytes[i..<(i+len)])
        i += len
        // Strip a single leading 0x00 that only carries the DER sign bit.
        if v.count > 1 && v[0] == 0x00 { v.removeFirst() }
        return Data(v)
    }

    let r = try readInt()
    let s = try readInt()
    return (r, s)
}

/// Left-pad (or minimally validate) a big-endian integer to `width` bytes.
/// Throws if the value is longer than `width`.
public func leftPad(_ value: Data, to width: Int) throws -> Data {
    guard value.count <= width else { throw OpenPGPError.invalidSignatureInteger }
    if value.count == width { return value }
    return Data(repeating: 0, count: width - value.count) + value
}
