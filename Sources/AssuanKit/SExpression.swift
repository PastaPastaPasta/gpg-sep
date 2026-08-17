import Foundation

/// A canonical S-expression as gpg-agent / libgcrypt exchange them inside `D`
/// lines. Canonical form only: `(<len>:<bytes><len>:<bytes>…)` with no
/// whitespace and no display hints. Atoms hold arbitrary bytes.
public indirect enum SExpression: Equatable, Sendable {
    case atom(Data)
    case list([SExpression])

    public struct ParseError: Error, Equatable, CustomStringConvertible {
        public let message: String
        public init(_ message: String) { self.message = message }
        public var description: String { "invalid canonical S-expression: \(message)" }
    }

    /// Nesting limit for ``parse(_:)``. Real gcrypt structures nest three or
    /// four deep; the cap keeps a hostile peer from exhausting the stack.
    public static let maxParseDepth = 64

    // MARK: Convenience constructors

    public static func atom(_ string: String) -> SExpression { .atom(Data(string.utf8)) }

    /// The atom's bytes, if this is an atom.
    public var atomData: Data? {
        if case .atom(let d) = self { return d }
        return nil
    }

    /// The atom's bytes decoded as UTF-8, if this is an atom.
    public var atomString: String? {
        atomData.map { String(decoding: $0, as: UTF8.self) }
    }

    /// The child expressions, if this is a list.
    public var items: [SExpression]? {
        if case .list(let l) = self { return l }
        return nil
    }

    // MARK: Serialize

    /// Byte-exact canonical serialization: `(len:bytes…)`.
    public func serialize() -> Data {
        var out = Data()
        serialize(into: &out)
        return out
    }

    private func serialize(into out: inout Data) {
        switch self {
        case .atom(let d):
            out.append(Data(String(d.count).utf8))
            out.append(0x3A) // ':'
            out.append(d)
        case .list(let items):
            out.append(0x28) // '('
            for item in items { item.serialize(into: &out) }
            out.append(0x29) // ')'
        }
    }

    // MARK: Parse

    /// Parse one canonical S-expression from the front of `data`. Extra trailing
    /// bytes are rejected so callers can trust the whole buffer was consumed.
    public static func parse(_ data: Data) throws -> SExpression {
        let bytes = [UInt8](data)
        var i = 0
        let expr = try parse(bytes, &i, depth: 0)
        // Tolerate a single trailing NUL, which some emitters append.
        if i < bytes.count, bytes[i] == 0x00 { i += 1 }
        guard i == bytes.count else {
            throw ParseError("trailing bytes after S-expression at offset \(i)")
        }
        return expr
    }

    private static func parse(_ bytes: [UInt8], _ i: inout Int, depth: Int) throws -> SExpression {
        guard depth <= maxParseDepth else {
            throw ParseError("nesting deeper than \(maxParseDepth)")
        }
        guard i < bytes.count else { throw ParseError("unexpected end of input") }
        if bytes[i] == 0x28 { // '('
            i += 1
            var items: [SExpression] = []
            while true {
                guard i < bytes.count else { throw ParseError("unterminated list") }
                if bytes[i] == 0x29 { // ')'
                    i += 1
                    return .list(items)
                }
                items.append(try parse(bytes, &i, depth: depth + 1))
            }
        } else if bytes[i] >= 0x30 && bytes[i] <= 0x39 { // digit => atom
            var len = 0
            let lenStart = i
            while i < bytes.count, bytes[i] >= 0x30, bytes[i] <= 0x39 {
                // Guard against overflow from an absurd length prefix.
                let digit = Int(bytes[i] - 0x30)
                if len > (Int.max - digit) / 10 { throw ParseError("atom length overflow") }
                len = len * 10 + digit
                i += 1
            }
            guard i > lenStart else { throw ParseError("empty atom length") }
            // Canonical form has exactly one spelling per length, so anything
            // but a bare "0" may not start with a zero digit.
            guard i - lenStart == 1 || bytes[lenStart] != 0x30 else {
                throw ParseError("atom length has a leading zero")
            }
            guard i < bytes.count, bytes[i] == 0x3A else { // ':'
                throw ParseError("expected ':' after atom length")
            }
            i += 1
            guard len <= bytes.count - i else { throw ParseError("atom length exceeds input") }
            let atom = Data(bytes[i..<(i + len)])
            i += len
            return .atom(atom)
        } else if bytes[i] == 0x5B { // '['
            throw ParseError("display hints are not part of libgcrypt canonical output")
        } else {
            throw ParseError("unexpected byte 0x\(String(bytes[i], radix: 16)) at offset \(i)")
        }
    }

    // MARK: Lookup

    /// Within a list, return the first child list whose head atom equals `name`.
    /// e.g. in `(sig-val(ecdsa(r …)(s …)))`, `find("ecdsa")` on the `sig-val`
    /// list returns the `(ecdsa …)` sublist.
    public func find(_ name: String) -> SExpression? {
        guard case .list(let items) = self else { return nil }
        let needle = Data(name.utf8)
        for item in items {
            if case .list(let sub) = item, let head = sub.first, head.atomData == needle {
                return item
            }
        }
        return nil
    }

    /// For a named single-value pair `(name value)`, return `value`'s atom bytes.
    public func value(_ name: String) -> Data? {
        guard let node = find(name), case .list(let sub) = node, sub.count >= 2 else { return nil }
        return sub[1].atomData
    }
}

// MARK: - gcrypt MPI and typed key/signature builders

public extension SExpression {
    /// Encode raw big-endian bytes as a libgcrypt "STD" MPI: strip leading zero
    /// bytes to the minimal length, then prepend a single `0x00` if the top bit
    /// of the leading byte is set (so the value stays positive/unsigned). This
    /// is the exact rule gpg-agent applies to signature and key MPIs; getting it
    /// wrong yields a signature gpg rejects.
    static func gcryptMPI(_ raw: Data) -> Data {
        var bytes = [UInt8](raw)
        // Minimal form: drop leading zeros but keep at least one byte.
        while bytes.count > 1, bytes.first == 0x00 { bytes.removeFirst() }
        if bytes.isEmpty { bytes = [0x00] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) } // sign-preserving pad
        return Data(bytes)
    }

    /// `(sig-val(ecdsa(r <mpi>)(s <mpi>)))` from raw big-endian r and s.
    static func ecdsaSigVal(r: Data, s: Data) -> SExpression {
        .list([
            .atom("sig-val"),
            .list([
                .atom("ecdsa"),
                .list([.atom("r"), .atom(gcryptMPI(r))]),
                .list([.atom("s"), .atom(gcryptMPI(s))]),
            ]),
        ])
    }

    /// `(public-key(ecc(curve <curve>)(q <point>)))` where `q` is the
    /// uncompressed point `0x04||X||Y` (encoded through the MPI rule, which is a
    /// no-op for a 0x04-prefixed point since 0x04 has its high bit clear).
    static func eccPublicKey(curve: String, q: Data) -> SExpression {
        .list([
            .atom("public-key"),
            .list([
                .atom("ecc"),
                .list([.atom("curve"), .atom(curve)]),
                .list([.atom("q"), .atom(gcryptMPI(q))]),
            ]),
        ])
    }

    /// Extract `(r, s)` from a `(sig-val(ecdsa(r …)(s …)))` tree, if present.
    /// Returns the raw MPI bytes as they appear (sign byte included).
    func ecdsaSignatureRS() -> (r: Data, s: Data)? {
        // Accept either the outer sig-val wrapper or the inner algo list.
        let algo = find("ecdsa") ?? (find("sig-val")?.find("ecdsa"))
        guard let algo, let r = algo.value("r"), let s = algo.value("s") else { return nil }
        return (r, s)
    }
}

// MARK: - Debug rendering

extension SExpression: CustomStringConvertible {
    /// Roughly libgcrypt's `GCRYSEXP_FMT_ADVANCED`: printable ASCII atoms show
    /// as themselves, everything else as a `#hex#` token.
    public var description: String {
        switch self {
        case .atom(let data):
            let printable = !data.isEmpty && data.allSatisfy { $0 >= 0x21 && $0 <= 0x7E && $0 != 0x23 }
            if printable { return String(decoding: data, as: UTF8.self) }
            return "#" + data.map { String(format: "%02X", $0) }.joined() + "#"
        case .list(let items):
            return "(" + items.map(\.description).joined(separator: " ") + ")"
        }
    }
}
