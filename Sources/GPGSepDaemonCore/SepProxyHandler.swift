import Foundation
import LocalAuthentication
import AssuanKit
import OpenPGPKit
import SEPKit

/// One per accepted client connection. Decides, per command, whether to answer
/// locally (the keygrip belongs to a gpg-sep store key) or forward verbatim to
/// the backend gpg-agent. Implements the routing table in PROTOCOL.md.
///
/// The handler shares one backend ``AssuanConnection`` with the ``AssuanServer``
/// driving it: the server relays `.forward` commands, and this handler issues
/// its own `transact`s (for HAVEKEY/KEYINFO merges) over the same connection.
/// Both run on the single per-connection thread, never concurrently.
public final class SepProxyHandler: AssuanCommandHandler {
    private let keyStore: KeyStore
    private let authSession: AuthSession
    private let backend: AssuanClient

    /// Uppercase-hex keygrip currently selected, iff it is a store key. `nil`
    /// means the last selection (if any) routed to the backend.
    private var selectedLocalGrip: String?
    private var storedDigest: Data?
    private var storedHash: PGPHashAlgorithm?

    /// Cache of store keygrips (uppercase), refreshed lazily.
    public init(keyStore: KeyStore, authSession: AuthSession, backend: AssuanClient) {
        self.keyStore = keyStore
        self.authSession = authSession
        self.backend = backend
    }

    public func handle(verb: String, rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        switch verb {
        case "RESET":
            selectedLocalGrip = nil
            storedDigest = nil
            storedHash = nil
            return .forward
        case "SIGKEY", "SETKEY":
            return try handleSelectKey(rest, io: io)
        case "SETKEYDESC":
            // In local mode there is no backend pinentry to describe; ack it.
            if selectedLocalGrip != nil { try io.sendOK(); return .handled }
            return .forward
        case "SETHASH":
            return try handleSetHash(rest, io: io)
        case "PKSIGN":
            return try handlePkSign(io: io)
        case "PKDECRYPT":
            return try handlePkDecrypt(io: io)
        case "HAVEKEY":
            return try handleHaveKey(rest, io: io)
        case "KEYINFO":
            return try handleKeyInfo(rest, io: io)
        case "READKEY":
            return try handleReadKey(rest, io: io)
        case "EXPORT_KEY":
            return try handleExportKey(rest, io: io)
        default:
            return .forward
        }
    }

    // MARK: - Key selection

    private func handleSelectKey(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        // SIGKEY/SETKEY take a single keygrip, possibly preceded by options.
        guard let grip = rest.split(separator: " ").last.map({ String($0).uppercased() }) else {
            return .forward
        }
        if try storeRecord(grip) != nil {
            selectedLocalGrip = grip
            try io.sendOK()
            return .handled
        }
        selectedLocalGrip = nil
        return .forward
    }

    // MARK: - SETHASH

    private func handleSetHash(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        guard selectedLocalGrip != nil else { return .forward }
        if rest.contains("--inquire") {
            try io.sendError(.notImplemented, text: "SETHASH --inquire is not supported")
            return .handled
        }
        // Forms: "--hash=<name|num> <hex>" or "<num> <hex>".
        var tokens = rest.split(separator: " ").map(String.init)
        var algoToken: String
        if let first = tokens.first, first.hasPrefix("--hash=") {
            algoToken = String(first.dropFirst("--hash=".count))
            tokens.removeFirst()
        } else if let first = tokens.first {
            algoToken = first
            tokens.removeFirst()
        } else {
            try io.sendError(.invValue, text: "SETHASH missing arguments")
            return .handled
        }
        guard let hex = tokens.first, let digest = Data(hexString: hex) else {
            try io.sendError(.invValue, text: "SETHASH missing or malformed digest")
            return .handled
        }
        guard let hash = Self.hashAlgorithm(from: algoToken) else {
            try io.sendError(.unsupportedAlgorithm, text: "unsupported hash \(algoToken)")
            return .handled
        }
        guard digest.count == hash.digestLength else {
            try io.sendError(.invValue, text: "digest length \(digest.count) != \(hash.digestLength)")
            return .handled
        }
        storedHash = hash
        storedDigest = digest
        try io.sendOK()
        return .handled
    }

    /// Map a SETHASH algorithm token (name or libgcrypt MD id) to our enum.
    /// libgcrypt SHA-2 ids (8/9/10) coincide with OpenPGP's.
    static func hashAlgorithm(from token: String) -> PGPHashAlgorithm? {
        switch token.lowercased() {
        case "sha256", "8": return .sha256
        case "sha384", "9": return .sha384
        case "sha512", "10": return .sha512
        default: return nil
        }
    }

    // MARK: - PKSIGN

    private func handlePkSign(io: AssuanServerIO) throws -> AssuanDisposition {
        guard let grip = selectedLocalGrip else { return .forward }
        guard let digest = storedDigest, let hash = storedHash else {
            try io.sendError(.invValue, text: "no hash set for PKSIGN")
            return .handled
        }
        let record = try requireRecord(grip)
        let context = authSession.context(graceSeconds: record.policy.graceSeconds)
        let signer = try keyStore.signingBackend(keygripHex: grip, context: context)
        let (r, s) = try signer.sign(digest: digest, hash: hash)
        let sigVal = SExpression.ecdsaSigVal(r: r, s: s)
        try io.sendData(sigVal.serialize())
        try io.sendOK()
        return .handled
    }

    // MARK: - PKDECRYPT

    private func handlePkDecrypt(io: AssuanServerIO) throws -> AssuanDisposition {
        guard let grip = selectedLocalGrip else { return .forward }
        let record = try requireRecord(grip)
        // Match the stock agent's advisory maxlen before inquiring.
        try io.sendStatus(keyword: "INQUIRE_MAXLEN", args: "4096")
        let raw = try io.sendInquire(keyword: "CIPHERTEXT")
        let ciphertext = try RFC6637.parseCiphertext(raw)
        let context = authSession.context(graceSeconds: record.policy.graceSeconds)
        let agreement = try keyStore.agreementBackend(keygripHex: grip, context: context)
        let blob = try RFC6637.recoverSessionKeyBlob(ciphertext: ciphertext, agreement: agreement)
        let value = SExpression.list([.atom("value"), .atom(blob)])
        try io.sendData(value.serialize())
        try io.sendOK()
        return .handled
    }

    // MARK: - HAVEKEY

    private func handleHaveKey(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        let trimmed = rest.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("--list") {
            let result = try backend.transact("HAVEKEY \(trimmed)")
            var combined = result.data
            var seen = Set<Data>()
            var i = combined.startIndex
            while i + 20 <= combined.endIndex {
                seen.insert(combined.subdata(in: i..<(i + 20)))
                i += 20
            }
            for record in try keyStore.allRecords() {
                guard let grip = Data(hexString: record.keygripHex), grip.count == 20 else { continue }
                if seen.insert(grip).inserted { combined.append(grip) }
            }
            try io.sendData(combined)
            try io.sendOK()
            return .handled
        }

        // Membership test over explicit grips.
        let requested = trimmed.split(separator: " ").map { String($0).uppercased() }
        let storeGrips = Set(try keyStore.allRecords().map { $0.keygripHex.uppercased() })
        let remainder = requested.filter { !storeGrips.contains($0) }
        if remainder.isEmpty {
            try io.sendOK()
            return .handled
        }
        let result = try backend.transact("HAVEKEY \(remainder.joined(separator: " "))")
        if let error = result.error {
            try io.sendError(error)
        } else {
            try io.sendOK()
        }
        return .handled
    }

    // MARK: - KEYINFO

    private func handleKeyInfo(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        let trimmed = rest.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("--list") {
            let result = try backend.transact("KEYINFO \(trimmed)")
            for status in result.statuses {
                try io.sendStatus(keyword: status.keyword, args: status.args)
            }
            for record in try keyStore.allRecords() {
                try io.sendStatus(keyword: "KEYINFO", args: keyInfoLine(grip: record.keygripHex.uppercased()))
            }
            try io.sendOK()
            return .handled
        }
        guard let grip = trimmed.split(separator: " ").last.map({ String($0).uppercased() }) else {
            return .forward
        }
        if try storeRecord(grip) != nil {
            try io.sendStatus(keyword: "KEYINFO", args: keyInfoLine(grip: grip))
            try io.sendOK()
            return .handled
        }
        return .forward
    }

    /// KEYINFO status arguments matching what gpg-agent 2.5.20 emits for an
    /// available on-disk key: `<grip> D - - - C - - -` (type D = on disk,
    /// protection C = clear). Verified against the live agent.
    private func keyInfoLine(grip: String) -> String {
        "\(grip) D - - - C - - -"
    }

    // MARK: - READKEY

    private func handleReadKey(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        guard let grip = rest.split(separator: " ").last.map({ String($0).uppercased() }) else {
            return .forward
        }
        guard let record = try storeRecord(grip) else { return .forward }
        let sexp = SExpression.eccPublicKey(curve: "NIST P-256", q: record.point.uncompressed)
        try io.sendData(sexp.serialize())
        try io.sendOK()
        return .handled
    }

    // MARK: - EXPORT_KEY

    private func handleExportKey(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        guard let grip = rest.split(separator: " ").last.map({ String($0).uppercased() }) else {
            return .forward
        }
        if try storeRecord(grip) != nil {
            try io.sendError(.notImplemented,
                             text: "key is sealed in the Secure Enclave and cannot be exported")
            return .handled
        }
        return .forward
    }

    // MARK: - Store helpers

    private func storeRecord(_ grip: String) throws -> EnclaveKeyRecord? {
        try keyStore.record(keygripHex: grip)
    }

    private func requireRecord(_ grip: String) throws -> EnclaveKeyRecord {
        guard let record = try storeRecord(grip) else {
            throw AssuanError(code: .noSeckey, text: "no store key for keygrip \(grip)")
        }
        return record
    }
}

extension Data {
    /// Decode a hex string (any case) into bytes, or `nil` if malformed.
    init?(hexString: String) {
        let chars = Array(hexString.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        func nibble(_ b: UInt8) -> UInt8? {
            switch b {
            case 0x30...0x39: return b - 0x30
            case 0x41...0x46: return b - 0x41 + 10
            case 0x61...0x66: return b - 0x61 + 10
            default: return nil
            }
        }
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            out.append((hi << 4) | lo)
            i += 2
        }
        self = out
    }
}
