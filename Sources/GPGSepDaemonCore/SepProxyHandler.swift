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
    /// The backend gpg-agent connection, or `nil` when the backend is
    /// unreachable. Enclave keygrips are still served in that state; only
    /// *forwarded* commands fail with a clean `ERR`. Set to `nil` ("poisoned")
    /// if one of our own `transact`s desyncs the shared connection.
    private var backend: AssuanClient?

    /// PID of the connecting client, used to attribute a Touch ID prompt.
    private let peerProcessID: pid_t?

    /// Uppercase-hex keygrip currently selected, iff it is a store key. `nil`
    /// means the last selection (if any) routed to the backend.
    private var selectedLocalGrip: String?
    private var storedDigest: Data?
    private var storedHash: PGPHashAlgorithm?

    /// The most recent `SETKEYDESC`, percent-plus-decoded. Carried into the Touch
    /// ID prompt so the user sees what they are actually authorizing.
    var keyDescription: String?

    /// The `localizedReason` applied to the context for the most recent enclave
    /// operation. Exposed for tests to assert consent integrity (H3).
    private(set) var lastLocalizedReason: String?

    public init(keyStore: KeyStore, authSession: AuthSession, backend: AssuanClient?,
                peerProcessID: pid_t? = nil) {
        self.keyStore = keyStore
        self.authSession = authSession
        self.backend = backend
        self.peerProcessID = peerProcessID
    }

    public func handle(verb: String, rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        switch verb {
        case "RESET":
            selectedLocalGrip = nil
            storedDigest = nil
            storedHash = nil
            keyDescription = nil
            // Answer locally when decoupled so a dead backend can't break the
            // preamble of an otherwise pure-enclave signing session (C1).
            if backend == nil { try io.sendOK(); return .handled }
            return .forward
        case "OPTION", "NOP":
            // Housekeeping verbs gpg issues before signing. When there is no
            // backend to forward them to, ack locally rather than failing — the
            // options are advisory and enclave signing needs no pinentry.
            if backend == nil { try io.sendOK(); return .handled }
            return .forward
        case "GETINFO":
            // gpg aborts the whole session if `GETINFO version` fails, so when the
            // backend is gone we must still answer it (a conservative version that
            // satisfies gpg's minimum) instead of erroring out the enclave path.
            if backend == nil { return try handleGetInfoOffline(rest, io: io) }
            return .forward
        case "KILLAGENT":
            // Do NOT forward: killing the backend out from under the proxy is
            // what wedges the whole stack (`gpgconf --kill gpg-agent`). Ack
            // locally so the proxy — and thus enclave signing — stays alive; the
            // backend is (re)started on demand by the serve path. To fully
            // restart everything, restart the gpg-sep-agent service.
            try io.sendOK()
            return .handled
        case "RELOADAGENT":
            // Safe to forward (it only reloads backend config). With no backend
            // reachable there is nothing to reload, so ack locally.
            if backend == nil { try io.sendOK(); return .handled }
            return .forward
        case "SIGKEY", "SETKEY":
            return try handleSelectKey(rest, io: io)
        case "SETKEYDESC":
            // Remember the description so the enclave prompt can quote it, then
            // still forward when a backend key is (or may be) the target so its
            // pinentry keeps describing the operation too.
            keyDescription = AssuanEscaping.percentPlusDecodeToString(rest)
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
        // SIGKEY/SETKEY take a single keygrip, possibly preceded by options. A
        // value that is not a 40-hex keygrip is never one of ours (and must never
        // reach the store's path logic); forward it to the backend unchanged.
        guard let raw = rest.split(separator: " ").last.map(String.init),
              let grip = KeyStore.normalizedKeygrip(raw) else {
            selectedLocalGrip = nil
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
        let (r, s): (Data, Data) = try authSession.withKeySerialized(grip) {
            let context = authSession.context(forKeygrip: grip, graceSeconds: record.policy.graceSeconds)
            context.localizedReason = applyLocalizedReason(for: record, action: "sign")
            let signer = try keyStore.signingBackend(keygripHex: grip, context: context)
            return try signer.sign(digest: digest, hash: hash)
        }
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
        let blob: Data = try authSession.withKeySerialized(grip) {
            let context = authSession.context(forKeygrip: grip, graceSeconds: record.policy.graceSeconds)
            context.localizedReason = applyLocalizedReason(for: record, action: "decrypt")
            let agreement = try keyStore.agreementBackend(keygripHex: grip, context: context)
            return try RFC6637.recoverSessionKeyBlob(ciphertext: ciphertext, agreement: agreement)
        }
        let value = SExpression.list([.atom("value"), .atom(blob)])
        try io.sendData(value.serialize())
        try io.sendOK()
        return .handled
    }

    // MARK: - HAVEKEY

    private func handleHaveKey(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        let trimmed = rest.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("--list") {
            var combined = Data()
            var seen = Set<Data>()
            if backend != nil, let result = transactOrPoison("HAVEKEY \(trimmed)") {
                combined = result.data
                var i = combined.startIndex
                while i + 20 <= combined.endIndex {
                    seen.insert(combined.subdata(in: i..<(i + 20)))
                    i += 20
                }
            }
            // Honor the client's requested bound: never return more grips than
            // `--list=N` asked for (N counts backend + store grips together).
            let limit = Self.listLimit(trimmed)
            for record in try keyStore.allRecords() {
                if let limit, combined.count / 20 >= limit { break }
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
        guard backend != nil, let result = transactOrPoison("HAVEKEY \(remainder.joined(separator: " "))") else {
            try io.sendError(.noAgent, text: "no backend gpg-agent for non-enclave keygrips")
            return .handled
        }
        if let error = result.error {
            try io.sendError(error)
        } else {
            try io.sendOK()
        }
        return .handled
    }

    /// Answer `GETINFO` locally while decoupled from the backend, so gpg's
    /// pre-signing handshake does not abort on a dead backend. Only `version`
    /// needs a concrete reply (gpg treats its failure as fatal); other queries
    /// are advisory and can be acked with no data.
    private func handleGetInfoOffline(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        if rest.trimmingCharacters(in: .whitespaces) == "version" {
            // A conservative floor that clears gpg's minimum-agent-version check.
            try io.sendData(Data("2.4.0".utf8))
        }
        try io.sendOK()
        return .handled
    }

    /// Parse the `N` from a `--list=N` argument, if present and positive.
    static func listLimit(_ arg: String) -> Int? {
        guard let token = arg.split(separator: " ").first(where: { $0.hasPrefix("--list") }),
              let eq = token.firstIndex(of: "="),
              let n = Int(token[token.index(after: eq)...]), n > 0 else { return nil }
        return n
    }

    // MARK: - KEYINFO

    private func handleKeyInfo(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        let trimmed = rest.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("--list") {
            if backend != nil, let result = transactOrPoison("KEYINFO \(trimmed)") {
                for status in result.statuses {
                    try io.sendStatus(keyword: status.keyword, args: status.args)
                }
            }
            for record in try keyStore.allRecords() {
                try io.sendStatus(keyword: "KEYINFO", args: keyInfoLine(grip: record.keygripHex.uppercased()))
            }
            try io.sendOK()
            return .handled
        }
        guard let raw = trimmed.split(separator: " ").last.map(String.init),
              let grip = KeyStore.normalizedKeygrip(raw) else {
            return .forward
        }
        if try storeRecord(grip) != nil {
            try io.sendStatus(keyword: "KEYINFO", args: keyInfoLine(grip: grip))
            try io.sendOK()
            return .handled
        }
        return .forward
    }

    /// KEYINFO status arguments for a store key: `<grip> D - - - P - - -`.
    ///
    /// Type `D` (on disk) matches how gpg selects the key and routes its PKSIGN to
    /// us. Protection `P` (protected) is the honest value — an enclave key demands
    /// Touch ID / presence and is never clear on disk. Verified against live
    /// gpg-agent 2.5.20, which emits exactly `D - - - P - - -` for a
    /// passphrase-protected on-disk key and `... C ...` only for an *unprotected*
    /// one; reporting `C` would misrepresent the key as unprotected.
    private func keyInfoLine(grip: String) -> String {
        "\(grip) D - - - P - - -"
    }

    // MARK: - READKEY

    private func handleReadKey(_ rest: String, io: AssuanServerIO) throws -> AssuanDisposition {
        guard let raw = rest.split(separator: " ").last.map(String.init),
              let grip = KeyStore.normalizedKeygrip(raw) else {
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
        guard let raw = rest.split(separator: " ").last.map(String.init),
              let grip = KeyStore.normalizedKeygrip(raw) else {
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

    /// Run a `transact` on the shared backend connection. If it throws, the
    /// connection is desynced (a `D`/`S`/`OK`/`ERR` may be left unread), so we
    /// poison it — close and forget it — rather than reuse a corrupt stream for
    /// later forwards. Returns nil when there is no usable backend.
    private func transactOrPoison(_ command: String) -> AssuanResult? {
        guard let backend else { return nil }
        do {
            return try backend.transact(command)
        } catch {
            backend.connection.close()
            self.backend = nil
            return nil
        }
    }

    /// Build the Touch ID prompt text (H3) and record it for tests. Prefers the
    /// client-supplied `SETKEYDESC`; otherwise synthesizes an attributable reason
    /// so the user can tell their own operation from an attacker's.
    private func applyLocalizedReason(for record: EnclaveKeyRecord, action: String) -> String {
        let reason: String
        if let desc = keyDescription, !desc.isEmpty {
            reason = desc
        } else {
            let shortID = record.fingerprintHex.isEmpty
                ? String(record.keygripHex.uppercased().prefix(16))
                : String(record.fingerprintHex.uppercased().suffix(16))
            let label = record.label.isEmpty ? "enclave key" : record.label
            let pid = peerProcessID.map(String.init) ?? "?"
            reason = "gpg-sep: \(action) with \(label) (\(shortID)) requested by pid \(pid)"
        }
        lastLocalizedReason = reason
        return reason
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
