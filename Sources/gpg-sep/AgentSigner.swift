import Foundation
import AssuanKit
import OpenPGPKit

/// Drives a `PKSIGN` against the running gpg-agent so a signature can be made by
/// a key gpg-sep does not hold itself — notably an existing primary (RSA on a
/// YubiKey, or ECDSA) that must sign a new subkey's 0x18 binding.
///
/// The agent returns `(sig-val(rsa(s <mpi>)))` or `(sig-val(ecdsa(r ..)(s ..)))`;
/// this returns the primary's algorithm octet plus the signature MPIs in the
/// order OpenPGP expects (`[s]` for RSA, `[r, s]` for ECDSA), ready to hand to
/// `PGPSignatureBuilder.finalizePacket(over:mpis:)`.
enum AgentSigner {
    struct SignResult {
        let algorithmByte: UInt8
        let mpis: [Data]
    }

    /// - Parameters:
    ///   - socket: the agent socket (already resolved).
    ///   - keygripHex: 40-hex keygrip of the signing key.
    ///   - digest: the precomputed digest to sign.
    ///   - hashName: SETHASH algorithm name (e.g. `sha256`).
    static func sign(socket: String, keygripHex: String, digest: Data,
                     hashName: String = "sha256") throws -> SignResult {
        let client = try AssuanClient.connect(toSocket: socket)
        defer { client.connection.close() }
        _ = try client.transact("RESET")

        let sig = try client.transact("SIGKEY \(keygripHex)")
        if let e = sig.error { throw CLIError("agent SIGKEY failed: \(e.text ?? "")") }

        // A description shown by pinentry if the key is protected; harmless
        // otherwise. Percent-plus escaped (spaces as +).
        _ = try client.transact("SETKEYDESC gpg-sep+subkey+binding")

        let setHash = try client.transact("SETHASH --hash=\(hashName) \(digest.hexLower)")
        if let e = setHash.error { throw CLIError("agent SETHASH failed: \(e.text ?? "")") }

        let signed = try client.transact("PKSIGN")
        if let e = signed.error {
            throw CLIError("agent PKSIGN failed (\(e.number)): \(e.text ?? "")")
        }
        guard !signed.data.isEmpty else { throw CLIError("agent PKSIGN returned no data") }

        let sexp = try SExpression.parse(signed.data)
        if let ecdsa = sexp.ecdsaSignatureRS() {
            return SignResult(algorithmByte: PGPPublicKeyAlgorithm.ecdsa.rawValue,
                              mpis: [ecdsa.r, ecdsa.s])
        }
        if let rsa = sexp.find("rsa"), let s = rsa.value("s") {
            return SignResult(algorithmByte: 1, mpis: [s])
        }
        if let eddsa = sexp.find("eddsa"), let r = eddsa.value("r"), let s = eddsa.value("s") {
            // EdDSA (algo 22): two fixed 32-byte MPIs.
            return SignResult(algorithmByte: 22, mpis: [r, s])
        }
        throw CLIError("unrecognized sig-val from agent: \(sexp)")
    }
}
