import Foundation
import CryptoKit
import CommonCrypto
import AssuanKit
import OpenPGPKit
import SEPKit

/// RFC 6637 ECDH decryption glue, matching GnuPG 2.5.x's `PKDECRYPT --kem=PGP`
/// path exactly.
///
/// Empirically verified against gpg-agent 2.5.20 (see PROTOCOL.md): modern gpg
/// hands the agent the whole ECDH ciphertext as
/// `(enc-val(ecc(c<sym>)(h<hash>)(e<ephemeral>)(s<wrapped>)(kdf-params<blob>)))`
/// where `kdf-params` already carries the RFC 6637 parameter string (curve OID,
/// algo 18, KDF spec, `"Anonymous Sender    "`, and the recipient fingerprint).
/// The agent's job is only:
///
/// 1. ECDH: shared X = X-coordinate of `d · e` (from the key backend).
/// 2. KEK = single-step KDF (NIST SP 800-56A concat KDF, one iteration for a
///    16-byte AES-128 KEK): `leftmost(kek_len, H(0x00000001 || sharedX || kdf))`.
/// 3. AES key-unwrap (RFC 3394) of `s` minus its 1-byte PGP length prefix.
/// 4. Return `(value <unwrapped>)`; gpg strips the symmetric-algo byte, checksum
///    and PKCS#5 padding itself (`g10/pubkey-enc.c:get_it`).
enum RFC6637 {

    struct DecryptError: Error, CustomStringConvertible {
        let message: String
        var description: String { message }
    }

    /// Parsed contents of a PGP ECDH `enc-val`.
    struct Ciphertext {
        var symmetricAlgo: Int          // `c`: KEK cipher id (7 = AES-128)
        var hashAlgo: Int               // `h`: KDF hash id (8 = SHA-256)
        var ephemeral: ECPoint          // `e`: sender's ephemeral point
        var wrappedSessionKey: Data     // `s`: PGP-framed wrapped key (len || wrap)
        var kdfParams: Data             // `kdf-params`: RFC 6637 parameter string
    }

    /// Parse the canonical S-expression gpg sends on the CIPHERTEXT inquiry.
    static func parseCiphertext(_ raw: Data) throws -> Ciphertext {
        let sexp = try SExpression.parse(raw)
        // Shape: (enc-val (ecc (c ..)(h ..)(e ..)(s ..)(kdf-params ..)))
        guard let ecc = sexp.find("ecc") ?? sexp.find("enc-val")?.find("ecc") else {
            throw DecryptError(message: "ciphertext is not an ECC enc-val: \(sexp)")
        }
        guard let e = ecc.value("e") else {
            throw DecryptError(message: "ECDH ciphertext missing ephemeral point 'e'")
        }
        guard let s = ecc.value("s") else {
            throw DecryptError(message: "ECDH ciphertext missing wrapped key 's'")
        }
        guard let kdf = ecc.value("kdf-params") else {
            throw DecryptError(message: "ECDH ciphertext missing kdf-params")
        }
        let point = try parseEphemeral(e)
        return Ciphertext(
            symmetricAlgo: ecc.value("c").map(integer(fromAtom:)) ?? 7,
            hashAlgo: ecc.value("h").map(integer(fromAtom:)) ?? 8,
            ephemeral: point,
            wrappedSessionKey: s,
            kdfParams: kdf
        )
    }

    /// Run the full RFC 6637 recovery and return the `m` blob gpg expects inside
    /// `(value <m>)` — i.e. the AES-unwrapped, still-framed session-key material.
    static func recoverSessionKeyBlob(
        ciphertext: Ciphertext,
        agreement: AgreementBackend
    ) throws -> Data {
        // 1. Raw ECDH: 32-byte X of d·e.
        let sharedX = try agreement.sharedSecretX(ephemeral: ciphertext.ephemeral)

        // 2. KEK via the single-step KDF over sharedX with the supplied params.
        let kekLen = keyLength(forCipherAlgo: ciphertext.symmetricAlgo)
        let kek = try singleStepKDF(
            hashAlgo: ciphertext.hashAlgo,
            z: sharedX,
            otherInfo: ciphertext.kdfParams,
            length: kekLen
        )

        // 3. Strip the 1-byte PGP length prefix, then RFC 3394 AES key-unwrap.
        let wrapped = ciphertext.wrappedSessionKey
        guard let first = wrapped.first, Int(first) == wrapped.count - 1 else {
            throw DecryptError(message: "wrapped session key length prefix mismatch")
        }
        let toUnwrap = wrapped.dropFirst()
        return try aesKeyUnwrap(kek: kek, wrapped: Data(toUnwrap))
    }

    // MARK: - Primitives

    /// NIST SP 800-56A single-step KDF (a.k.a. X9.63 concat KDF with a 4-octet
    /// big-endian counter starting at 1), which is what GnuPG's
    /// `GCRY_KDF_ONESTEP_KDF` computes for PGP ECDH.
    static func singleStepKDF(hashAlgo: Int, z: Data, otherInfo: Data, length: Int) throws -> Data {
        var out = Data()
        var counter: UInt32 = 1
        while out.count < length {
            var input = Data()
            withUnsafeBytes(of: counter.bigEndian) { input.append(contentsOf: $0) }
            input.append(z)
            input.append(otherInfo)
            out.append(try digest(hashAlgo: hashAlgo, input))
            counter &+= 1
        }
        return out.prefix(length)
    }

    static func digest(hashAlgo: Int, _ data: Data) throws -> Data {
        switch hashAlgo {
        case 8: return Data(SHA256.hash(data: data))
        case 9: return Data(SHA384.hash(data: data))
        case 10: return Data(SHA512.hash(data: data))
        default:
            throw DecryptError(message: "unsupported KDF hash algorithm \(hashAlgo)")
        }
    }

    /// RFC 3394 AES key unwrap via CommonCrypto (`CCSymmetricKeyUnwrap`), which
    /// implements the standard-IV (0xA6…) unwrap and integrity check directly.
    static func aesKeyUnwrap(kek: Data, wrapped: Data) throws -> Data {
        guard wrapped.count >= 24, wrapped.count % 8 == 0 else {
            throw DecryptError(message: "wrapped key length \(wrapped.count) is not a valid AESWRAP block")
        }
        let iv = [UInt8](repeating: 0xA6, count: 8)
        var outLen = wrapped.count - 8
        var raw = [UInt8](repeating: 0, count: outLen)
        let status = kek.withUnsafeBytes { (kekBuf: UnsafeRawBufferPointer) -> Int32 in
            wrapped.withUnsafeBytes { (wBuf: UnsafeRawBufferPointer) -> Int32 in
                CCSymmetricKeyUnwrap(
                    CCWrappingAlgorithm(kCCWRAPAES),
                    iv, iv.count,
                    kekBuf.bindMemory(to: UInt8.self).baseAddress, kek.count,
                    wBuf.bindMemory(to: UInt8.self).baseAddress, wrapped.count,
                    &raw, &outLen
                )
            }
        }
        guard status == Int32(kCCSuccess) else {
            throw DecryptError(message: "AES key unwrap failed (integrity check), status \(status)")
        }
        return Data(raw.prefix(outLen))
    }

    // MARK: - Helpers

    /// KEK length in bytes for an OpenPGP/libgcrypt symmetric cipher id. AES ids
    /// coincide between the two numbering schemes (7/8/9 → 16/24/32).
    static func keyLength(forCipherAlgo algo: Int) -> Int {
        switch algo {
        case 7: return 16   // AES-128
        case 8: return 24   // AES-192
        case 9: return 32   // AES-256
        default: return 16
        }
    }

    /// Interpret an atom holding a gcry `%d` value. In canonical S-expressions
    /// gcry serializes `%d` as its *decimal ASCII string* (verified against gpg
    /// 2.5.20: `(1:h1:8)` carries the byte `'8'`, not 0x08), so parse it as
    /// decimal, falling back to a big-endian integer for any non-digit encoding.
    static func integer(fromAtom atom: Data) -> Int {
        if !atom.isEmpty, atom.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
           let value = Int(String(decoding: atom, as: UTF8.self)) {
            return value
        }
        var value = 0
        for byte in atom { value = (value << 8) | Int(byte) }
        return value
    }

    /// Parse an ephemeral point atom (`0x04 || X || Y`, optionally a native
    /// `0x40 || X` prefix which does not occur for nistp256) into an `ECPoint`.
    static func parseEphemeral(_ atom: Data) throws -> ECPoint {
        let bytes = Data(atom)
        guard bytes.count == 65, bytes.first == 0x04 else {
            throw DecryptError(message: "unexpected ephemeral point encoding (\(bytes.count) bytes)")
        }
        let x = bytes.subdata(in: (bytes.startIndex + 1)..<(bytes.startIndex + 33))
        let y = bytes.subdata(in: (bytes.startIndex + 33)..<(bytes.startIndex + 65))
        return try ECPoint(validatingX: x, y: y)
    }
}
