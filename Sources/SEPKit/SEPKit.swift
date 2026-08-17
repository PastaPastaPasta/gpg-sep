// SEPKit — Secure Enclave & software signing/agreement backends for gpg-sep.
//
// This module provides the crypto backends the gpg-sep daemon routes to:
//
//   * `SecureEnclaveBackend` / `SecureEnclaveAgreementBackend` — P-256 keys
//     generated and held inside the Apple Secure Enclave via CryptoKit
//     (`SecureEnclave.P256`). Keys persist as opaque sealed `dataRepresentation`
//     blobs — no keychain entry, no entitlement — exactly the age-plugin-se
//     model. Only the SEP that created a blob can unseal it.
//   * `SoftwareSigningBackend` / `SoftwareAgreementBackend` — plain CryptoKit
//     `P256` keys persisted UNSEALED. TEST / CI ONLY — never for real keys.
//   * `KeyStore` — on-disk record store keyed by libgcrypt keygrip.
//   * `Config`, `AuthSession` — policy defaults and the Touch ID grace window.
//
// Both backends sign a caller-supplied precomputed digest (never hash-then-sign)
// because gpg hands us the digest via the agent SETHASH command and expects an
// ECDSA signature over exactly those bytes.
