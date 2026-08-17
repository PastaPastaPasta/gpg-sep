# Security model

`gpg-sep` lets GnuPG use OpenPGP keys whose private halves are generated inside
the Apple Secure Enclave (SEP) and never exist outside it. This document states
precisely what that does and does not buy you, so you can decide whether it fits
your threat model.

## What the Secure Enclave gives you

- **Non-extractability.** An enclave key is created by `SecKeyCreateRandomKey` /
  CryptoKit `SecureEnclave.P256` entirely inside the SEP. The private scalar is
  never returned to the CPU, never written to disk in the clear, and cannot be
  exported — not by you, not by root, not by malware running as you. What is
  stored on disk is an opaque *sealed blob* that only this Mac's SEP can unseal.
- **Optional mandatory user presence.** With a presence policy, every signature
  (or a grace-windowed batch) requires Touch ID or the login password. This is
  the property a YubiKey with `touch` policy off does not provide: an attacker
  with code execution as you cannot sign silently.
- **Per-machine binding.** The sealed blob is useless on any other machine.

## What it does NOT give you

- **Backup / portability.** An enclave key cannot be copied, exported, or moved
  to another Mac. If the machine is lost, wiped, or its SEP is reset, the key is
  gone forever. Contrast the YubiKey, which survives a machine change. This is
  the central trade-off; see *Operational guidance* below.
- **Protection of past signatures.** Compromise of the machine does not let an
  attacker forge past signatures, but with `presence = none` (or inside an open
  grace window) it does let them produce *new* signatures while they have code
  execution and the machine is unlocked. Presence policy is what bounds this.
- **Algorithm choice.** The SEP only implements NIST P-256. Keys are therefore
  ECDSA (OpenPGP algorithm 19) and ECDH (algorithm 18) on `nistp256`. If your
  verifiers require Ed25519/Curve25519 or RSA, the enclave cannot serve them.
- **Anything about the rest of your keyring.** Existing on-disk and smartcard
  keys keep exactly their prior security posture; `gpg-sep` forwards their
  operations to the real gpg-agent untouched.

## Threat model

| Adversary | Outcome |
|---|---|
| Stolen powered-off Mac (FileVault on) | Key unreachable — SEP locked, blob sealed. |
| Stolen unlocked Mac, `presence = none` key | Attacker can sign until logout/reboot. Use a presence policy for high-value keys. |
| Malware as your user, `presence` key, no open grace window | Cannot sign without a Touch ID / password prompt you would see. |
| Malware as your user, `presence` key, grace window open | Can sign silently until the window closes. Shorter `graceSeconds` shrinks this. |
| Root / kernel attacker | Cannot extract the key; can request signatures subject to the same presence policy. |
| Attacker on another machine with the sealed blob | Nothing — the blob is bound to this SEP. |

## The proxy is in the signing path

`gpg-sep-agent` owns `~/.gnupg/S.gpg-agent` and forwards non-enclave keygrips to
the real gpg-agent. Consequences:

- It only ever *forwards* or *refuses*; it never sees your smartcard PIN or your
  on-disk key passphrases (those flow inside the forwarded Assuan stream to the
  real agent, which handles pinentry itself).
- It enforces that the connecting peer is the same UID (Assuan's expectation for
  a user socket).
- **Failure is safe.** If `gpg-sep-agent` is stopped or crashes, gpg autostarts
  the stock gpg-agent and you are back to your exact pre-install setup. Enclave
  keys become temporarily inert; nothing else breaks. `gpg-sep uninstall`
  restores the stock agent permanently.
- **Backend death does not brick signing.** The proxy is decoupled from the
  backend gpg-agent it forwards to: if that backend dies (including via
  `gpgconf --kill gpg-agent`, which the proxy intercepts rather than forwarding),
  enclave keygrips keep signing, and the proxy restarts the backend on demand for
  forwarded traffic. A forwarded operation against a still-dead backend returns a
  clean error, never a hang. The remaining single point of failure is the proxy
  process itself, which launchd (`KeepAlive`) relaunches; a relaunched proxy binds
  a clean socket and rebuilds the backend.
- **Single instance.** The daemon takes an exclusive lockfile before it touches
  the socket, so two instances cannot race and clobber each other's socket.
- `EXPORT_KEY` for an enclave keygrip is refused by design.

## Operational guidance

Because enclave keys cannot be backed up:

1. **Prefer an enclave *subkey* under a primary you can recover** (e.g. your
   YubiKey-held primary). If the Mac dies, the identity survives; you just bind a
   new subkey. `gpg-sep add-subkey --to <primary-fpr>` is built for this.
2. **Set an expiration.** An expiring key is a dead-man switch if you ever lose
   access to it.
3. **Keep the pre-generated revocation certificate** that `gpg-sep keygen`
   writes to the key store, off-machine. It is the only way to revoke a
   standalone enclave primary whose key you can no longer reach.
4. **Choose presence policy by value.** Release-signing keys: `presence` (or
   `biometry`) with a short grace window. Everyday commit keys: a longer grace
   window trades a little safety for not tapping on every rebase commit.
5. `biometryCurrentSet` additionally destroys the key if the enrolled biometric
   set changes — strong anti-tamper, but it will brick a key you cannot back up
   the moment you add or remove a fingerprint. Opt in deliberately.

## Reporting

This is experimental software handling signing keys. Report vulnerabilities via
a GitHub security advisory on the repository rather than a public issue.
