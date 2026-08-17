# gpg-sep

**GPG keys born and held in the Apple Secure Enclave.**

`gpg-sep` lets GnuPG use OpenPGP keys (primaries or subkeys) that are generated
inside the Secure Enclave of Apple Silicon Macs and never exist outside it.
Signing and decryption are performed by the enclave; the private key is not
exportable, not by you and not by malware running as you.

There is no Secure Enclave backend in GnuPG itself — its only hardware paths
are smartcards (scdaemon) and Linux TPMs (tpm2d, which merely wraps
software-generated keys). `gpg-sep` fills that gap with a keygrip-routed
gpg-agent proxy:

```
gpg/git ──▶ ~/.gnupg/S.gpg-agent   (owned by gpg-sep-agent)
              │ enclave keygrips ──▶ Secure Enclave (ECDSA P-256 / ECDH)
              └─ everything else ──▶ real gpg-agent ──▶ scdaemon ──▶ your smartcards
```

Existing keys — on-disk, YubiKey/smartcard — keep working unchanged. If
`gpg-sep-agent` is stopped or uninstalled, gpg autostarts the stock agent and
you are back to exactly the setup you had before.

**Status: experimental.** Feature-complete and covered by 214 tests, including
live interop against GnuPG 2.5.20 and real Secure Enclave sign/verify on Apple
Silicon. It has not had external users or a formal audit — treat it as such
before trusting it with a high-value key.

## Requirements

- Apple Silicon Mac (M-series) with a Secure Enclave.
- GnuPG 2.4+ (developed and tested against 2.5.20, Homebrew).
- Xcode / Swift 5.9+ toolchain to build.

## Build

```
swift build -c release        # produces .build/release/{gpg-sep,gpg-sep-agent}
swift test                    # 214 tests
```

## Quick start

```
gpg-sep install                              # take over the agent socket via launchd
gpg-sep keygen --uid "You <you@example.com>" # a standalone enclave-born certificate
# …or bind an enclave subkey under a key you already have (recoverable identity):
gpg-sep add-subkey --to <your-primary-fpr> --role sign
gpg-sep doctor                               # end-to-end sign/verify self-test
```

`git commit -S` and `gpg --sign` then route through the enclave automatically.
See [`DEPLOYMENT.md`](DEPLOYMENT.md) for the full runbook (including the
YubiKey/Touch ID interactive steps), [`SECURITY.md`](SECURITY.md) for the threat
model, and [`PROTOCOL.md`](PROTOCOL.md) for the Assuan surface.

## Constraints inherited from the hardware

- The Secure Enclave only does NIST P-256, so keys are ECDSA/ECDH `nistp256`
  (OpenPGP algorithms 19/18, RFC 6637). No Ed25519/RSA enclave keys.
- Enclave keys cannot be backed up. Plan with expirations and the pre-generated
  revocation certificate `gpg-sep keygen` gives you; for a daily-driver
  identity, prefer an enclave *subkey* under a primary you can recover.

## License

MIT
