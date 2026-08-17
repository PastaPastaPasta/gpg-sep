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

**Status: work in progress — not yet ready for use.**

## Constraints inherited from the hardware

- The Secure Enclave only does NIST P-256, so keys are ECDSA/ECDH `nistp256`
  (OpenPGP algorithms 19/18, RFC 6637).
- Enclave keys cannot be backed up. Plan with expirations and the pre-generated
  revocation certificate `gpg-sep keygen` gives you; for a daily-driver
  identity, prefer an enclave *subkey* under a primary you can recover.

## License

MIT
