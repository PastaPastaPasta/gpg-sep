# Protocol notes

How `gpg-sep-agent` sits on the gpg-agent Assuan socket, which commands it
answers itself, and the exact wire formats it must reproduce. Formats marked
*verified* were captured from a live GnuPG 2.5.20 `gpg-agent` during development,
not taken from specs alone.

## Socket takeover

gpg finds its agent at `~/.gnupg/S.gpg-agent` (from `gpgconf --list-dirs
agent-socket`). `gpg-sep-agent` owns that path in one of two ways:

- **Bind directly.** After `gpgconf --kill gpg-agent`, bind an `AF_UNIX`
  listener at `S.gpg-agent`. gpg's autostart sees a live socket and does not
  start the stock agent.
- **Redirection file.** Alternatively the path may be a libassuan redirection
  file whose first line is literally `%Assuan%` and second line `socket=PATH`
  (with `${VAR}` expansion, ≤ 511 bytes). A connecting client transparently
  reconnects to `PATH`.

The stock gpg-agent is relocated to a backend home under
`~/.local/share/gpg-sep/backend-home/`, whose `private-keys-v1.d/`,
`gpg-agent.conf`, and `sshcontrol` are symlinks into `~/.gnupg`, so smartcard
PIN and passphrase caching behave exactly as before. The proxy forwards
non-enclave traffic to that backend's socket.

## Assuan framing (verified)

- Lines end in `\n`; content ≤ 1001 octets (libassuan `ASSUAN_LINELENGTH`,
  1002-octet buffer minus the LF). Longer logical data is chunked across `D`
  lines.
- Greeting on connect: `OK Pleased to meet you, process <pid>` where `<pid>` is
  the **server's own** `getpid()`, not the client's.
- `BYE` → `OK closing connection`.
- Error line: `ERR <n> <text>` where `<n>` is `(source << 24) | code`. Example
  observed for an unknown verb: `ERR 67109139 Unknown IPC command <GPG Agent>`
  = source 4 (`GPG_ERR_SOURCE_GPGAGENT`), code 275 (`GPG_ERR_ASS_UNKNOWN_CMD`).
- Status line: `S <keyword> <args>`, e.g.
  `S KEYINFO <grip> T D2760001240103040006179939700000 OPENPGP.3 - - - - -`.
- **`D`-line escaping**: only `%`, CR, LF are escaped, as `%25`, `%0D`, `%0A`.
  NUL and all high bytes travel raw. (Command-argument escaping additionally
  uses `+` for space — "percent-plus".)

## Command routing

For every client command the proxy decides: answer locally (enclave keygrip) or
forward verbatim to the backend agent (everything else). Routing key is the
40-hex keygrip.

Intercepted for enclave keygrips:

| Command | Handling |
|---|---|
| `SIGKEY`/`SETKEY <grip>` | Record the selected keygrip for the next operation. A value that is not a 40-hex keygrip is never ours: it is forwarded, never used for a store lookup (defends against path-traversal grips like `../../evil`). |
| `SETHASH --hash=<name>\|<n> <hex>` | Store the precomputed digest and its hash algorithm. `--inquire` (deferred hashing) is not supported in v1. |
| `PKSIGN [...]` | Sign the stored digest in the enclave; reply `D (7:sig-val(5:ecdsa(1:r32:…)(1:s32:…)))` then `OK`. |
| `PKDECRYPT` | ECDH: enclave yields the shared X; RFC 6637 KDF + AES key-unwrap performed in-process; reply the session key S-expression. |
| `HAVEKEY <grips>` | `OK` iff all listed grips are held (enclave grips answered locally, others delegated). |
| `HAVEKEY --list` | Union of backend grips and enclave grips (20-byte binary blobs over `D`). |
| `KEYINFO [--list] <grip>` | Report enclave grips as available, with fields `<grip> D - - - P - - -`: type `D` (on disk) so gpg selects the key and routes its `PKSIGN` to us, protection `P` (protected) because an enclave key demands Touch ID / presence and is never clear on disk. Reporting `C` (clear) would misrepresent it as unprotected; verified against gpg-agent 2.5.20, which emits `... P ...` for a passphrase-protected on-disk key and `... C ...` only for an unprotected one. |
| `SETKEYDESC <text>` | Percent-plus-decoded and carried into the enclave Touch ID prompt (`LAContext.localizedReason`) so the user sees what they are authorizing. Also forwarded when a backend key may be the target so its pinentry still describes the operation. |
| `HAVEKEY --list[=N]` | Union of backend and enclave grips, but never more than the client's requested `N`. |
| `KILLAGENT` | **Not forwarded.** Acked locally so `gpgconf --kill gpg-agent` cannot wedge the stack by killing the backend out from under the proxy; the proxy (and thus enclave signing) stays up and the backend is restarted on demand. Restart the `gpg-sep-agent` service to fully restart everything. |
| `RELOADAGENT` | Forwarded (it only reloads backend config); acked locally when no backend is reachable. |
| `READKEY <grip>` | Return the public key S-expression `(public-key(ecc(curve nistp256)(q <point>)))`. |
| `EXPORT_KEY <grip>` | Refused with an error — enclave keys are non-exportable by design. |

Everything else (`GENKEY` for non-enclave keys, `PKDECRYPT` for on-disk keys,
scdaemon-backed smartcard operations, `GETINFO`, `OPTION`, `RESET`, pinentry
`INQUIRE` round-trips, …) is relayed to the backend unchanged, including
bidirectional `INQUIRE` streaming with escaping preserved.

**Backend unreachable (decoupled mode).** If the backend gpg-agent cannot be
started or connected, the proxy still serves enclave keygrips: `SIGKEY`/`SETHASH`/
`PKSIGN`/`PKDECRYPT`/`HAVEKEY`/`KEYINFO`/`READKEY` for store keys keep working, and
the pre-signing housekeeping verbs gpg relies on (`RESET`, `OPTION`, `NOP`, and
`GETINFO version`) are answered locally so a dead backend cannot abort an enclave
signature. Genuinely backend-only commands (an on-disk key op, membership of a
non-store keygrip, other `GETINFO` queries) return a clean `ERR` (`GPG_ERR_NO_AGENT`)
rather than hanging or dropping the connection.

## Canonical S-expressions

Values are libgcrypt canonical S-expressions: `(<len>:<bytes> …)`. MPI values
are raw big-endian; a leading `0x00` is prepended when the high bit is set to
keep the value unsigned — this rule is reproduced for `r`, `s`, and the point
`q`. Observed shapes:

- public key: `(10:public-key(3:ecc(5:curve10:NIST P-256)(1:q65:…)))`
- signature: `(7:sig-val(5:ecdsa(1:r32:…)(1:s32:…)))`
