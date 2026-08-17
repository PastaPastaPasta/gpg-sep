# Deployment runbook

Steps to put `gpg-sep` into service on your own Mac. Some steps are interactive
(they need your YubiKey PIN or Touch ID) and some change your live GnuPG setup,
so this is written to be run by hand, with checkpoints. Everything here is
reversible via `gpg-sep uninstall`.

Throughout, `gpg-sep` and `gpg-sep-agent` are the release binaries from
`swift build -c release` (`.build/release/`). Put them on your `PATH` or call
them by full path.

## 0. Pre-flight

```
gpg-sep doctor                 # before install: reports SEP available, socket still stock
gpg -K                         # note your current keys so you can compare afterwards
```

Back up `~/.gnupg` (a plain copy is fine) before changing the agent, so you have
a known-good state to return to.

## 1. Install the agent (changes your live setup)

```
gpg-sep install
```

This creates the backend mirror home under `~/.local/share/gpg-sep/backend-home`
(symlinks to your real `~/.gnupg` key store, config, and card access), writes
`~/Library/LaunchAgents/org.gpg-sep.agent.plist`, kills the stock agent, and
`launchctl bootstrap`s `gpg-sep-agent` so it owns `~/.gnupg/S.gpg-agent`.

Verify nothing else changed:

```
gpg-sep doctor                 # socket now "ours", backend healthy, self-test green
gpg -K                         # same keys as before
echo test | gpg --clearsign    # your YubiKey primary still signs (PIN/touch as usual)
```

If anything looks wrong, `gpg-sep uninstall` restores the stock agent.

## 2a. Enclave subkey under your existing primary (recommended daily driver)

This binds a new enclave signing subkey under a primary you can still recover
(e.g. your YubiKey key). **Interactive: your YubiKey PIN is required** — the
primary makes the subkey's binding signature via the backend agent.

```
gpg-sep add-subkey --to <your-primary-fpr> --role sign --expire 2y \
    --presence presence --grace 15
```

Then confirm gpg accepts it and auto-selects it:

```
gpg --check-signatures <your-primary-fpr>   # new subkey binding + back-sig "sig!"
git commit -S --allow-empty -m "test: gpg-sep enclave subkey"
git log --show-signature -1                 # Good signature, new subkey
```

Because `user.signingkey` points at the primary fingerprint, gpg picks the newest
valid signing subkey (this one) automatically — no git config change needed.

Optionally add an enclave encryption subkey too: `--role encrypt`.

## 2b. Standalone enclave-born primary (the pure "never left the enclave" demo)

A brand-new certificate whose primary is itself in the enclave:

```
gpg-sep keygen --uid "Your Name (Secure Enclave) <you@example.com>" \
    --expire 2y --with-encryption-subkey --presence presence --grace 15
```

Note the printed **revocation certificate path** under the store's
`revocations/` — copy it somewhere off-machine. It is the only way to revoke this
identity if the Mac is lost (the primary can't be backed up).

## 3. Verify end to end

```
gpg-sep doctor --hardware      # forces the self-test through the real Secure Enclave
gpg-sep list                   # your enclave keys, policy, and gpg visibility
```

Touch ID: with `--presence presence` you get a prompt per signature outside the
grace window; the prompt now names the key and the requesting process. A rebase
of N commits authenticates once within the grace window.

## 4. Publish (only for keys others verify — do each deliberately)

For the subkey under an existing published primary, redistribute the updated
public key so verifiers see the new subkey:

```
gpg --export --armor <your-primary-fpr> > pub.asc
# keyservers:
curl -sS --data-urlencode "keytext@pub.asc" https://keyserver.ubuntu.com/pks/add
# keybase (if you use it):   keybase pgp update <your-primary-fpr>
# GitHub needs the admin:gpg_key scope first:
#   gh auth refresh -h github.com -s admin:gpg_key
#   then delete the old GPG key entry and re-add pub.asc (GitHub won't update in place)
```

A standalone enclave primary is a new identity — publish and cross-certify it the
same way you would any new key, and keep its revocation certificate safe.

## Rollback

```
gpg-sep uninstall              # hands the socket back to the stock gpg-agent
```

Your on-disk and YubiKey keys are unaffected at every step; only the enclave keys
depend on `gpg-sep-agent` running.
