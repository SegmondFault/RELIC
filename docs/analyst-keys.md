# Analyst signing keys

RELIC analyst identities are Ed25519 keys stored in the **OpenSSH private-key
format**. This is the only format the Rust signer loads
(`relic_crypto::SystemSigner::from_openssh_file`), and `relic-sign-fidbf` is the
only supported way to produce analyst submission signatures. RELIC does not
ship its own key generator: use OpenSSH's `ssh-keygen`.

The private key and its passphrase never leave the analyst's machine. RELIC
stores only the 32-byte public key in `catalogue.user_public` (see
[BYO-key registration](api-handoff.md#byo-key-registration)).

## Rules

- Use a **dedicated** key for RELIC. Do not reuse it for SSH login, Git
  signing, or any other system, and do not reuse an existing SSH key as a
  RELIC identity.
- **Never sign arbitrary files or bytes with a RELIC key.** RELIC signatures
  are Ed25519 over `u64be(len(domain)) || domain || SHA-256 digest`. A generic
  "sign this file" tool lets anyone who can choose the file contents obtain a
  valid FIDBF, batch or source signature for content of their choosing. Only
  `relic-sign-fidbf` (and future RELIC signers that apply the versioned domain
  tags) may use the key.
- Always encrypt the private key with a strong passphrase.
- If the key is lost or compromised, the account is revoked and a fresh
  registration creates a fresh User ID; keys are never rotated in place.

## Generate a key

```bash
umask 077
mkdir -p ~/.config/relic/identity
chmod 700 ~/.config/relic/identity
ssh-keygen -t ed25519 -a 100 -C relic-analyst \
  -f ~/.config/relic/identity/id_ed25519
```

`-a 100` raises the bcrypt_pbkdf work factor that protects the encrypted key.
`ssh-keygen` prompts for the passphrase and creates the private key with mode
`0600`. The loader rejects a key file that is a symlink, is not a regular
file, or has any group/other permission bits set.

## Public key for registration

RELIC registers the raw 32-byte Ed25519 public key as 64 hexadecimal
characters:

```bash
awk '{print $2}' ~/.config/relic/identity/id_ed25519.pub \
  | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n'; echo
```

The SSH fingerprint is useful for confirming the key out of band with a
moderator:

```bash
ssh-keygen -lf ~/.config/relic/identity/id_ed25519.pub
```

## Sign a FIDBF submission

`relic-sign-fidbf` reads the passphrase from a file because it runs
non-interactively. The file must also be private (mode `0600`, regular,
non-symlink); one trailing LF or CRLF is ignored. Create it only for the
signing session and delete it afterwards:

```bash
umask 077
read -rs -p 'RELIC key passphrase: ' passphrase; echo
printf '%s\n' "$passphrase" > ~/.config/relic/identity/passphrase
unset passphrase

relic-sign-fidbf \
  --manifest manifest.json \
  --fidbf-object object.fidbf \
  --analyst-key ~/.config/relic/identity/id_ed25519 \
  --analyst-key-passphrase-file ~/.config/relic/identity/passphrase \
  --output signed-manifest.json

rm -f ~/.config/relic/identity/passphrase
```

The signer verifies the exact FIDBF bytes against the manifest before signing,
and the output contains no private material or local object path. See
[FIDBF submission boundary](workers.md#fidbf-submission-boundary).
