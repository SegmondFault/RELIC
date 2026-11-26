# Publishing the RELIC MMR public key (pin)

A verifier of inclusion proofs checks every checkpoint against a *pin*: the
MMR system account's user id and Ed25519 public key, obtained from the
operator rather than from the API. Why, and how to derive and check the key:
[`deployment.md`](deployment.md#pinning-the-mmr-public-key).

This page is the procedure and the template; it records no key. Every
installation creates its own MMR key at setup, so a pin belongs on that
operator's own channel (their site, their configuration repository, a
document they send to partners), not in this shared repository.

**Only the public key is ever published.** The private key stays on the server
in `/var/lib/relic/keys` and is never copied, pasted or committed anywhere. A
public key can only check signatures, never create them.

## What to publish

```text
RELIC MMR pin:       <installation name>
MMR system user id:  <UUID>
Ed25519 public key:  <64 lowercase hexadecimal characters>
Published:           <date>, by <person A>, checked on the server by <person B>
Replaces:            <previous user id and key, and why: rotation or compromise> or "none"
```

Every field is known when the pin is published; none depends on checkpoints
that do not exist yet.

## Publishing or changing the pin (operator)

Two people take part, so that one mistake or one person alone cannot slip a
wrong key in:

1. Person A derives the key on the server with the command in
   `deployment.md` and checks it matches `GET /v1/users/{MMR user id}`.
2. Person A prepares the pin as a change that a second person must approve
   where it is published (a pull request on the configuration repository, a
   reviewed page edit).
3. Person B, who is not the author, derives the key **again on the server**
   (not by copying from the change), compares all 64 characters and the user
   id, and approves the change saying so.
4. Publish. For a new key, publish **before** its first checkpoint is created.

Any change of a published pin is a security event.

## Giving the pin to a partner who verifies proofs

Send the user id and the key by a channel that is neither the API nor a single
repository (in person, by a call, or an email you can trust), then confirm
over a second channel that both sides read the same value (for example the
first and last 8 characters aloud). The partner stores both and passes them as
`--public-key` and `--system-uid` on every verification. They should also
watch where the pin is published: a change they were not told about is a
reason to stop and ask.

## When the key changes

Every checkpoint covers the whole chain from its first entry, so the first
checkpoint signed by a new key also covers every entry admitted before it.
Nothing needs an old key to stay trusted: proofs are fetched again against a
checkpoint signed by the new key.

An old key pin must not simply be kept "for old checkpoints". A pin has no
expiry a verifier could enforce: a checkpoint's timestamp is signed by the
same key, so whoever obtains an old key can sign checkpoints dated in the
past, and a verifier cannot tell them from genuine ones. To re-check proofs
archived against an old key, pin the exact checkpoints instead: their
commitments, recorded while the key was trusted, passed with `--commitment`.

**Routine rotation** (the old key is not suspected):

1. Create a new MMR system account and key, and publish the new pin with the
   two-person check above, marked as replacing the old one by rotation.
2. Run `relic-checkpoint-mmr` with the new account and key. Publish, with the
   notice of the rotation, the old key's last checkpoint (`mmr_checkpoint_id`
   and `commitment`) for anyone holding proofs against it.
3. Revoke the old MMR system account (only the database operator, as
   `relic_owner`, can revoke a system account); the database then refuses any
   checkpoint it signs. Destroy the old private key, and its copies in the
   encrypted backups once those runs expire.
4. Verifiers replace the pin. To re-check a proof archived against an old
   checkpoint, they pass the old key together with that checkpoint's recorded
   commitment (`--commitment`), so only that exact checkpoint is accepted.

**Compromise** (the private key leaked, or may have):

1. Stop the timer, revoke the MMR system account so the database refuses
   anything it signs, and create a new account and key. Publish the new pin as
   replacing the old one **because of a compromise**, and tell every partner
   directly.
2. Run `relic-checkpoint-mmr` with the new key. It first re-verifies the
   newest stored checkpoint against the chain. If it refuses because that
   checkpoint diverges, a forged checkpoint was stored: keep the database as
   evidence and investigate before going on; do not delete the row.
3. Treat every checkpoint signed by the compromised key as untrusted, whatever
   its date. Verifiers drop the old pin and fetch proofs again against the new
   key's checkpoints. A `--commitment` recorded *before* the compromise may
   still be used, if that record is itself trusted.
4. Run `relic-verify` too. The integrity chain is signed by a different key,
   which the MMR key cannot replace, and the investigation should confirm the
   chain is intact.
