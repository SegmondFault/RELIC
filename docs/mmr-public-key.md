# RELIC MMR public key (pin)

This file is the reference for the public key that signs RELIC's MMR
checkpoints. A verifier of inclusion proofs checks every checkpoint against it,
not against a key served by the API. Why, and how to derive and check the key:
[`deployment.md`](deployment.md#pinning-the-mmr-public-key).

**Only the public key goes here.** The private key stays on the server in
`/var/lib/relic/keys` and is never copied, pasted or committed anywhere. A
public key can only check signatures, never create them.

Every installation generates its own key at setup, so this file is a place to
record the pin of one installation and the procedure to follow, not a key that
applies to every deployment. Leave the tables empty if you publish the pin
somewhere else (your own site, or directly to your partners).

## Current key

**Status: not published yet.** The operator fills this table in when the
production MMR key is created. Until then no verifier has anything to pin.

| Field | Value |
|---|---|
| MMR system user id | `NOT PUBLISHED YET` |
| Ed25519 public key (64 lowercase hex characters) | `NOT PUBLISHED YET` |
| Covers checkpoints | from checkpoint `NOT PUBLISHED YET` |
| Published on | `NOT PUBLISHED YET` |

## Past keys

Keep every key that ever signed a checkpoint: its checkpoints stay verifiable
only with it. Add a row when a key is replaced; never delete one.

| MMR system user id | Public key | Checkpoints it signed |
|---|---|---|
| (none yet) | | |

## Publishing or changing the key (operator)

Two people take part, so that one mistake or one person alone cannot slip a
wrong key in:

1. Person A derives the key on the server with the command in
   `deployment.md` and checks it matches `GET /v1/users/{MMR user id}`.
2. Person A opens a pull request that changes only this file.
3. Person B, who is not the author, derives the key **again on the server**
   (not by copying from the pull request), compares all 64 characters, and
   approves the pull request with a comment saying so.
4. Merge. For a replacement key, merge **before** its first checkpoint is
   created, and move the old key to "Past keys".

Any change to this file is a security event. If your team uses `CODEOWNERS`,
list this file in it so a change cannot be merged without the operators.

## Giving the key to a partner who verifies proofs

Send the user id and the key by a channel that is neither this API nor this
repository alone (in person, by a call, or an email you can trust), then
confirm over a second channel that both sides read the same value (for
example the first and last 8 characters aloud). The partner stores it and
passes it as `--public-key` on every verification. They should also watch
this file: a change they were not told about is a reason to stop and ask.
