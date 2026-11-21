# Authentication and registration

RELIC has no passwords. Every human account is an Ed25519 public key, and
authentication is proof of possession of the matching private key over a
single-use challenge. The private key never leaves the user's machine.

The canonical formats below are defined in `crates/relic-crypto/src/auth.rs`.
The Python API re-implements them in `database/api/crypto.py` and is pinned to
`crates/relic-crypto/tests/vectors/auth-v1.json`; both test suites fail if
either side diverges. Any change to a field, its order or encoding, or a
domain tag requires a `v2` and new vectors.

## Challenges

`POST /v1/auth/challenge` returns:

```json
{
  "challenge_id": "d30e2223-43ac-4b1f-adec-e2cbbb901837",
  "purpose": "login",
  "nonce": "<32 random bytes, hex>",
  "audience": "https://relic.example.org",
  "expires_at": "2026-11-19T22:53:17.465769Z",
  "expires_at_unix_micros": 1795128797465769
}
```

The database (`catalogue.auth_challenge`, migration 008) guarantees that a
challenge is consumed at most once and never after `expires_at`. The API
consumes the challenge *before* checking the signature, so a failed attempt
burns it. `audience` binds the proof to one deployment.

## Encoding

Every signature uses the RELIC primitive:

```
record    = u64be(len(D)) || D || for each field: u64be(len(f)) || f
digest    = SHA-256(record)
message   = u64be(len(S)) || S || digest
signature = Ed25519(private_key, message)
```

`D` is the record domain and `S` the signature domain. UUIDs are their 16 RFC
4122 bytes, integers are big-endian, text is UTF-8 exactly as submitted (the
API rejects rather than trims surrounding whitespace), and an optional text is
`0x00` when absent or `0x01 || bytes` when present.

Common challenge fields, in order: `challenge_id`, `nonce`, `audience`,
`expires_at_unix_micros` (i64).

### Login

- `D = RELIC:login-challenge:v1`, `S = RELIC:login-signature:v1`
- fields: common challenge fields, then `user_id`
- `POST /v1/auth/login` with `{challenge_id, user_id, signature}`

The challenge was issued for that `user_id`, the key is the one registered for
that `user_id` in `catalogue.user_public`, and the account must be an active
(non-revoked) human. The response is a bearer token. The account is re-checked
on every request.

### Registration

- `D = RELIC:registration-request:v1`, `S = RELIC:registration-proof-signature:v1`
- fields: common challenge fields, then `public_key` (32 bytes),
  `requested_role`, `name`, optional `organisation`, `email`
- `POST /v1/accounts` with those values plus `challenge_id` and `signature`

The signature proves the applicant holds the private key and binds every
detail they submitted. The result is a pending `catalogue.registration_request`,
not an account. System accounts and the first Moderator are created by the
database operator.

### Registration decision

- `D = RELIC:registration-decision:v1`, `S = RELIC:registration-decision-signature:v1`
- fields: `registration_request_id`, `public_key` (32 bytes), `requested_role`,
  `name`, optional `organisation`, `email`, `moderator_id`, `decision`
  (`approved` or `rejected`)
- `POST /v1/registrations/{id}/decision` with `{moderator_id, decision, signature}`

The Moderator signs exactly what they reviewed (`GET /v1/registrations/{id}`)
and their verdict. The API requires `moderator_id` to be the authenticated
account, verifies the signature with that Moderator's registered key over the
request row as stored, and records it through `catalogue.decide_registration()`
in the same transaction. That function is the only way the application can
create a human account; the database re-checks that the decider is an active
Moderator and that the decision is final. There is no challenge: the request
ID is unique and a decision can be recorded once, so a captured decision cannot
be replayed. Every field is stored in the row, so anyone can re-verify the
decision later without the API.

## Client

```bash
cargo build --release -p relic-ingest
curl -s -X POST https://$HOST/v1/auth/challenge \
     -H 'content-type: application/json' \
     -d "{\"purpose\":\"login\",\"user_id\":\"$USER_ID\"}" > challenge.json
target/release/relic-sign-challenge login --challenge challenge.json \
     --key ~/.ssh/relic_ed25519 --key-passphrase-file ~/.config/relic/passphrase \
     --user-id "$USER_ID" > login.json
curl -s -X POST https://$HOST/v1/auth/login \
     -H 'content-type: application/json' -d @login.json
```

`relic-sign-challenge register --role analyst --name ... --email ...
[--organisation ...]` produces the body for `POST /v1/accounts` the same way.

A Moderator decides a request like this (the tool prints what it is about to
sign on stderr and refuses a request that is no longer pending):

```bash
curl -s -H "authorization: Bearer $TOKEN" \
     https://$HOST/v1/registrations/$REQUEST_ID > request.json
target/release/relic-sign-challenge decide-registration --request request.json \
     --moderator-id "$MODERATOR_ID" --decision approved \
     --key ~/.ssh/relic_ed25519 > decision.json
curl -s -X POST https://$HOST/v1/registrations/$REQUEST_ID/decision \
     -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d @decision.json
```
