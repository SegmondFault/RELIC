# Authentication, registration and revocation

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
burns it. `audience` binds the proof to one deployment. The request names only
the `purpose` (`login` or `registration`): a challenge is bound to no account,
so issuing one reveals nothing about which keys or accounts exist.

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
- fields: common challenge fields, then `public_key` (32 bytes)
- `POST /v1/auth/login` with `{challenge_id, public_key, signature}`

The client identifies itself by its public key, which is unique across all
accounts; `GET /v1/me` returns the User ID afterwards. The API checks, in
order:

1. The challenge is a live, unused login challenge (it is consumed either way).
2. The signature verifies under the **submitted** public key. This happens
   before any account lookup, so without the private key every failure (unknown
   key, wrong signature, spent challenge) is the same `401` on the same path.
3. Only then is the key looked up. Because the caller has proven possession,
   the API can tell them about their own state: `403 Registration is pending
   approval`, `403 Registration was rejected` or `403 Account has been revoked`.
   An unknown key or a system account is `401`.

An active human account gets a bearer token. The account is re-checked on
every request.

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

### Revocation request

- `D = RELIC:revocation-request:v1`, `S = RELIC:revocation-request-signature:v1`
- fields: `revocation_id`, `analyst_id` (both UUID bytes), `target_type`
  (a `corpus_target_type` value, e.g. `user` or `fidbf`), `target_id`, `reason`
- `POST /v1/revocations` with those values plus `signature`

Only an active Analyst can request, and `analyst_id` must be the caller. The
API verifies the signature with the key registered for `analyst_id`, never a
key from the request. There is no challenge: the Analyst chooses
`revocation_id` (a fresh UUID) and signs it, and it is the row's primary key,
so a signed request is stored at most once. An identical retry returns the
stored request (`200`); the same ID with different content is `409`.

The database allows one open request per target and refuses a request for a
target that is already revoked (both `409`). A rejected target can be
requested again. The requester must be an active Analyst when filing; the
request stays decidable if they are revoked afterwards, so a revoked requester
cannot block a target. System accounts (the integrity and MMR workers) cannot
be revoked through the API (`403`): revoking one stops admissions and
checkpoints, so only the database operator (`relic_owner`) can do it. Revoking an account (`target_type = user`) is how a lost or
compromised key is handled: the next request with its token is `401`, and
login reports `403 Account has been revoked`.

### Revocation decision

- `D = RELIC:revocation-decision:v1`, `S = RELIC:revocation-decision-signature:v1`
- fields: the five request fields as stored, then `moderator_id`, `decision`
  (`approved` or `rejected`)
- `POST /v1/revocations/{id}/decision` with `{moderator_id, decision, signature}`

As with registrations, the Moderator signs exactly what they reviewed
(`GET /v1/revocations/{id}`) and their verdict, `moderator_id` must be the
caller, and the API verifies with that Moderator's registered key over the
stored row in the same transaction as the update. The database re-checks that
the decider is an active Moderator,
forbids a Moderator deciding the revocation of their own account, sets
`decided_at` from its own clock, and makes the decision final. Anyone logged in
can read revocations and re-verify both signatures from the row.

## Client

Generate a key used only for RELIC, and build the signer:

```bash
ssh-keygen -t ed25519 -a 100 -C relic -f ~/.ssh/relic_ed25519
cargo build --release -p relic-ingest
```

The signer has no passphrase prompt yet: for an encrypted key pass
`--key-passphrase-file <file>` (mode `0600`) to each command below.

**Register** (applicant):

```bash
curl -s -X POST https://$HOST/v1/auth/challenge \
     -H 'content-type: application/json' -d '{"purpose":"registration"}' > challenge.json
target/release/relic-sign-challenge register --challenge challenge.json \
     --key ~/.ssh/relic_ed25519 --role analyst --name "Ada Lovelace" \
     --email ada@example.org [--organisation "..."] > register.json
curl -s -X POST https://$HOST/v1/accounts \
     -H 'content-type: application/json' -d @register.json
```

**Log in** (anyone with a key; the same command tells an applicant whether
their request is still pending or was rejected):

```bash
curl -s -X POST https://$HOST/v1/auth/challenge \
     -H 'content-type: application/json' -d '{"purpose":"login"}' > challenge.json
target/release/relic-sign-challenge login --challenge challenge.json \
     --key ~/.ssh/relic_ed25519 > login.json
TOKEN="$(curl -s -X POST https://$HOST/v1/auth/login \
     -H 'content-type: application/json' -d @login.json | jq -r .access_token)"
curl -s -H "authorization: Bearer $TOKEN" https://$HOST/v1/me    # your user_id and role
```

**Decide a registration** (Moderator, after logging in as above). The tool
prints what it is about to sign on stderr and refuses a request that is no
longer pending:

```bash
MODERATOR_ID="$(curl -s -H "authorization: Bearer $TOKEN" https://$HOST/v1/me | jq -r .user_id)"
curl -s -H "authorization: Bearer $TOKEN" https://$HOST/v1/registrations    # pending requests
curl -s -H "authorization: Bearer $TOKEN" \
     https://$HOST/v1/registrations/$REQUEST_ID > request.json
target/release/relic-sign-challenge decide-registration --request request.json \
     --moderator-id "$MODERATOR_ID" --decision approved \
     --key ~/.ssh/relic_ed25519 > decision.json
curl -s -X POST https://$HOST/v1/registrations/$REQUEST_ID/decision \
     -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d @decision.json
```

**Request a revocation** (Analyst, logged in as above; `$ANALYST_ID` from
`/v1/me`). Keep the printed body: resending it unchanged is a safe retry.

```bash
target/release/relic-sign-challenge request-revocation --analyst-id "$ANALYST_ID" \
     --target-type user --target-id "$TARGET_ID" --reason "Key reported lost" \
     --key ~/.ssh/relic_ed25519 > revocation.json
curl -s -X POST https://$HOST/v1/revocations \
     -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d @revocation.json
```

**Decide a revocation** (Moderator):

```bash
curl -s -H "authorization: Bearer $TOKEN" "https://$HOST/v1/revocations?status=pending"
curl -s -H "authorization: Bearer $TOKEN" \
     https://$HOST/v1/revocations/$REVOCATION_ID > revocation.json
target/release/relic-sign-challenge decide-revocation --request revocation.json \
     --moderator-id "$MODERATOR_ID" --decision approved \
     --key ~/.ssh/relic_ed25519 > decision.json
curl -s -X POST https://$HOST/v1/revocations/$REVOCATION_ID/decision \
     -H "authorization: Bearer $TOKEN" -H 'content-type: application/json' \
     -d @decision.json
```
