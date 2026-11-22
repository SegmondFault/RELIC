# RELIC API

## Roles (RBAC)

Every application identity is a row in `catalogue.user_public` with one
permanent Ed25519 public key. Human accounts have exactly one role
(`account_role`).

| Role | Capabilities |
|---|---|
| Viewer | Read catalogue data and submit signed flags |
| Analyst | Submit signed corpus objects, classifications and flag responses; request revocations |
| Moderator | Review registrations and approve/reject revocation requests |
| Infrastructure admin | Operate PostgreSQL/server; not a RELIC application identity |

### Rules

- **Roles are exclusive, not ranked.** The database checks for an exact role,
  so a moderator cannot submit corpus data and an analyst cannot raise a flag.
- **System accounts** (`owner_type = 'system'`, no role) belong to the
  integrity and MMR workers. They sign chain entries and checkpoints and cannot
  use any route.
- **Infrastructure admins** have server access but no RELIC identity. Server
  access never lets anyone sign as a user.
- **Revoked accounts** keep their history but cannot sign anything new.
  Revocation happens through the revocation routes, not by deleting rows.
- **A login does not authorise a write; the signature does.** A session token
  only decides which routes a caller can reach. Every signed write carries the
  claimed User ID and a signature. The server must verify that signature with
  the key registered for *that* User ID, over the operation's versioned,
  domain-separated canonical bytes, inside the same transaction as the insert.
  Keys supplied in the request are never trusted.

## Endpoints

Application routes live under `/v1`. List routes accept `limit` (1–500,
default 100) and `offset` (≥ 0).

**Legend:** *Any* = any active human account. *Signed* = the body carries an
Ed25519 signature verified against the claimed user's registered key.

### Health

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/healthz` | none | Liveness probe. Returns `{"status": "ok"}`. Not versioned. |

### Authentication and accounts

There are no passwords. A user proves possession of their registered Ed25519
key by signing a single-use server challenge; message formats are specified in
[`docs/authentication.md`](../../docs/authentication.md), and
`relic-sign-challenge` (in `crates/relic-ingest`) produces the signed bodies.

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/auth/challenge` | none | Issue a single-use challenge (`purpose`: `login` or `registration`). Expires after `RELIC_CHALLENGE_TTL_SECONDS` (default 120 s). Bound to no account, so it reveals nothing about which accounts exist. |
| `POST` | `/v1/auth/login` | none | `{challenge_id, public_key, signature}`: exchange a signed login challenge for a bearer token (HS256, `RELIC_JWT_TTL_SECONDS`, default 8 h). The account is found by its public key; `/v1/me` returns the User ID. Without a valid signature every failure is the same `401`; with one, a pending or rejected registration or a revoked account is reported as `403`. Only active human accounts get a token. |
| `GET` | `/v1/me` | Any | The caller's User ID, role, owner type and public key. |
| `POST` | `/v1/accounts` | none | Submit a registration request: the applicant's own public key, account details and a signature over a registration challenge (proof of possession). Returns `202 Accepted`; the request stays pending until a moderator signs an approval. RELIC never generates or receives private keys. |
| `GET` | `/v1/registrations` | Moderator | Registration requests, oldest first. `status` = `pending` (default), `approved` or `rejected`. Includes name, organisation and email, which no other route exposes. |
| `GET` | `/v1/registrations/{id}` | Moderator | One request, in the exact shape `relic-sign-challenge decide-registration` signs. |
| `POST` | `/v1/registrations/{id}/decision` | Moderator · Signed | Approve or reject a pending request: `{moderator_id, decision, signature}`. `moderator_id` must be the caller. The signature covers the stored request and the verdict. Approval creates the account and returns its `user_id`. Final: a second decision is `409`. |

Every authenticated request re-reads the account, so an approved revocation
invalidates live tokens immediately. Challenges are consumed before the
signature is checked: a failed attempt cannot be retried with the same
challenge.

**Rate limits** (per client address, per process): 10 challenge or login
requests per minute, 5 registrations per hour, 300 requests per minute
overall. Exceeding them returns `429` with `Retry-After`.

### Catalogue (read)

All `GET`, all *Any* role: a valid bearer token is required. Implemented so
far: `/v1/users`, `/v1/users/{user_id}` and the revocation reads; the rest
return `501`.

| Path | Returns |
|---|---|
| `/v1/users`, `/v1/users/{user_id}` | Public identity: User ID, role, owner type, public key (hex), created-at and whether the account is revoked. Never name, email or organisation. |
| `/v1/sources`, `/v1/sources/{id}` | Where binaries and objects came from, including the ecological/artificial flag. |
| `/v1/batches`, `/v1/batches/{id}` | Signed batches covering binary and function records. |
| `/v1/binaries`, `/v1/binaries/{id}` | Binary metadata and SHA-256/MD5. Binary bytes are never stored. |
| `/v1/functions`, `/v1/functions/{id}` | Functions within a binary, with FID full/specific hashes. |
| `/v1/fidbf`, `/v1/fidbf/{id}` | FIDBF object metadata: hashes, submitter, signature. |
| `/v1/fidbf/{id}/download` | The FIDBF object itself. |
| `/v1/bsim`, `/v1/bsim/{id}` | BSim similarity objects. |
| `/v1/function-bsim` | Which functions each BSim object describes. |
| `/v1/provenance`, `/v1/provenance/{id}` | OCSF-style provenance seals and build recipes. |
| `/v1/license-assertions`, `/v1/license-assertions/{id}` | Signed SPDX licence claims on one source or one binary. |
| `/v1/classifications`, `/v1/classifications/{id}` | Signed labels on binaries, functions or behavioural compositions. |
| `/v1/flags`, `/v1/flags/{id}` | Viewer flags on catalogue objects. |
| `/v1/flag-responses` | Analyst responses to flags. |
| `/v1/revocations`, `/v1/revocations/{id}` | Revocation requests and moderator decisions (implemented, see Revocations). |
| `/v1/integrity`, `/v1/integrity/{id}` | The append-only, system-signed integrity chain (integer IDs). |
| `/v1/mmr-checkpoints`, `/v1/mmr-checkpoints/{id}` | Signed Merkle Mountain Range checkpoints over the chain (integer IDs). |
| `/v1/mmr-checkpoints/latest` | The newest checkpoint. |

### Corpus submissions

Each returns `201 Created`. Each is atomic: the object, its related rows and
its integrity-chain entry commit together or not at all. An identical retry
returns the original result; the same ID with different content is a conflict.

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/sources` | Analyst · Signed | Register a source. |
| `POST` | `/v1/batches` | Analyst · Signed | Submit a batch of binary and function records. |
| `POST` | `/v1/fidbf` | Analyst · Signed | Admit a FIDBF object together with its source, batch, binary, functions and integrity entry. Reference implementation: `crates/relic-ingest`. |
| `POST` | `/v1/bsim` | Analyst · Signed | Admit a BSim object and its function links. |
| `POST` | `/v1/provenance` | Analyst · Signed | Submit a provenance seal (a JSON object). The server re-checks its hashes and keeps `unmapped.relic` intact. |
| `POST` | `/v1/license-assertions` | Analyst · Signed | Claim an SPDX licence for one source or binary. Immutable: corrections are a new assertion plus a revocation. |
| `POST` | `/v1/classifications` | Analyst · Signed | Label a binary, function or behavioural composition. |

### Flags

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/flags` | Viewer · Signed | Flag any catalogue object with a note. |
| `POST` | `/v1/flags/{flag_id}/responses` | Analyst · Signed | Respond to a flag. A flag can have many responses. |

### Revocations

Implemented. Signed formats: [`docs/authentication.md`](../../docs/authentication.md#revocation-request);
`relic-sign-challenge request-revocation` and `decide-revocation` produce the bodies.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/v1/revocations` | Any | Requests and decisions, oldest first. Filters: `status` (`pending`, `approved`, `rejected`), `target_type`, `target_id`. Both signatures are returned as hex for offline re-verification. |
| `GET` | `/v1/revocations/{id}` | Any | One request, in the exact shape `decide-revocation` signs. |
| `POST` | `/v1/revocations` | Analyst · Signed | `{revocation_id, analyst_id, target_type, target_id, reason, signature}`: request revocation of a catalogue object, or of an account (`target_type = user`). `analyst_id` must be the caller; `revocation_id` is a fresh UUID chosen by the client. `201` created; `200` identical retry; `403` bad signature; `409` ID reused with other content, target already has an open request, or target already revoked; `422` unknown target. |
| `POST` | `/v1/revocations/{id}/decision` | Moderator · Signed | `{moderator_id, decision, signature}`: approve or reject a pending request. `moderator_id` must be the caller; never for the Moderator's own account (`403`). Final: a second decision is `409`. An approved account revocation blocks that account's tokens and logins immediately. |

Nothing is deleted. A revoked object or account remains visible, marked as
revoked.
