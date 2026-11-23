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

## Database logins

| Login | Used by | May write |
|---|---|---|
| `relic_owner` | Migrations and the database operator (NOLOGIN; reached with `SET ROLE`) | Everything. Owns the schema. Creates the first Moderator and system accounts, and is the only one allowed to revoke a system account. |
| `relic_app` | This API (`RELIC_DATABASE_URL`) | Inserts only what its routes write: challenges, registration requests, first approvals, revocations, flags and responses, licence assertions and classifications; each further submission route grants its own table. New tables are read-only for it by default. Accounts only through `decide_registration()`. Never the integrity chain or MMR checkpoints; cannot read contact details. No `DELETE` anywhere. |
| `relic_worker` | `relic-ingest-fidbf`, `relic-chain-bsim`, `relic-checkpoint-mmr` | Appends only: FIDBF admissions (source, batch, binary, FIDBF, functions) and system-signed integrity entries and checkpoints. Reads catalogue data, never contact details, registration requests or login challenges. |
| `relic_auditor` | `relic-verify` (e.g. from cron) | Nothing; read-only transactions by default. Reads everything it re-verifies (including registration requests and their challenges), never `user_private`. |

The database checks who a row names and its shape, not its signature. Only the
workers, which hold the system keys, may append system-signed evidence; for
user-signed rows the API is trusted to verify, and `relic-verify` re-checks
them afterwards.
`tests/test_database_roles.py` pins both privilege sets.

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
| `GET` | `/v1/registrations/{id}` | Moderator | One request, in the exact shape `relic-sign-challenge decide-registration` signs, with `approvals_required` and the first `approvals` so far. |
| `POST` | `/v1/registrations/{id}/decision` | Moderator · Signed | Approve or reject a pending request: `{moderator_id, decision, signature}`. `moderator_id` must be the caller. The signature covers the stored request and the verdict. Approval creates the account and returns its `user_id`. **A Moderator registration needs two different Moderators:** the first approval is stored and answered `202 {status: "awaiting_second_approval", approvals}`; the same Moderator again is `409`; the second approval creates the account. One rejection is final. Final: a second decision is `409`. |

Every authenticated request re-reads the account, so an approved revocation
invalidates live tokens immediately. Challenges are consumed before the
signature is checked: a failed attempt cannot be retried with the same
challenge.

**Rate limits** (per client address, per process): 10 challenge or login
requests per minute, 5 registrations per hour, 300 requests per minute
overall. Exceeding them returns `429` with `Retry-After`.

### Catalogue (read)

All `GET`, all *Any* role: a valid bearer token is required. All routes below
are implemented except `/v1/fidbf/{id}/download` (`501` until object storage is
designed).

**Conventions**

- **Cursor paging.** Lists are ordered by primary key; request the next page
  with `after=<last id of this page>` and `limit` (1–500, default 100). An
  empty page is the end. No totals are returned. (`/v1/users`,
  `/v1/registrations` and `/v1/revocations` still use `limit`/`offset`.)
- **Encoding.** Signatures and keys are lowercase hex; digests exactly as
  stored. `NUMERIC(20,0)` addresses (`entry_point`, `image_base`,
  `virtual_address`) and `NUMERIC(5,4)` confidences are decimal **strings**,
  so no client loses precision above 2^53.
- **`revoked`** is `true` when an approved revocation targets that exact
  object. It is not inherited: functions of a revoked FIDBF are not marked.
- **Not returned:** internal `storage_path` values, ever. Large JSON
  (`object_data` of BSim and provenance, classification `evidence`) only on
  the single-object route; provenance lists show `has_object_data`.
- Signatures are returned as stored and are **not re-verified** by these
  routes. The database only accepts 64-byte signatures; checking one needs the
  signer's key from `/v1/users/{id}` and the canonical bytes.

| Path | Filters | Returns |
|---|---|---|
| `/v1/users`, `/v1/users/{user_id}` | — | Public identity: User ID, role, owner type, public key (hex), created-at and whether the account is revoked. Never name, email or organisation. |
| `/v1/sources`, `/v1/sources/{id}` | — | Where binaries and objects came from, including the ecological/artificial flag. |
| `/v1/batches`, `/v1/batches/{id}` | — | Signed batches covering binary and function records. |
| `/v1/binaries`, `/v1/binaries/{id}` | `batch_id`, `source_id`, `sha256`, `md5` | Binary metadata and SHA-256/MD5. Binary bytes are never stored. |
| `/v1/functions`, `/v1/functions/{id}` | `binary_id`, `fidbf_id` | Functions within a binary, with FID full/specific hashes. |
| `/v1/fidbf`, `/v1/fidbf/{id}` | `binary_id`, `source_id`, `sha256` | FIDBF object metadata: hashes, submitter, signature. |
| `/v1/fidbf/{id}/download` | — | The FIDBF object itself (`501`). |
| `/v1/bsim`, `/v1/bsim/{id}` | `source_id`, `sha256` | BSim similarity objects; `object_data` on `/{id}` only. |
| `/v1/function-bsim` | `function_id`, `binary_id`, `bsim_id` | Which functions each BSim object describes. |
| `/v1/provenance`, `/v1/provenance/{id}` | `source_id`, `fidbf_id`, `bsim_id`, `binary_id` | OCSF-style provenance seals; `object_data` on `/{id}` only. |
| `/v1/license-assertions`, `/v1/license-assertions/{id}` | `source_id`, `binary_id` | Signed SPDX licence claims on one source or one binary, with `target_type` and `target_id` as signed. |
| `/v1/classifications`, `/v1/classifications/{id}` | `target_type`, `target_id` | Signed labels on binaries, functions or behavioural compositions; `evidence` and the signed `evidence_json` on `/{id}` only. |
| `/v1/flags`, `/v1/flags/{id}` | `target_type`, `target_id` | Viewer flags on objects, accounts, flags or responses, in the exact shape `respond-flag` signs. |
| `/v1/flag-responses`, `/v1/flag-responses/{id}` | `flag_id` | Analyst responses to flags. |
| `/v1/revocations`, `/v1/revocations/{id}` | see Revocations | Revocation requests and moderator decisions. |
| `/v1/integrity`, `/v1/integrity/{id}` | `source_id` | The append-only, system-signed integrity chain, in insertion order (integer IDs, `after` is an integer). |
| `/v1/mmr-checkpoints`, `/v1/mmr-checkpoints/{id}` | — | Signed Merkle Mountain Range checkpoints over the chain (integer IDs). |
| `/v1/mmr-checkpoints/latest` | — | The checkpoint covering the most integrity rows; `404` before the first. |

Software components, releases, binary-component assertions and behavioural
compositions have no read routes yet.

### Corpus submissions

Each returns `201 Created`. Each is atomic: the object, its related rows and
(for sources, batches, FIDBF, BSim and provenance) its integrity-chain entry
commit together or not at all. An identical retry returns the original result
(`200`); the same ID with different content is a conflict (`409`).

Licence assertions and classifications are implemented. Signed formats:
[`docs/authentication.md`](../../docs/authentication.md#licence-assertion);
`relic-sign-challenge assert-license` and `classify` produce the bodies. The
other submission routes return `501` until integrity-key custody and object
storage are decided.

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/sources` | Analyst · Signed | Register a source. |
| `POST` | `/v1/batches` | Analyst · Signed | Submit a batch of binary and function records. |
| `POST` | `/v1/fidbf` | Analyst · Signed | Admit a FIDBF object together with its source, batch, binary, functions and integrity entry. Reference implementation: `crates/relic-ingest`. |
| `POST` | `/v1/bsim` | Analyst · Signed | Admit a BSim object and its function links. |
| `POST` | `/v1/provenance` | Analyst · Signed | Submit a provenance seal (a JSON object). The server re-checks its hashes and keeps `unmapped.relic` intact. |
| `POST` | `/v1/license-assertions` | Analyst · Signed | `{license_assertion_id, analyst_id, target_type (source\|binary), target_id, spdx_expression, basis, confidence?, evidence_provenance_id?, signature}`: claim an SPDX licence. `confidence` has exactly four decimals. Immutable: corrections are a new assertion plus a revocation. `403` bad signature; `409` ID reused or target revoked; `422` invalid expression, unknown target or evidence. |
| `POST` | `/v1/classifications` | Analyst · Signed | `{classification_id, analyst_id, target_type (binary\|function\|behavioural_composition), target_id, label, confidence?, misp_universe?, misp_uuid?, evidence_json?, signature}`: label one object. `evidence_json` is a JSON object as a string, signed and stored verbatim (the parsed `evidence` is stored too). Immutable. Same status codes. |

### Flags

| Method | Path | Role | Description |
|---|---|---|---|
Implemented. Signed formats: [`docs/authentication.md`](../../docs/authentication.md#flag);
`relic-sign-challenge flag` and `respond-flag` produce the bodies. A flag has
no status: Analysts answer it, and act on it by requesting a revocation of its
target (or of the flag). Flags and responses are append-only.

| Method | Path | Role | Description |
|---|---|---|---|
| `POST` | `/v1/flags` | Viewer · Signed | `{flag_id, viewer_id, target_type, target_id, note, signature}`: flag a catalogue object, an account, a flag or a flag response. `viewer_id` must be the caller; `flag_id` is a fresh UUID chosen by the client. `201` created; `200` identical retry; `403` bad signature; `409` ID reused with other content, target already flagged by this Viewer, or target revoked; `422` unknown target. |
| `POST` | `/v1/flags/{flag_id}/responses` | Analyst · Signed | `{flag_response_id, analyst_id, note, signature}`, signed over the flag as stored and the response. A flag can have many responses. `201`; `200` identical retry; `403` bad signature; `404` unknown flag; `409` ID reused with other content, or the flag is revoked. |

### Revocations

Implemented. Signed formats: [`docs/authentication.md`](../../docs/authentication.md#revocation-request);
`relic-sign-challenge request-revocation` and `decide-revocation` produce the bodies;
`decide-revocation` verifies the stored request with the requester's registered
key and shows the target before it signs.

| Method | Path | Role | Description |
|---|---|---|---|
| `GET` | `/v1/revocations` | Any | Requests and decisions, oldest first. Filters: `status` (`pending`, `approved`, `rejected`), `target_type`, `target_id`. Both signatures are returned as hex for offline re-verification. |
| `GET` | `/v1/revocations/{id}` | Any | One request, in the exact shape `decide-revocation` signs, with `approvals_required` and the first `approvals` so far. |
| `POST` | `/v1/revocations` | Analyst · Signed | `{revocation_id, analyst_id, target_type, target_id, reason, signature}`: request revocation of a catalogue object, or of an account (`target_type = user`). `analyst_id` must be the caller; `revocation_id` is a fresh UUID chosen by the client. `201` created; `200` identical retry; `403` bad signature or a system account as target (operator only); `409` ID reused with other content, target already has an open request, or target already revoked; `422` unknown target. |
| `POST` | `/v1/revocations/{id}/decision` | Moderator · Signed | `{moderator_id, decision, signature}`: approve or reject a pending request. `moderator_id` must be the caller; never for the Moderator's own account (`403`). Final: a second decision is `409`. Stays decidable if the requesting Analyst has since been revoked. **Revoking a Moderator account needs two different Moderators** (neither the target): the first approval is answered `202`, the second revokes; one rejection is final. An approved account revocation blocks that account's tokens and logins immediately. |

Nothing is deleted. A revoked object or account remains visible, marked as
revoked.
