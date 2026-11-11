# Checkpoint-qualified Bloom filters

> **Status:** reviewed design and synthetic reference target only. No production
> worker, publication registry, HTTP endpoint or database integration exists.
> PostgreSQL remains authoritative. This document must not be read as a claim
> that Bloom-filter acceleration is production ready.

## Decision

RELIC may publish immutable, content-addressed Bloom-filter artifacts as a
disposable read accelerator for exact-value membership questions. A filter is
valid only for one named value namespace and one exact, verified MMR
checkpoint.

The result contract is deliberately asymmetric:

- **definitely absent at checkpoint** means the value was not in that namespace
  at the exact checkpoint named by the verified manifest;
- **possibly present at checkpoint** is a probabilistic answer and requires an
  authoritative PostgreSQL lookup or other authoritative confirmation; and
- **unknown** means no verified filter covers the requested namespace and
  checkpoint. It must never be rewritten as absent.

A Bloom filter is not evidence, a cryptographic non-membership proof, an MMR
inclusion proof, an authorization decision, a uniqueness constraint, an
admission decision or a replacement for the integrity chain. A positive result
must never reject a legitimate submission because false positives are expected.
Database constraints remain responsible for uniqueness even after a negative
filter result.

## Intended uses

The filters are useful only for repeated exact-equality probes where most
values are absent. Expected uses are:

- avoid unnecessary database work before an exact object/hash lookup;
- let a read-only API answer checkpoint-pinned negative membership probes;
- let analytical clients download and memory-map a checkpoint-pinned filter;
- cheaply pre-screen large comparison sets before authoritative joins; and
- measure corpus overlap without sending every negative candidate to
  PostgreSQL.

They do not perform BSim similarity search, approximate function matching,
classification, provenance validation or substring/prefix search.

## Separate namespaces

Every namespace has a separate filter, manifest, false-positive budget and
publication lifecycle. Combining unlike values would lose type meaning,
increase saturation and make a positive answer ambiguous.

| Namespace | Canonical value | Initial recommendation |
| --- | --- | --- |
| `binary-sha256` | 32 bytes decoded from `binary_record.content_sha256` | Build |
| `function-full-hash` | 8 bytes decoded from the canonical 16-character lowercase hexadecimal FID hash | Build |
| `function-specific-hash` | 8 bytes decoded from the canonical 16-character lowercase hexadecimal FID hash | Build |
| `bsim-sha256` | 32 bytes decoded from `bsim.sha256`, which covers the agreed canonical BSim JSON serialization | Build |
| `fidbf-sha256` | 32 bytes decoded from `fidbf.sha256` | Build |
| `provenance-sha256` | 32 bytes decoded from `provenance.sha256` | Build when provenance lookup is exposed |
| `batch-content-sha256` | 32 bytes decoded from `batch.content_sha256` | Optional; build only if batch-manifest lookup is a measured use case |

MD5 values, UUID primary keys, signatures, MMR commitments, integrity-chain
hashes and relationship-table identifiers are excluded. MD5 is compatibility
metadata, UUIDs already have efficient exact indexes, and MMR/integrity values
have dedicated verification paths.

### Canonical input bytes

The builder and consumers must reject a value that does not satisfy its
namespace grammar. They must not trim, case-fold or guess an encoding.

- SHA-256 namespaces accept exactly 64 lowercase hexadecimal characters and
  decode them to 32 bytes.
- Function-hash namespaces accept exactly 16 lowercase hexadecimal characters
  and decode them to 8 bytes in displayed byte order.
- A future change in lexical form or byte order creates a new namespace/version;
  it is not a transparent parser change.

Duplicate rows are expected, especially for function hashes. Insertion is
idempotent. `entry_count` records all covered rows and `unique_value_count`
records distinct canonical values. Sizing uses `unique_value_count`. The build
must obtain exact counts through an authoritative distinct stream or equivalent
exact external sort; an approximate cardinality estimate cannot establish the
advertised false-positive bound.

## Domain-separated hashing

Version 1 uses the existing RELIC length-prefixed field encoding and SHA-256.
The filter index digest is:

```text
SHA-256(encode_fields(
  "relic-bloom-index-v1",
  [namespace, canonical_value]
))
```

The first and second 128-bit halves provide `h1` and `h2`. The `i`th bit index
is calculated with deterministic double hashing:

```text
(h1 + i * h2) mod bit_count, for i in 0..hash_function_count
```

An implementation must specify the exact integer byte order, modular reduction
and zero-step handling in golden vectors before format version 1 can be
admitted. The reference design uses unsigned big-endian integers and replaces a
zero reduced step with one. The namespace is inside the hashed input as well as
the manifest, so the same bytes cannot silently cross namespaces.

An unkeyed cryptographic hash is intentional: independently rebuilt filters
must be byte-identical. The artifact is an optimization, not a security
primitive. Changing the hash construction requires a new format version and
new vectors.

## Append-only and revocation semantics

Version 1 answers **historical admission membership**. It includes every value
admitted on or before the covered checkpoint. A later approved revocation does
not clear bits and does not make the historical admission disappear.

This matches RELIC's append-only evidence model and avoids pretending that a
Bloom filter supports deletion. If an active/non-revoked population becomes a
real use case, it must use a separately named namespace such as
`binary-sha256-active-v1` and be rebuilt from an exact checkpoint snapshot.
Active and historical filters must never share a manifest or result label.

## Relationship to integrity and the MMR

The integrity chain remains the authoritative sequence of admitted evidence.
The MMR checkpoint commits to an exact prefix of that chain. A Bloom artifact
is a derived projection over values visible at that checkpoint:

```text
authoritative rows -> signed integrity chain -> signed MMR checkpoint
                                              -> derived Bloom artifact
```

The Bloom manifest binds the artifact to `checkpoint_id`,
`integrity_chain_head` and `mmr_leaf_count`. A consumer verifies those fields
against the signed checkpoint before using the filter. The MMR does not prove
that a Bloom bitset was constructed correctly; correctness comes from
deterministic rebuilds, qualification tests, the artifact digest and the
separate system signature.

If an MMR proof and Bloom result disagree, the authoritative chain/MMR wins and
the Bloom artifact is quarantined. A delayed or unavailable Bloom artifact has
no effect on admission or integrity.

The current schema does not map each individual function/object value directly
to an integrity ordinal. Therefore the first builder may publish only from a
repeatable-read snapshot in which the selected verified MMR checkpoint covers
the current integrity tip. This makes every authoritative row visible in that
snapshot covered by the checkpoint. Historical checkpoint rebuilds and true
incremental layers require a reviewed admission-to-integrity change stream or
equivalent durable mapping; they must not infer coverage from timestamps.

## Filter organization

### Version-1 choice: immutable partitioned snapshots

Version 1 should publish one immutable generation per namespace at selected
MMR checkpoints. Each generation is partitioned by the first byte of the
canonical value into 256 deterministic shards. A query visits exactly one
shard.

Each shard is a standard Bloom filter sized from its exact distinct count and
the generation's common target false-positive probability. Empty shards are
represented explicitly. The payload stores shards in byte-prefix order, which
allows parallel construction and deterministic concatenation while keeping a
single downloadable, memory-mappable artifact.

This choice is preferred initially because it offers:

- a simple checkpoint/set meaning;
- deterministic complete rebuilds;
- atomic immutable publication;
- parallel construction without query-time fan-out across all shards; and
- bounded reader complexity.

### Alternatives not selected for version 1

- **One unpartitioned standard filter:** simplest, but a 300-million-value
  function filter is a large serial build and a coarse download/rebuild unit.
- **Mutable standard filter:** cheap incremental writes, but cannot give an
  immutable checkpoint artifact and is vulnerable to partial/crashed updates.
- **Counting/Cuckoo filter:** supports deletion, which historical membership
  does not need; counters add storage and a larger mutation surface.
- **Scalable/layered Bloom filter:** avoids full rebuilds by querying a base plus
  immutable deltas. It also increases query work and requires an explicit
  per-layer false-positive budget whose sum stays below the advertised bound.

Layered filters remain a possible format version 2 after real-corpus build-time
and checkpoint-cadence measurements. A future design should use immutable base
and delta layers, geometric capacities, a bounded aggregate probability and
periodic deterministic compaction. It must not silently change version-1
payload semantics.

## Sizing

For `n` distinct values and target false-positive probability `p`, the ideal
standard Bloom-filter values are:

```text
m = ceil(-n * ln(p) / (ln(2)^2)) bits
k = round((m / n) * ln(2)) hash-derived bit indexes
```

The following figures exclude headers, shard tables, alignment and manifest
overhead. Partition rounding adds a small amount. They are **per namespace**.

| Distinct values | Target `p` | Bits/value | `k` | Payload estimate |
| ---: | ---: | ---: | ---: | ---: |
| 3,000,000 | `1e-4` | 19.17 | 13 | 6.86 MiB |
| 30,000,000 | `1e-4` | 19.17 | 13 | 68.56 MiB |
| 300,000,000 | `1e-4` | 19.17 | 13 | 685.58 MiB |
| 3,000,000 | `1e-6` | 28.76 | 20 | 10.28 MiB |
| 30,000,000 | `1e-6` | 28.76 | 20 | 102.84 MiB |
| 300,000,000 | `1e-6` | 28.76 | 20 | 1,028.37 MiB |
| 3,000,000 | `1e-9` | 43.13 | 30 | 15.43 MiB |
| 30,000,000 | `1e-9` | 43.13 | 30 | 154.25 MiB |
| 300,000,000 | `1e-9` | 43.13 | 30 | 1,542.55 MiB |

`1e-6` is the proposed qualification default, not a production decision. It is
roughly one expected false positive per million negative probes while keeping a
300-million-value namespace near 1 GiB. Choosing `1e-9` adds roughly 50% more
memory and 50% more bit indexes than `1e-6`; that cost should be justified by
observed request volume and database-avoidance benefit. The five required
namespaces do not all have equal cardinality, so multiplying the largest line
by five is a conservative upper bound, not a forecast.

The realized probability should be calculated from actual `m`, `k` and unique
count:

```text
p_realized = (1 - exp(-k * n / m))^k
```

Publication fails if `p_realized` exceeds the manifest target.

## Versioned deterministic artifact

The binary payload is a little-endian-independent, memory-mappable format. All
integers are unsigned fixed-width big-endian. Version 1 fixes:

- eight-byte magic `RELICBF\0`;
- payload format version;
- namespace identifier and domain;
- target probability as a canonical decimal string, not a binary float;
- common hash-function count;
- total bit count and shard count;
- 256 shard descriptors in prefix order;
- for each shard: prefix, entry count, unique count, bit count, byte offset and
  byte length; and
- shard bitsets, with bit index zero as the least-significant bit of byte zero
  and unused high bits forced to zero.

Offsets must be monotonic, non-overlapping and inside the file. Consumers reject
unknown versions, unknown namespaces, nonzero reserved fields, length mismatch,
trailing data, impossible counts, overlapping ranges and nonzero padding.

The payload bytes are deterministic for the same format, checkpoint namespace
and value multiset, regardless of input order, duplicate order, worker count or
machine architecture. Build timing and host data never enter the payload.

## Manifest and signature

The artifact manifest contains at least:

| Field | Meaning |
| --- | --- |
| `format` | `relic-bloom-filter` |
| `format_version` | payload/manifest format version |
| `namespace` | exact value namespace |
| `checkpoint_id` | immutable RELIC MMR checkpoint identifier |
| `integrity_chain_head` | raw checkpoint-covered chain head rendered as lowercase hex |
| `mmr_leaf_count` | covered integrity-row count |
| `entry_count` | covered rows in this namespace, including duplicates |
| `unique_value_count` | distinct canonical values inserted |
| `bit_count` | total shard bit count |
| `hash_function_count` | common `k` |
| `target_false_positive_probability` | canonical decimal string |
| `hash_algorithm` | `sha256-double-v1` |
| `domain` | `relic-bloom-index-v1` |
| `payload_sha256` | SHA-256 of exact payload bytes |
| `built_at` | canonical UTC timestamp |
| `builder_version` | reviewed RELIC release/commit identity |
| `system_uid` | dedicated Bloom-publication system identity |
| `signature` | Ed25519 signature rendered as lowercase hex |

An example is stored in
[`examples/bloom-filter-manifest-v1.json`](examples/bloom-filter-manifest-v1.json).
Its repeated hexadecimal values are illustrative placeholders, not a valid
signature or an accepted golden vector.

The signature does not sign arbitrary JSON bytes. It signs the SHA-256 digest of
the existing RELIC length-prefixed encoding under domain
`relic-bloom-manifest-v1`, with these fields in this exact order:

```text
format
format_version                 (u32 big-endian)
namespace
checkpoint_id                  (u64 big-endian)
integrity_chain_head            (32 raw bytes)
mmr_leaf_count                 (u64 big-endian)
entry_count                    (u64 big-endian)
unique_value_count             (u64 big-endian)
bit_count                      (u64 big-endian)
hash_function_count            (u32 big-endian)
target_false_positive_probability
hash_algorithm
domain
payload_sha256                  (32 raw bytes)
built_at
builder_version
system_uid                      (16 UUID bytes)
```

`signature` is excluded from its own signed field list. The published manifest
is serialized with RFC 8785 JSON canonicalization after adding the signature.
Its SHA-256 is the manifest content address. Verification checks canonical
field grammar, payload digest and registered non-revoked system key before
loading any bitset.

The Bloom publisher uses a system identity distinct from integrity and MMR
signers. The private key remains outside PostgreSQL and Git under the same
least-privilege key-custody rules as other workers.

## Content-addressed storage and registration

Artifacts should use immutable keys such as:

```text
bloom/payloads/sha256/ab/<payload_sha256>.rbf
bloom/manifests/sha256/cd/<manifest_sha256>.json
```

A future database registry stores only verified metadata and immutable object
keys. A small namespace pointer may identify the newest published generation,
but it is mutable routing state, not evidence. Clients requesting an explicit
checkpoint never follow `latest` without resolving and returning the exact
checkpoint.

Publication order is payload, finalized manifest, registry row, then optional
latest pointer. Orphaned immutable objects are harmless and may be removed only
by a separate audited retention process.

## Worker lifecycle

The future `relic-bloom-worker` is asynchronous and never participates in
record admission:

1. acquire a namespace/format advisory lock;
2. start a repeatable-read, read-only transaction;
3. verify the selected signed MMR checkpoint and integrity-chain head;
4. require the checkpoint to cover the transaction's current integrity tip
   until durable record-to-integrity coverage exists;
5. stream exact canonical values and exact distinct counts in deterministic
   shard/value order;
6. build into a private temporary directory;
7. verify counts, realized probability, known-positive membership, payload
   structure and payload digest;
8. construct and sign the manifest outside PostgreSQL;
9. upload payload and manifest under temporary names, verify them after upload,
   then make their content-addressed names visible;
10. atomically insert the immutable registry row and advance a latest pointer
    only if it still names the expected predecessor; and
11. emit metrics and release the lock.

Exact retries are idempotent: they reproduce the payload digest and either find
the same registered generation or insert it once. Two builders may compute the
same artifact, but only one publisher advances the pointer. A conflicting
artifact for the same namespace/checkpoint/format is a hard integrity error,
not a last-writer-wins case.

PostgreSQL notifications may wake the worker but are not durable work. The
worker polls and reconciles signed checkpoints after restart.

### Crash recovery and rebuild

- A crash before registry publication leaves at most unreferenced immutable
  objects.
- A crash after registry insertion is recovered by reconciling the registry
  and pointer; it never edits the registered generation.
- Startup verifies the complete currently served artifact. Failure removes it
  from service and falls back to PostgreSQL; it does not rebuild in place.
- Rebuilds write a shadow generation from authoritative rows, compare digests
  and counts, and publish atomically only after qualification.
- Rollback changes only the routing pointer to a previously verified manifest.
- Recovery never patches bits or signatures to make an artifact pass.

## Consumer designs

### Server membership API

Proposed endpoints:

```text
GET /v1/bloom/{namespace}/checkpoints/{checkpoint_id}/manifest
GET /v1/bloom/{namespace}/checkpoints/{checkpoint_id}/payload
POST /v1/bloom/{namespace}/membership
```

The membership request supplies `checkpoint_id` and a bounded list of canonical
values. The response for each value is exactly one of:

```json
{
  "result": "definitely_absent",
  "confirmation_required": false
}
```

```json
{
  "result": "possibly_present",
  "confirmation_required": true
}
```

```json
{
  "result": "unknown",
  "reason": "verified_filter_unavailable",
  "confirmation_required": true
}
```

Every response also names the namespace, exact checkpoint, manifest digest,
target probability and filter format version. A malformed value is `400`; a
valid value for an unavailable/mismatched checkpoint is `unknown`, never
`definitely_absent`. API authorization controls access to the service but does
not change membership semantics.

### Download and memory map

Large analytical clients may download a manifest and payload using immutable
URLs, ETags equal to content digests and resumable range requests. Before
memory-mapping, the client verifies:

1. manifest format and namespace;
2. checkpoint ID, chain head and MMR leaf count against the requested signed
   checkpoint;
3. system identity and signature;
4. exact payload length and SHA-256; and
5. payload header, offsets and reserved fields.

Readers load a new generation beside the old one and swap an in-process pointer
only after full verification. Existing requests retain the old mapping until
completion. Verification failure keeps the old mapping or uses database-only
mode.

## Security and failure analysis

| Failure or threat | Required behaviour |
| --- | --- |
| Stale filter used as current | Require exact checkpoint equality; otherwise return `unknown` or query PostgreSQL |
| Bloom positive treated as fact | API labels it `possibly_present`; authoritative confirmation is mandatory |
| Bloom negative used for admission/uniqueness | Forbidden; database constraints and transaction checks always run |
| Payload corruption/truncation | Digest, length, header and offset validation reject before mapping |
| Manifest substitution or rollback | Verify signature, checkpoint tuple and explicit caller checkpoint; expose manifest digest |
| Cross-namespace confusion | Strict namespace grammar plus domain-separated hashing and separate artifacts |
| False negative caused by build bug | Full known-positive validation, deterministic independent rebuild and canary shadow comparison; quarantine on any discrepancy |
| Saturation or wrong cardinality | Exact unique counts; reject realized probability above target; capacity alerts |
| Concurrent publishers | Namespace/format lock plus compare-and-swap latest pointer and immutable uniqueness |
| Crash during publication | Temporary names, fsync/verified upload and registry-last publication |
| Revocation interpreted as deletion | Version-1 semantics explicitly mean ever admitted by checkpoint |
| Hostile query volume | Authentication, bounded batch size, rate limits and no attacker-controlled allocation |
| Parser/resource attack | Fixed maximum header/shard count, checked arithmetic, bounded files and reject trailing data |
| Private-key exposure | Dedicated unprivileged signer; key outside PostgreSQL/repository; no key bytes in metrics or artifact |
| Chosen-value bit targeting | SHA-256 domain hashing; artifact remains non-authoritative even if attacked |
| Filter service outage | Database-only fallback; no effect on integrity/admission |

A Bloom filter cannot provide cryptographic proof of absence. “Definitely
absent” is an algorithmic guarantee relative to a verified artifact's declared
set and checkpoint, contingent on the qualified builder having inserted every
covered value.

## Observability

Per namespace and generation, publish:

- checkpoint ID, MMR leaf count and lag from latest verified checkpoint;
- entry and unique counts, duplicate ratio and per-shard skew;
- bit count, set-bit ratio, calculated realized probability and capacity headroom;
- build duration, source scan duration, verification duration, peak RAM and
  temporary disk;
- payload/manifest size and download/verification time;
- membership request rate, batch size, latency and result counts;
- possibly-present confirmations, actual hits and measured false positives;
- database queries avoided, database fallback count and reason;
- worker retries, lock contention, orphan cleanup candidates and pointer age;
  and
- artifact rejection/quarantine events by exact reason.

Alerts should cover signature/digest failure, any known-positive miss, checkpoint
regression, generation conflict, target-probability breach, excessive lag,
pointer to an unverified object and a sudden change in shard/cardinality
distribution.

## Validation and implementation gates

The executable validation plan is in
[`bloom-filter-validation.md`](bloom-filter-validation.md). The staged delivery
and acceptance gates are in
[`bloom-filter-implementation-plan.md`](bloom-filter-implementation-plan.md).

Nothing in this document authorizes a worker, database migration, service,
production key or server deployment.
