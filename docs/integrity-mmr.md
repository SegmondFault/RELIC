# Integrity service and Merkle Mountain Range

> **Status:** the pure Rust hashing, frontier and checkpoint-signing core, the
> PostgreSQL checkpoint worker, inclusion proofs (Rust and API) and the offline
> proof verifier are implemented. Consistency proofs, key-custody integration,
> service supervision and publication states remain future work.

This page records the intended boundary for RELIC's future append-only
integrity layer. It is deliberately descriptive rather than executable so the
team can agree the behaviour before choosing the schema and implementing it.

The proposed structure is a **Merkle Mountain Range (MMR)**. Unlike a balanced
Merkle tree rebuilt for every odd leaf count, an MMR keeps each complete tree
as a peak and merges equal-sized peaks when the next leaf arrives. Existing
leaf indexes and completed subtrees remain stable as the dataset grows.

## MMR visual explainer

Each existing `catalogue.integrity` row is an MMR leaf. Its zero-based leaf
index is its ordinal position when the non-forking hash chain is followed from
the genesis row. The index is not a database ID, timestamp or source-record
identifier and does not need to be copied into a parallel table.

Purple nodes in the diagrams are the current peaks. The checkpoint commitment
is derived by combining those peaks in an exact, versioned left-to-right order.
The pictures explain topology. The version-1 construction uses each integrity
row's `chain_hash` as leaf input and commits to the zero-based leaf index,
left/right order, peak positions and tree heights.

### 1. Start with leaf 0

![One-leaf MMR: leaf 0 is the only peak](images/mmr-growth/mmr-growth-01.svg)

### 2. Append leaf 1

The two one-leaf peaks merge into the complete `[0–1]` subtree.

![Two-leaf MMR: leaves 0 and 1 merge](images/mmr-growth/mmr-growth-02.svg)

### 3. Append leaf 2

There is no equal-sized peak to merge with leaf 2, so `[0–1]` and `[2]`
remain as separate mountains.

![Three-leaf MMR: peaks 0 to 1 and 2](images/mmr-growth/mmr-growth-03.svg)

### 4. Append leaf 3

Leaves 2 and 3 merge, then the two two-leaf peaks merge into `[0–3]`.

![Four-leaf MMR: a complete four-leaf tree](images/mmr-growth/mmr-growth-04.svg)

### 5. Append leaf 4

The complete `[0–3]` tree is unchanged and leaf 4 becomes a second peak.

![Five-leaf MMR: peaks 0 to 3 and 4](images/mmr-growth/mmr-growth-05.svg)

### 6. Append leaf 5

Leaves 4 and 5 merge. The peaks are now `[0–3]` and `[4–5]`.

![Six-leaf MMR: peaks 0 to 3 and 4 to 5](images/mmr-growth/mmr-growth-06.svg)

### 7. Append leaf 6

Leaf 6 cannot yet merge. Three peaks cover all seven leaves without padding or
duplicating a leaf.

![Seven-leaf MMR: three current peaks](images/mmr-growth/mmr-growth-07.svg)

### 8. Append leaf 7

Leaf 7 triggers a carry: `[6–7]`, then `[4–7]`, then the complete `[0–7]`
tree. This is analogous to carrying bits in a binary counter.

![Eight-leaf MMR: a complete eight-leaf tree](images/mmr-growth/mmr-growth-08.svg)

The same pattern continues indefinitely. A leaf is appended once; only the
right-hand frontier changes.

## Component boundary

The design separates the tree algorithm from storage and operations:

- **`relic-mmr-worker`** contains the Rust append, peak, commitment and
  checkpoint-signing implementation plus the fail-closed PostgreSQL
  reconciler exposed as `relic-checkpoint-mmr`, and the inclusion-proof
  construction and verification (`proof` module) with the offline
  `relic-verify-proof` command (`client` module).
- **`relic-checkpoint-mmr`** is the current explicit one-shot operational
  entry point. It independently rebuilds the integrity chain, verifies the
  latest checkpoint, signs any advanced frontier and inserts once.
- **`relic-integrityd`** will be the normal long-running worker. It will catch
  up new leaves, persist nodes and checkpoints, and request signatures.
- **`relicctl`** will provide explicit status, verification, dry-run rebuild,
  recovery and manual-checkpoint operations. It is an administrative tool, not
  the normal record-processing path.

PostgreSQL should not start a command-line process from a trigger. The database
owns durable records and ordering; the worker owns the incremental computation.
PostgreSQL notification may wake the worker quickly, but notifications are only
hints. The worker must poll and reconcile from durable state because a
notification can be lost.

## Leaf-index constraints

- `catalogue.integrity` remains the authoritative system-signed linear hash
  chain; the MMR is a derived overlay and does not replace or modify it.
- Leaf indexes begin at `0` and increase contiguously.
- An assigned index is immutable and is never reused.
- The existing `prev_hash` relationship supplies the order. The database's
  single-genesis and single-successor constraints prevent forks.
- A checkpoint points to its newest covered row through
  `mmr_checkpoint.last_integrity_id`. Every earlier covered leaf is reached by
  following `prev_hash` back to the genesis row.

## Version-1 hashing constraints

The implemented calculation fixes these rules:

- a leaf consumes the committed integrity row's `chain_hash`, not a fresh copy
  of the source record;
- SHA-256 is the digest algorithm;
- leaf, internal-node, peak commitment, checkpoint and signature inputs use
  distinct versioned domain tags;
- variable fields are length-prefixed, integers are fixed-width big-endian,
  and children and peaks are encoded left to right;
- a leaf commits to its zero-based index;
- a node commits to its start index and resulting height as well as both child
  hashes;
- the commitment commits to `leaf_count` and every ordered peak's start index,
  height and hash; and
- the Ed25519 system signature covers the format, newest integrity ID, leaf
  count, peaks, commitment, system identity and explicit timestamp.

Changing any of these is a format migration, not a silent implementation
detail. No leaf duplication or invented padding leaf is used to handle an odd
count. The inclusion-proof encoding is specified below.

## Database responsibilities

The existing `integrity` table remains unchanged. One additional table,
`mmr_checkpoint`, stores each immutable signed checkpoint:

- `last_integrity_id` is a foreign key to the newest covered integrity row;
- `leaf_count` states how many chain rows are covered from genesis through that
  row and is verified by walking the chain;
- `peaks` is the ordered, inspectable JSON representation of the current MMR
  frontier;
- `commitment` is the digest derived from those peaks under `format_version`;
- `system_uid` and `system_signature` identify and authenticate the system
  account that created the checkpoint; and
- `created_at` records when it was committed.

For a given format version, both `last_integrity_id` and `leaf_count` are
unique. A checkpoint therefore identifies one unambiguous extent of the
integrity chain.

Hashes, signatures, source identities and timestamps from the integrity chain
are not copied. The MMR is a binary-tree structure, but completed internal
nodes are initially recomputed or carried in worker memory rather than stored
as a second permanent tree. A node cache may be introduced later if proof or
rebuild performance requires it; it would remain disposable derived state.

The database must enforce checkpoint immutability, foreign-key integrity, an
active system signing identity and agreement between `leaf_count` and the
referenced hash-chain extent.

## Worker behaviour

Only one active sequencer may advance an MMR. The current worker uses a
format-scoped PostgreSQL advisory lock and independently reconstructs the
complete ordered frontier from genesis before it advances the latest
checkpoint.

It loads the latest checkpoint's peaks, registered system identity and
signature and compares them with that reconstruction. It stops rather than
advance if they diverge. An exact retry is idempotent: a fully verified current
checkpoint is returned without inserting another row. A crash between attempts
is safe because signing and insertion occur in one serializable transaction.

The service should run under an unprivileged `relic` operating-system account.
Its database permissions should be limited to the integrity records it needs.

## Checkpoints and signing

A checkpoint commits to a specific leaf count and ordered set of peaks. The
private signing key remains outside PostgreSQL; PostgreSQL stores the
commitment, signature and public signing-key identity required for verification.

Checkpoint insertion is atomic, but checkpoint creation is intentionally not
part of source-record admission. A record is authoritative only after its
object digest, integrity-chain hash and integrity system signature have been
committed in one database transaction. MMR status is a separate derived state;
a delayed checkpoint does not weaken the integrity admission rule.

## Inclusion proofs

An inclusion proof shows that one integrity row (a leaf) is covered by a
signed checkpoint, without downloading or replaying the chain.

**What a proof is.** Every peak is a perfect binary tree whose first leaf is a
multiple of its size, so the path from a leaf to its peak follows from the leaf
index alone. A proof is only the sibling hashes from the leaf level upwards,
plus the leaf index and the leaf count of the checkpoint it targets. The
sibling at level `k` is on the right when bit `k` of the leaf index is `0`, and
on the left otherwise. The number of siblings is the height of the peak that
holds the leaf, and that peak is fixed by the leaf count (the set bits of
`leaf_count`, largest first). A proof is logarithmic: 10 hashes for 1 024
leaves. It is only meaningful for the `leaf_count` it names; a later checkpoint
needs its own proof, and an earlier checkpoint stays provable.

**Encoding (version 1).** Canonical JSON with exactly these fields, lowercase
hexadecimal digests and no others (unknown fields and versions are rejected):

```json
{"format_version": 1, "leaf_index": 4, "leaf_count": 6, "siblings": ["<64 hex>"]}
```

The Rust crate is the source of truth; `crates/relic-mmr-worker/tests/vectors/inclusion-v1.json`
pins the construction, and the Python API is tested against the same file.

**Verification** (`relic_mmr_worker::proof` and `relic-verify-proof`):

1. verify the checkpoint's commitment and Ed25519 system signature with a key
   obtained independently of the proof;
2. check that the proof and the checkpoint agree on the checkpoint id, leaf
   count and commitment, and that the peaks have the shape the leaf count
   dictates;
3. fold the leaf (`chain_hash`) and the siblings into a peak and require it to
   be one of the checkpoint's signed peaks.

A client that recomputed an entry's chain hash itself should pass it as
`--chain-hash`; otherwise the proof only shows that the server's claim is
consistent with its own signed checkpoint.

```bash
curl -H "Authorization: Bearer $TOKEN" "$API/v1/integrity/$ID/proof?checkpoint_id=$N" > proof.json
curl -H "Authorization: Bearer $TOKEN" "$API/v1/mmr-checkpoints/$N"                   > checkpoint.json
relic-verify-proof --proof proof.json --checkpoint checkpoint.json \
    --public-key "$SYSTEM_PUBLIC_KEY" --chain-hash "$CHAIN_HASH"
```

**API** (`GET /v1/integrity/{id}/proof`, any role). The server builds the proof
from the integrity chain and checks it against the stored checkpoint before
answering; if they disagree it answers `500` and logs the cause rather than
serve a proof the checkpoint would reject.

**Cost.** Internal nodes are not stored, so a proof rebuilds the peak that holds
the entry: work proportional to that peak's size, run off the event loop.
`RELIC_PROOF_MAX_PEAK_LEAVES` (default 262 144) caps it and larger peaks are
refused with `503`; `RELIC_PROOF_RATE_LIMIT_PER_MINUTE` limits each account.
The oldest entries always sit in the largest peak, so this cap is what a node
cache would lift once the chain outgrows it.

## Verification and recovery

RELIC must be able to rebuild the expected MMR independently from the immutable
leaves and compare it with stored nodes, peaks and signed checkpoints. A
rebuild defaults to dry-run and reports the first divergence. Recovery must not
overwrite conflicting evidence merely to make verification pass.

Proof generation and verification state which checkpoint and leaf count they
target (see [Inclusion proofs](#inclusion-proofs)). A later checkpoint may cover more leaves, but it must not change
the meaning of an earlier signed checkpoint.

## Decisions still open

- Checkpoint cadence: every append, time-based, count-based or explicit batch.
- Whether publication waits for sealing or exposes a visible pending state.
- Which internal nodes are retained and whether safe pruning is ever allowed.
- Consistency proofs between two checkpoints.
- A node cache, so a proof no longer costs the size of its peak (see below).
- Production key custody and rotation procedure.
- Monitoring thresholds and the operational recovery procedure.

No runtime adapter should quietly settle one of these choices. The selected
behaviour belongs in a reviewed operational specification and regression
vectors.
