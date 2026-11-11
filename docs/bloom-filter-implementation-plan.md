# Bloom-filter implementation plan

> **Status:** future checklist. No phase is authorized merely because the prior
> phase is documented or tested.

## Phase 0 — semantics and reference validation

- [ ] Approve namespaces, historical revocation meaning and exact response terms.
- [ ] Freeze canonical bytes, hash construction, bit ordering and format limits.
- [ ] Freeze manifest signed fields and golden vectors.
- [ ] Validate formulas, no-false-negative property, deterministic rebuilds and
      statistical harness using synthetic data.
- [ ] Record alternatives and unresolved questions.

**Gate:** reviewed design plus cross-platform golden-vector agreement. No server
or database dependency.

## Phase 1 — artifact builder and verifier

- [ ] Implement bounded deterministic partitioned-snapshot builder.
- [ ] Implement independent parser/verifier before memory mapping.
- [ ] Implement dedicated test signer/verifier and canonical manifest output.
- [ ] Add corruption, truncation, malformed-count and resource-limit tests.
- [ ] Benchmark 3M/30M synthetic builds and document 300M feasibility.

**Gate:** independent build equality, all inserted values present, calculated
probability within target, artifact verifier rejects every malformed class, and
resource evidence is reviewed.

## Phase 2 — checkpoint worker

- [ ] Specify a durable authoritative coverage query.
- [ ] Use repeatable-read read-only snapshot and verify checkpoint equals its
      covered integrity tip.
- [ ] Add namespace/format single-publisher lock and idempotent retries.
- [ ] Load only a dedicated external Bloom signing identity.
- [ ] Produce dry-run artifacts and reports without publication.

**Gate:** crash/restart tests and an end-to-end dry-run against a disposable
database prove exact counts, checkpoint binding and no authoritative writes.

## Phase 3 — atomic publication and registration

- [ ] Add reviewed immutable artifact registry/pointer migration.
- [ ] Stage, digest, upload, re-read/verify and atomically register artifacts.
- [ ] Implement compare-and-swap latest pointer and orphan reporting.
- [ ] Implement dry-run rebuild, reconciliation and rollback commands.

**Gate:** fault-injection demonstrates no partial generation is discoverable,
conflicts fail closed, and rollback requires no bitset mutation.

## Phase 4 — read-only API and mmap consumer

- [ ] Add exact-checkpoint manifest/payload download with immutable caching.
- [ ] Add bounded batch membership endpoint with three-state results.
- [ ] Implement client-side signature/digest/structure verification before mmap.
- [ ] Add hot-swap with request-safe old mapping and database-only fallback.
- [ ] Add authentication, rate limiting and metrics without logging queried
      values or credentials unnecessarily.

**Gate:** contract/integration tests prove mismatched or unavailable checkpoints
return unknown, positives require confirmation, and corruption falls back to
PostgreSQL.

## Phase 5 — real-corpus shadow canary

- [ ] Measure real cardinality, collisions, shard skew, resources and lag.
- [ ] Compare every Bloom response with authoritative PostgreSQL.
- [ ] Measure empirical false positives and database-only baseline.
- [ ] Exercise service restart, artifact quarantine, key rotation and rollback.

**Gate:** zero false negatives across the reviewed trace, observed behavior
within approved statistical/resource limits, and an operational review. Bloom
results still do not skip database work in shadow mode.

## Phase 6 — performance qualification and production admission

- [ ] Decide whether measured value justifies negative short-circuiting.
- [ ] Set production probability, checkpoint cadence, lag and resource budgets.
- [ ] Approve monitoring, retention, key custody and incident runbook.
- [ ] Run a representative canary with rollback ready.
- [ ] Record explicit production admission.

**Gate:** reviewed evidence shows materially fewer database probes with no
integrity/admission change and acceptable operational cost. If not, retain the
artifacts only for offline analytics or do not deploy them.

## Deferred version-2 questions

- Whether real build cost justifies immutable base-plus-delta layers.
- Aggregate false-positive budget and compaction rules for layers.
- Durable mapping from individual authoritative values to integrity ordinals.
- Whether active/non-revoked filters have sufficient demand to justify a second
  semantics and rebuild path.
- Whether clients need shard-specific range downloads instead of one mmap file.
- Whether checkpoint cadence should be count-, time- or demand-driven.
