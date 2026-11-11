# Bloom-filter validation plan

> **Status:** test plan. Tests using generated values validate algorithms and
> artifact handling only. They do not qualify real RELIC corpus behaviour or a
> production service.

## Synthetic validation available now

Use fixed, published seeds and deterministic value generators. Test each
namespace grammar independently rather than treating arbitrary byte strings as
equivalent to corpus data.

### Correctness and properties

- Insert deterministic sets at empty, one, boundary-byte, shard-boundary and
  configured-maximum sizes.
- Assert no false negatives for every inserted unique value.
- Insert duplicates in different orders and assert identical payload bytes.
- Shuffle unique input order and worker partitioning and assert identical
  payload bytes and digest.
- Assert the same canonical bytes map differently under every namespace.
- Assert uppercase, wrong-width, whitespace-padded and non-hex values are
  rejected rather than normalized.
- Verify empty shards return definitely absent and cannot be mistaken for a
  missing shard.
- Exercise checked arithmetic near supported count/offset limits without
  allocating attacker-selected memory.

### Statistical false-positive test

For each target probability, build with a deterministic inserted set and query
a disjoint deterministic set. The test records observed false positives and
uses a predeclared binomial confidence bound. It fails only when the upper
confidence bound exceeds an agreed tolerance over the target; it must not
expect exactly `p * queries`.

`1e-9` cannot be meaningfully measured in a routine unit test: observing even
ten expected false positives requires about ten billion independent negatives.
Routine tests instead validate its formula/parameters and use smaller filters
or elevated probabilities to exercise the statistical harness. Long-running
qualification may test lower probabilities with sufficient samples.

### Golden serialization and signature boundaries

Commit small golden vectors containing:

- namespace and canonical inputs;
- bit count and hash-function count;
- expected bit indexes;
- exact payload bytes and SHA-256;
- canonical manifest signed fields and digest;
- deterministic test public key and signature; and
- finalized canonical manifest bytes and manifest SHA-256.

Golden private-key material may exist only as an unmistakable test vector with
no operational use. Tests prove that changing field order, namespace, checkpoint,
probability, payload digest, builder version, timestamp or system identity
breaks verification. The signature field itself is excluded from its signed
input but covered by the final canonical-manifest digest.

### Rejection and recovery tests

- Flip every class of header, descriptor and bitset field and require rejection
  where the payload digest or structural rules are violated.
- Test truncated headers, truncated bitsets, extra trailing bytes, overlapping
  offsets, nonzero padding, unknown versions and wrong magic.
- Test valid payload with wrong manifest digest, signature, namespace,
  checkpoint, chain head or MMR leaf count.
- Simulate crashes before payload rename, between payload and manifest, before
  registry insert and after registry insert but before pointer advance.
- Run competing publishers and prove one immutable generation/pointer result.
- Retry every interrupted phase and prove idempotence.
- Corrupt the currently served artifact and prove fail-closed database fallback,
  not an absence response.

### Synthetic benchmarks

Benchmarks should report rather than promise production limits:

- build and full verification throughput at 3M, 30M and, where host resources
  permit, 300M generated values;
- single and batched membership throughput/latency;
- cold/warm memory-map lookup performance;
- one, several and 256 builder workers;
- peak RSS, temporary disk, payload bytes and per-shard skew;
- duplicate-heavy inputs and uniformly unique inputs; and
- database-free API overhead relative to direct in-process lookup.

Benchmark artifacts remain generated/ignored files. Results record host,
compiler, build profile, commit, parameters and deterministic seed.

## Real-corpus validation required later

Synthetic success does not establish production readiness. After a real corpus
and exact API/checkpoint contract exist, qualification must measure:

- exact row and distinct cardinalities for every namespace;
- real duplicate/collision rates, including full/specific FID-hash reuse;
- shard skew and whether first-byte partitioning remains balanced;
- full source-scan, build, verification and publication time;
- peak RAM, temporary disk, payload/manifest sizes and network transfer time;
- warm/cold mmap footprint and server/client lookup latency;
- worker lag against actual MMR checkpoint cadence;
- observed false-positive rate from database-confirmed negative probes;
- possibly-present confirmation rate and actual database queries avoided;
- database-only baseline throughput and latency under the same trace;
- rebuild equality on an independently provisioned worker;
- corruption, restart, key-rotation, canary and pointer-rollback procedures;
- behavior around approved revocations and the historical-membership contract;
  and
- authorization, rate-limit and bounded-batch behavior of the real API.

### Real-corpus acceptance criteria

Before serving a negative answer:

1. two independent builds for the same namespace/checkpoint produce identical
   payload digests and counts;
2. every authoritative distinct value in a full validation pass is present;
3. the manifest verifies against a dedicated registered system key and exact
   signed MMR checkpoint;
4. measured/calculated false-positive probability stays within the approved
   bound;
5. the API passes checkpoint mismatch, stale artifact and database-fallback
   integration tests;
6. the canary shows a material database-query reduction without violating the
   latency/resource budget;
7. rollback to database-only and to the previous verified generation is tested;
8. operating procedures, alerts and key custody are reviewed; and
9. production admission is an explicit decision, not a consequence of a green
   unit test.

The canary initially runs in shadow mode: every result is compared with
PostgreSQL and no query is avoided. Only after the full trace shows zero false
negatives and expected false positives may a later review authorize negative
short-circuiting for exact checkpoint reads.
